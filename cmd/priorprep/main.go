// Command priorprep turns labelled public flow datasets into head C training
// rows, using trafficam's own feature code so training and the live watcher
// compute features identically ("train/serve parity").
//
// Development tool only: the product never runs it, and it reads no traffic
// from the machine it runs on.
//
//	go run ./cmd/priorprep -group neris -out neris.csv CTU-13-Dataset/1/capture20110810.binetflow ...
//
// Each input flow file is CTU-13 / Stratosphere "binetflow" (Argus CSV with a
// Label column). Flows labelled From-Botnet are positives, From-Normal are
// negatives, and Background flows are skipped (they are unlabelled). Flows are
// rolled up into trafficam's per-minute rows with the source host standing in
// for the program, then passed through modelscore.Tracker and
// model.PriorFeatures, exactly as live rows are.
//
// Features a flow capture cannot provide (DNS name shape, whether a lookup
// came first, code signing) are written as NaN; the Python trainer replaces
// them with the training mean, so head C neither learns from nor relies on
// them. Output CSV columns: group,label,<the 14 feature names>.
package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
	"github.com/Venkatesan7G/trafficam/internal/model"
	"github.com/Venkatesan7G/trafficam/internal/modelscore"
)

// Must match python/prior/features.py NAMES.
var names = []string{"bytes_out", "bytes_in", "out_in_ratio", "duration", "send_events",
	"interval_cv", "contacts_1h", "fan_out", "fail_rate", "dns_before",
	"dns_entropy", "dns_len", "dest_new", "signed"}

// Columns a flow capture cannot fill.
var missing = map[int]bool{9: true, 10: true, 11: true, 13: true}

type key struct {
	start    int64
	src, dst string
	proto    event.Proto
	port     uint16
}

type agg struct {
	m     event.Minute
	label int
}

func main() {
	group := flag.String("group", "", "group name written in every row (e.g. the botnet family)")
	out := flag.String("out", "", "output CSV (appends if it exists)")
	maxNormal := flag.Int("max-normal", 0, "keep at most this many normal rows per file (0 = all)")
	flag.Parse()
	if *group == "" || *out == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: priorprep -group NAME -out FILE.csv FILE.binetflow...")
		os.Exit(2)
	}
	_, statErr := os.Stat(*out)
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	check(err)
	w := csv.NewWriter(bufio.NewWriter(f))
	if os.IsNotExist(statErr) {
		check(w.Write(append([]string{"group", "label"}, names...)))
	}
	for _, path := range flag.Args() {
		pos, neg, err := convert(path, *group, *maxNormal, w)
		check(err)
		fmt.Fprintf(os.Stderr, "%s: %d botnet rows, %d normal rows\n", path, pos, neg)
	}
	w.Flush()
	check(w.Error())
	check(f.Close())
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func convert(path, group string, maxNormal int, w *csv.Writer) (pos, neg int, err error) {
	fh, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer fh.Close()
	r := csv.NewReader(bufio.NewReaderSize(fh, 1<<20))
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	head, err := r.Read()
	if err != nil {
		return 0, 0, err
	}
	col := map[string]int{}
	for i, h := range head {
		col[strings.TrimSpace(h)] = i
	}
	for _, c := range []string{"StartTime", "Dur", "Proto", "SrcAddr", "DstAddr", "Dport", "State", "TotPkts", "TotBytes", "SrcBytes", "Label"} {
		if _, ok := col[c]; !ok {
			return 0, 0, fmt.Errorf("%s: no %s column", path, c)
		}
	}
	rows := map[key]*agg{}
	for line := 2; ; line++ {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, 0, fmt.Errorf("%s:%d: %v", path, line, err)
		}
		lab := strings.TrimPrefix(rec[col["Label"]], "flow=")
		y := -1
		switch {
		case strings.HasPrefix(lab, "From-Botnet"):
			y = 1
		case strings.HasPrefix(lab, "From-Normal"):
			y = 0
		}
		if y < 0 {
			continue
		}
		t, err := time.Parse("2006/01/02 15:04:05.000000", strings.TrimSpace(rec[col["StartTime"]]))
		if err != nil {
			continue
		}
		proto := event.Other
		switch strings.TrimSpace(rec[col["Proto"]]) {
		case "tcp":
			proto = event.TCP
		case "udp":
			proto = event.UDP
		}
		if proto == event.Other { // icmp, arp, ...: trafficam does not record these
			continue
		}
		port64, _ := strconv.ParseUint(strings.TrimSpace(rec[col["Dport"]]), 0, 16)
		dur, _ := strconv.ParseFloat(rec[col["Dur"]], 64)
		pk, _ := strconv.ParseUint(rec[col["TotPkts"]], 10, 64)
		tot, _ := strconv.ParseUint(rec[col["TotBytes"]], 10, 64)
		src, _ := strconv.ParseUint(rec[col["SrcBytes"]], 10, 64)
		k := key{t.Truncate(time.Minute).Unix(), rec[col["SrcAddr"]], rec[col["DstAddr"]], proto, uint16(port64)}
		a := rows[k]
		if a == nil {
			a = &agg{m: event.Minute{V: event.SchemaVersion, Start: t.UTC().Truncate(time.Minute),
				Program: event.Program{Name: "host-" + k.src}, Proto: proto, Dir: event.Outbound,
				Host: k.dst, RemoteIP: k.dst, Port: k.port}, label: y}
			rows[k] = a
		}
		a.label = max(a.label, y)
		a.m.Flows++
		a.m.Packets += pk
		a.m.BytesOut += src
		if tot > src {
			a.m.BytesIn += tot - src
		}
		a.m.DurationMs += uint64(dur * 1000)
		if proto == event.TCP && !established(rec[col["State"]]) {
			a.m.FailedCount++
		}
	}
	list := make([]*agg, 0, len(rows))
	for _, a := range rows {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i].m, list[j].m
		if !a.Start.Equal(b.Start) {
			return a.Start.Before(b.Start)
		}
		if a.Program.Name != b.Program.Name {
			return a.Program.Name < b.Program.Name
		}
		return a.Host < b.Host
	})
	tr := modelscore.NewTracker()
	keepNormal := 1.0
	if maxNormal > 0 {
		var n int
		for _, a := range list {
			if a.label == 0 {
				n++
			}
		}
		if n > maxNormal {
			keepNormal = float64(maxNormal) / float64(n)
		}
	}
	var acc float64
	for i := 0; i < len(list); {
		j := i + 1
		for j < len(list) && list[j].m.Start.Equal(list[i].m.Start) {
			j++
		}
		batch := make([]event.Minute, j-i)
		for k := range batch {
			batch[k] = list[i+k].m
		}
		flows := tr.Observe(batch) // every row, so history is complete
		for k := range flows {
			y := list[i+k].label
			if y == 0 {
				acc += keepNormal
				if acc < 1 {
					continue
				}
				acc--
				neg++
			} else {
				pos++
			}
			x := model.PriorFeatures(&flows[k])
			rec := []string{group, strconv.Itoa(y)}
			for c, v := range x {
				if missing[c] {
					rec = append(rec, "nan")
				} else {
					rec = append(rec, strconv.FormatFloat(v, 'g', 7, 64))
				}
			}
			if err := w.Write(rec); err != nil {
				return 0, 0, err
			}
		}
		i = j
	}
	return pos, neg, nil
}

// established reports whether an Argus TCP state shows the server answered
// the handshake: the destination side ("src_dst") carries a SYN-ACK.
func established(state string) bool {
	i := strings.IndexByte(state, '_')
	if i < 0 {
		return strings.Contains(state, "EST") || strings.Contains(state, "CON")
	}
	return strings.Contains(state[i+1:], "S")
}
