package model

import (
	"hash/fnv"
	"math"
	"strconv"
	"strings"
)

// Architecture constants. Changing any of them changes the weight-file layout;
// bump the format version if you do.
const (
	NumCat      = 5
	NumNum      = 20
	InputDim    = 64
	EmbDim      = 40 // 16+8+8+4+4
	ProtoDim    = 4
	Hidden1     = 64
	Bottleneck  = 16
	NumClasses  = 512
	HeadBHidden = 32
)

var (
	catBuckets = [NumCat]int{4096, 1024, 512, 256, 16}
	catDims    = [NumCat]int{16, 8, 8, 4, 4}
	catOffsets = [NumCat]int{0, 16, 24, 32, 36}
)

// Input is an encoded Flow, ready for the network.
type Input struct {
	Cat   [NumCat]int32
	Proto int32
	Num   [NumNum]float32 // standardised; Head B's reconstruction target
}

// Names of the 26 features, in the order of the design doc table. Used by
// explanations.
var FeatureNames = [6 + NumNum]string{
	"destination", "asn", "parent_program", "country", "port_class", "protocol_direction",
	"bytes_out", "bytes_in", "out_in_ratio", "duration", "send_events",
	"hour_sin", "hour_cos", "weekday_sin", "weekday_cos",
	"interval_regularity", "contacts_1h", "fan_out", "failure_rate",
	"dns_before_connect", "dns_entropy", "dns_length",
	"seen_before_by_program", "days_since_first_seen", "other_programs_using", "signed",
}

// passthrough numeric slots are not standardised (cyclic, binary, 0..1).
var passthrough = [NumNum]bool{5: true, 6: true, 7: true, 8: true, 12: true, 13: true, 16: true, 19: true}

// Norm holds the fixed per-feature standardisation. It is fitted once, on the
// first training run, and then frozen so warm-started weights keep seeing the
// same input distribution.
type Norm struct {
	Mean [NumNum]float32 `json:"mean"`
	Std  [NumNum]float32 `json:"std"`
}

// IdentityNorm leaves features unstandardised.
func IdentityNorm() Norm {
	var n Norm
	for i := range n.Std {
		n.Std[i] = 1
	}
	return n
}

func hashBucket(salt, s string, buckets int) int32 {
	h := fnv.New64a()
	h.Write([]byte(salt))
	h.Write([]byte{0})
	h.Write([]byte(s))
	return int32(h.Sum64() % uint64(buckets))
}

// PortClass maps a port to one of 16 coarse classes.
func PortClass(p uint16) int32 {
	switch p {
	case 0:
		return 15
	case 80, 443, 8080, 8443:
		return 1
	case 53, 853:
		return 2
	case 25, 465, 587, 110, 995, 143, 993:
		return 3
	case 22:
		return 4
	case 20, 21:
		return 5
	case 3389, 445, 139:
		return 6
	case 123:
		return 7
	case 67, 68:
		return 8
	case 5353, 1900:
		return 9
	case 500, 4500, 1194, 51820:
		return 10
	case 3306, 5432, 1433, 27017, 6379:
		return 11
	}
	switch {
	case p < 1024:
		return 12
	case p < 49152:
		return 13
	default:
		return 14
	}
}

func log1p(x float64) float64 {
	if x < 0 || math.IsNaN(x) {
		return 0
	}
	return math.Log1p(x)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// rawNumeric returns the 20 numeric features before standardisation.
func rawNumeric(f *Flow) [NumNum]float64 {
	var r [NumNum]float64
	r[0] = log1p(f.BytesOut)
	r[1] = log1p(f.BytesIn)
	r[2] = log1p(f.BytesOut / (f.BytesIn + 1))
	r[3] = log1p(f.DurationSec)
	r[4] = log1p(f.SendEvents)
	h := float64(f.Time.Hour()) + float64(f.Time.Minute())/60
	r[5], r[6] = math.Sin(2*math.Pi*h/24), math.Cos(2*math.Pi*h/24)
	wd := float64(f.Time.Weekday())
	r[7], r[8] = math.Sin(2*math.Pi*wd/7), math.Cos(2*math.Pi*wd/7)
	r[9] = math.Min(math.Max(f.IntervalCV, 0), 10)
	r[10] = log1p(f.Contacts1h)
	r[11] = log1p(f.FanOut60s)
	r[12] = math.Min(math.Max(f.FailRate5m, 0), 1)
	r[13] = b2f(f.DNSBeforeConnect)
	r[14] = math.Max(f.DNSEntropy, 0)
	r[15] = math.Max(f.DNSLen, 0)
	r[16] = b2f(f.SeenBefore)
	r[17] = log1p(f.DaysSinceFirstSeen)
	r[18] = log1p(f.OtherPrograms)
	r[19] = b2f(f.Signed)
	return r
}

// FitNorm computes the standardisation from a set of flows.
func FitNorm(flows []Flow) Norm {
	n := IdentityNorm()
	if len(flows) == 0 {
		return n
	}
	var sum, sq [NumNum]float64
	for i := range flows {
		r := rawNumeric(&flows[i])
		for j, v := range r {
			sum[j] += v
			sq[j] += v * v
		}
	}
	cnt := float64(len(flows))
	for j := range sum {
		if passthrough[j] {
			continue
		}
		m := sum[j] / cnt
		v := sq[j]/cnt - m*m
		n.Mean[j] = float32(m)
		n.Std[j] = float32(math.Max(math.Sqrt(math.Max(v, 0)), 1e-3))
	}
	return n
}

// Encode converts a Flow to network input using n for standardisation.
// Standardised values are clamped to +-5 so one extreme flow cannot dominate.
func Encode(f *Flow, n *Norm) Input {
	var in Input
	in.Cat[0] = hashBucket("dest", f.Dest, catBuckets[0])
	in.Cat[1] = hashBucket("asn", strconv.FormatUint(uint64(f.ASN), 10), catBuckets[1])
	in.Cat[2] = hashBucket("parent", strings.ToLower(f.Parent), catBuckets[2])
	c := strings.ToUpper(f.Country)
	if c == "" {
		c = "??"
	}
	in.Cat[3] = hashBucket("country", c, catBuckets[3])
	in.Cat[4] = PortClass(f.Port)
	in.Proto = int32(f.Proto)*2 + int32(f.Dir)
	r := rawNumeric(f)
	for j, v := range r {
		if !passthrough[j] {
			v = (v - float64(n.Mean[j])) / float64(n.Std[j])
			v = math.Max(-5, math.Min(5, v))
		}
		in.Num[j] = float32(v)
	}
	return in
}
