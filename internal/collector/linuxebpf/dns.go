//go:build linux

package linuxebpf

// dns.go reads DNS packets so trafficam knows (a) which names each program
// looks up and (b) which name an IP address came from, so a connection to
// 93.184.216.34 can be shown as "example.org".
//
// How: a passive packet socket (AF_PACKET, the same thing tcpdump uses)
// with a tiny classic BPF filter that only lets UDP port 53 through. It
// receives COPIES of packets; it cannot change or block them. Which program
// sent a DNS packet comes from the eBPF udp_owner map (local port -> owner).
//
// Limits: encrypted DNS (DNS over HTTPS/TLS, e.g. browsers with "secure
// DNS" on) cannot be read. Those connections still show up, just by IP.

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/dns/dnsmessage"
)

// dnsPacket is one parsed DNS message with its addresses.
type dnsPacket struct {
	Src, Dst netip.AddrPort
	Response bool
	Name     string       // the question, lower case, no trailing dot
	Answers  []netip.Addr // A and AAAA records in a response
	TTL      time.Duration
}

// parseDNSPacket parses an IPv4 or IPv6 packet (starting at the IP header)
// carrying UDP port 53. ok=false for anything else or anything malformed.
// It must never panic on hostile input; it is fuzz tested.
func parseDNSPacket(pkt []byte) (p dnsPacket, ok bool) {
	if len(pkt) < 1 {
		return p, false
	}
	var payload []byte
	var srcIP, dstIP netip.Addr
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return p, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+8 || pkt[9] != 17 { // 17 = UDP
			return p, false
		}
		srcIP = netip.AddrFrom4([4]byte(pkt[12:16]))
		dstIP = netip.AddrFrom4([4]byte(pkt[16:20]))
		payload = pkt[ihl:]
	case 6:
		if len(pkt) < 48 || pkt[6] != 17 { // no extension headers expected for DNS
			return p, false
		}
		srcIP = netip.AddrFrom16([16]byte(pkt[8:24]))
		dstIP = netip.AddrFrom16([16]byte(pkt[24:40]))
		payload = pkt[40:]
	default:
		return p, false
	}
	sport := binary.BigEndian.Uint16(payload[0:2])
	dport := binary.BigEndian.Uint16(payload[2:4])
	p.Src = netip.AddrPortFrom(srcIP, sport)
	p.Dst = netip.AddrPortFrom(dstIP, dport)
	body := payload[8:]

	var parser dnsmessage.Parser
	hdr, err := parser.Start(body)
	if err != nil {
		return p, false
	}
	p.Response = hdr.Response
	q, err := parser.Question()
	if err != nil {
		return p, false
	}
	p.Name = normName(q.Name.String())
	_ = parser.SkipAllQuestions()
	if !p.Response {
		return p, true
	}
	minTTL := uint32(0)
	for {
		h, err := parser.AnswerHeader()
		if err != nil {
			break // done, or truncated: keep what we have
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := parser.AResource()
			if err != nil {
				return p, true
			}
			p.Answers = append(p.Answers, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := parser.AAAAResource()
			if err != nil {
				return p, true
			}
			p.Answers = append(p.Answers, netip.AddrFrom16(r.AAAA))
		default:
			// CNAMEs etc.: the A/AAAA records that follow are still
			// answers for the name the program asked about.
			if err := parser.SkipAnswer(); err != nil {
				return p, true
			}
			continue
		}
		if minTTL == 0 || h.TTL < minTTL {
			minTTL = h.TTL
		}
	}
	p.TTL = time.Duration(minTTL) * time.Second
	return p, true
}

func normName(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

// dnsFilter is a classic BPF program run by the kernel on every packet the
// packet socket would see. It returns 0 (drop) unless the packet is UDP to
// or from port 53, so user space is not woken for other traffic. Packets
// start at the IP header because we use a SOCK_DGRAM packet socket.
func dnsFilter() ([]bpf.RawInstruction, error) {
	const keep, drop = 65535, 0
	// Skip counts are "instructions to jump over". They are easy to get
	// wrong, so dns_test.go runs this program in a BPF emulator against
	// real packets.
	return bpf.Assemble([]bpf.Instruction{
		// IP version nibble.
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x60, SkipTrue: 11},    // -> IPv6
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipFalse: 9},    // not IPv4 -> drop
		bpf.LoadAbsolute{Off: 9, Size: 1},                           // IPv4 protocol
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 7},      // not UDP -> drop
		bpf.LoadAbsolute{Off: 6, Size: 2},                           // fragment offset
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 5}, // later fragment -> drop
		bpf.LoadMemShift{Off: 0},                                    // X = IPv4 header length
		bpf.LoadIndirect{Off: 0, Size: 2},                           // UDP source port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 10},      // -> keep
		bpf.LoadIndirect{Off: 2, Size: 2},                           // UDP destination port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 8},       // -> keep
		bpf.RetConstant{Val: drop},
		// IPv6 (no extension headers).
		bpf.LoadAbsolute{Off: 6, Size: 1},                      // next header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 4}, // not UDP -> drop
		bpf.LoadAbsolute{Off: 40, Size: 2},                     // UDP source port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 3},  // -> keep
		bpf.LoadAbsolute{Off: 42, Size: 2},                     // UDP destination port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 1, SkipFalse: 0},
		bpf.RetConstant{Val: drop},
		bpf.RetConstant{Val: keep},
	})
}

// nameCache remembers which DNS name each IP address came from, per
// process and machine-wide. The per-process entry wins because two
// programs may resolve different names that share a CDN address.
type nameCache struct {
	mu     sync.Mutex
	byProc map[procIP]nameEntry
	global map[netip.Addr]nameEntry
	max    int
	now    func() time.Time
}

type procIP struct {
	pid int
	ip  netip.Addr
}

type nameEntry struct {
	name    string
	expires time.Time
}

func newNameCache(max int) *nameCache {
	return &nameCache{byProc: map[procIP]nameEntry{}, global: map[netip.Addr]nameEntry{}, max: max, now: time.Now}
}

// Put records that pid looked up name and got ip. TTLs are clamped to
// [1 min, 1 h]: programs often keep using an address past its TTL.
func (c *nameCache) Put(pid int, ip netip.Addr, name string, ttl time.Duration) {
	ttl = max(time.Minute, min(ttl, time.Hour))
	ip = ip.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.byProc) >= c.max || len(c.global) >= c.max {
		c.sweepLocked()
	}
	e := nameEntry{name, c.now().Add(ttl)}
	if pid > 0 {
		c.byProc[procIP{pid, ip}] = e
	}
	c.global[ip] = e
}

// Lookup returns the name pid most likely used to reach ip, or "".
func (c *nameCache) Lookup(pid int, ip netip.Addr) string {
	ip = ip.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if e, ok := c.byProc[procIP{pid, ip}]; ok && now.Before(e.expires) {
		return e.name
	}
	if e, ok := c.global[ip]; ok && now.Before(e.expires) {
		return e.name
	}
	return ""
}

func (c *nameCache) sweepLocked() {
	now := c.now()
	for k, e := range c.byProc {
		if !now.Before(e.expires) {
			delete(c.byProc, k)
		}
	}
	for k, e := range c.global {
		if !now.Before(e.expires) {
			delete(c.global, k)
		}
	}
	// Still full of live entries (a flood of lookups): start over rather
	// than grow without bound.
	if len(c.byProc) >= c.max {
		c.byProc = map[procIP]nameEntry{}
	}
	if len(c.global) >= c.max {
		c.global = map[netip.Addr]nameEntry{}
	}
}
