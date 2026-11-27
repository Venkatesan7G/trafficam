package etw

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"time"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

// netOp is what happened on a socket, decoded from the Kernel-Network event ID.
type netOp uint8

const (
	opSend        netOp = iota + 1 // bytes sent
	opRecv                         // bytes received
	opConnect                      // this PC opened a TCP connection (handshake done)
	opAccept                       // this PC accepted an incoming TCP connection
	opDisconnect                   // TCP connection closed
	opRetransmit                   // TCP segment sent again (lost packet or no answer)
	opReconnect                    // TCP connect attempt repeated (no answer yet)
	opConnectFail                  // TCP connect gave up: refused, timed out, unreachable (TCPIP event 1034)
)

// netEvent is one decoded Kernel-Network event. It is small and has no
// pointers so pushing it through a channel is cheap.
type netEvent struct {
	Op     netOp
	Proto  event.Proto // TCP or UDP
	PID    uint32
	Size   uint32 // payload bytes for send/receive; NTSTATUS for opConnectFail
	Local  netip.AddrPort
	Remote netip.AddrPort
	Time   time.Time
}

// kernelNetworkIDs maps the Kernel-Network event IDs we use to (op, proto, ipv6).
//
// Source: the provider manifest ("logman query providers
// Microsoft-Windows-Kernel-Network" / "wevtutil gp ... /ge /gm"). IPv6
// variants are the IPv4 ID + 16. IDs not listed (TCP copy, the address-less
// "fail" events 17 and 49) are ignored.
var kernelNetworkIDs = map[uint16]struct {
	op    netOp
	proto event.Proto
	v6    bool
}{
	10: {opSend, event.TCP, false}, 26: {opSend, event.TCP, true},
	11: {opRecv, event.TCP, false}, 27: {opRecv, event.TCP, true},
	12: {opConnect, event.TCP, false}, 28: {opConnect, event.TCP, true},
	13: {opDisconnect, event.TCP, false}, 29: {opDisconnect, event.TCP, true},
	14: {opRetransmit, event.TCP, false}, 30: {opRetransmit, event.TCP, true},
	15: {opAccept, event.TCP, false}, 31: {opAccept, event.TCP, true},
	16: {opReconnect, event.TCP, false}, 32: {opReconnect, event.TCP, true},
	42: {opSend, event.UDP, false}, 58: {opSend, event.UDP, true},
	43: {opRecv, event.UDP, false}, 59: {opRecv, event.UDP, true},
}

// parseKernelNetwork decodes the fixed start that every Kernel-Network event
// we use shares:
//
//	IPv4: PID u32 | size u32 | daddr [4]  | saddr [4]  | dport u16 | sport u16 | ...
//	IPv6: PID u32 | size u32 | daddr [16] | saddr [16] | dport u16 | sport u16 | ...
//
// Integers are little-endian; addresses and ports are in network byte order
// (big-endian), as on the wire. "d" is always the remote end and "s" the local
// end of the socket, for sends and receives alike.
//
// The PID in the payload is the process that owns the socket. (The PID in the
// ETW event header is just whichever process the CPU was running, and is
// often wrong for receives, so we never use it here.)
//
// ok is false for event IDs we do not use or payloads that are too short.
func parseKernelNetwork(id uint16, data []byte, t time.Time) (ev netEvent, ok bool) {
	k, known := kernelNetworkIDs[id]
	if !known {
		return ev, false
	}
	alen := 4
	if k.v6 {
		alen = 16
	}
	need := 8 + 2*alen + 4
	if len(data) < need {
		return ev, false
	}
	ev.Op, ev.Proto, ev.Time = k.op, k.proto, t
	ev.PID = binary.LittleEndian.Uint32(data[0:4])
	ev.Size = binary.LittleEndian.Uint32(data[4:8])
	daddr := addrFrom(data[8 : 8+alen])
	saddr := addrFrom(data[8+alen : 8+2*alen])
	p := 8 + 2*alen
	dport := binary.BigEndian.Uint16(data[p : p+2])
	sport := binary.BigEndian.Uint16(data[p+2 : p+4])
	ev.Remote = netip.AddrPortFrom(daddr, dport)
	ev.Local = netip.AddrPortFrom(saddr, sport)
	return ev, true
}

func addrFrom(b []byte) netip.Addr {
	if len(b) == 4 {
		return netip.AddrFrom4([4]byte(b)).Unmap()
	}
	return netip.AddrFrom16([16]byte(b)).Unmap() // "::ffff:1.2.3.4" -> "1.2.3.4"
}

// tcpConnectFailID is Microsoft-Windows-TCPIP's TcpConnectTcbFailure event:
// "a TCP connect attempt failed". Kernel-Network has no usable event for
// this (its "fail" events 17/49 carry no addresses), and a connection that is
// refused straight away (the other side answers "nothing listening here")
// sends no data, so without this event it would not be seen at all.
const tcpConnectFailID = 1034

// Status codes seen in event 1034 (NTSTATUS values).
const (
	statusConnectionRefused = 0xC0000236
	statusIOTimeout         = 0xC00000B5
)

// parseTCPConnectFail decodes event 1034 (versions 0 and 1 share this start):
//
//	LocalAddressLength u32 | LocalAddress [len] | RemoteAddressLength u32 |
//	RemoteAddress [len] | Status u32 | ProcessId u32 | Compartment u32 | Tcb ptr | ...
//
// The addresses are Windows SOCKADDR structures (sockaddr_in, 16 bytes, or
// sockaddr_in6, 28 bytes). Integers are little-endian. The PID is the
// process that owns the socket. ok is false for anything malformed.
func parseTCPConnectFail(data []byte, t time.Time) (ev netEvent, ok bool) {
	local, rest, ok1 := lenPrefixedSockaddr(data)
	remote, rest, ok2 := lenPrefixedSockaddr(rest)
	if !ok1 || !ok2 || len(rest) < 8 {
		return ev, false
	}
	ev.Op, ev.Proto, ev.Time = opConnectFail, event.TCP, t
	ev.Local, ev.Remote = local, remote
	ev.Size = binary.LittleEndian.Uint32(rest[0:4]) // status
	ev.PID = binary.LittleEndian.Uint32(rest[4:8])
	return ev, true
}

// lenPrefixedSockaddr reads "length u32 | SOCKADDR" and returns the rest.
func lenPrefixedSockaddr(b []byte) (netip.AddrPort, []byte, bool) {
	if len(b) < 4 {
		return netip.AddrPort{}, nil, false
	}
	n := int(binary.LittleEndian.Uint32(b[0:4]))
	if n < 16 || n > 128 || len(b) < 4+n {
		return netip.AddrPort{}, nil, false
	}
	ap, ok := parseSockaddr(b[4 : 4+n])
	return ap, b[4+n:], ok
}

// parseSockaddr reads a Windows sockaddr_in (AF_INET = 2) or sockaddr_in6
// (AF_INET6 = 23). The family is little-endian; port and address are in
// network byte order.
func parseSockaddr(b []byte) (netip.AddrPort, bool) {
	if len(b) < 8 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(b[2:4])
	switch binary.LittleEndian.Uint16(b[0:2]) {
	case 2:
		return netip.AddrPortFrom(addrFrom(b[4:8]), port), true
	case 23:
		if len(b) < 24 {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(addrFrom(b[8:24]), port), true
	}
	return netip.AddrPort{}, false
}

// dnsEvent is one finished DNS lookup from the DNS-Client provider (event 3008).
type dnsEvent struct {
	PID    uint32
	Name   string       // name that was looked up, lower case, no trailing dot
	Status uint32       // 0 = success; otherwise a Win32/DNS error (9003 = name does not exist)
	Addrs  []netip.Addr // IP answers (CNAME steps are dropped)
	Time   time.Time
}

// dnsCompletedID is the DNS-Client event "DNS query is completed".
const dnsCompletedID = 3008

// parseDNSResults turns the QueryResults text of event 3008 into addresses.
// Windows formats it as entries separated by ';', for example:
//
//	"type:  5 example.cdn.net;::ffff:93.184.216.34;2606:2800::1;"
//
// IPv4 answers come as IPv4-mapped IPv6 ("::ffff:a.b.c.d"). Entries starting
// with "type:" are non-address records (CNAME and friends) and are skipped.
func parseDNSResults(s string) []netip.Addr {
	var out []netip.Addr
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "type:") {
			continue
		}
		if a, err := netip.ParseAddr(part); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// cleanDNSName lower-cases a name and drops the trailing root dot.
func cleanDNSName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// procEvent is a process start or stop from Microsoft-Windows-Kernel-Process.
type procEvent struct {
	Start     bool // true = started, false = exited
	PID       uint32
	ParentPID uint32
	Image     string // NT path as Windows logs it, e.g. \Device\HarddiskVolume3\Windows\System32\cmd.exe
	Time      time.Time
}

// Kernel-Process event IDs (keyword WINEVENT_KEYWORD_PROCESS).
const (
	procStartID = 1
	procStopID  = 2
)

// filetimeToTime converts a Windows FILETIME (100 ns ticks since 1601-01-01
// UTC) to time.Time. ETW timestamps use this format when the session is
// started with "system time" clock resolution, which we do.
func filetimeToTime(ft int64) time.Time {
	const ticksTo1970 = 116444736000000000
	return time.Unix(0, (ft-ticksTo1970)*100).UTC()
}
