// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-or-later
//
// trafficam.bpf.c: the kernel half of the Linux collector.
//
// This file is compiled to eBPF bytecode (by clang, via `go generate`) and
// loaded into the kernel by collector.go. It only OBSERVES: every hook below
// is a tracing hook (tp_btf / fentry / fexit) that runs after or beside the
// kernel's own code and cannot change a return value, drop a packet or delay
// anything. If trafficam crashes, the kernel simply detaches these hooks and
// networking carries on untouched.
//
// What it records:
//   TCP: who opened each connection (outbound connect or inbound accept),
//        whether the handshake completed, bytes/segments each way, and how
//        long it lasted. One event when it opens, one when it closes.
//   UDP: a per (socket, remote address) counter table that user space sweeps
//        every few seconds. One event when a new UDP peer first appears.
//   DNS owner table: local UDP port -> owning process, so user space can tell
//        which program sent each DNS packet it sniffs.
//
// Licence: the kernel only loads tracing programs that declare a
// GPL-compatible licence, and the kernel is GPLv2. trafficam is GPL-3.0, so
// this one file is dual licensed (GPLv2 or GPLv3+) to be valid in both places.

#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define IPPROTO_TCP 6

// Event kinds sent to user space. Keep in sync with collector.go.
enum {
	EV_TCP_OPEN = 1,  // a TCP connection started (owner is known)
	EV_TCP_CLOSE = 2, // a TCP connection ended; carries the totals
	EV_UDP_OPEN = 3,  // first packet with a new UDP peer
};

enum {
	DIR_OUT = 1,
	DIR_IN = 2,
};

// owner: who a socket belongs to. Captured in the kernel at the moment of
// connect/listen/send, so it is right even if the process exits a
// millisecond later (user space then cannot read /proc any more).
struct owner {
	__u64 cgroup; // cgroup v2 id; user space maps it to a systemd unit
	__u32 tgid;   // process id
	__u32 ppid;   // parent process id
	char comm[16];
	char pcomm[16]; // parent's comm
};

// The record sent to user space through the ring buffer.
struct event {
	__u64 sk;       // kernel socket address, used only as an id
	__u64 start_ns; // CLOCK_BOOTTIME nanoseconds
	__u64 end_ns;
	__u64 bytes_in;
	__u64 bytes_out;
	__u64 pkts_in;
	__u64 pkts_out;
	struct owner o;
	__u8 saddr[16]; // local address (first 4 bytes for IPv4)
	__u8 daddr[16]; // remote address
	__u16 sport;    // local port, host byte order
	__u16 dport;    // remote port, host byte order
	__u8 kind;
	__u8 family; // AF_INET or AF_INET6
	__u8 dir;
	__u8 established;
};

// Per TCP connection state, keyed by the kernel's socket pointer.
struct conn {
	struct owner o;
	__u64 start_ns;
	__u8 laddr[16]; // local address, saved when established
	__u16 lport;
	__u8 dir;
	__u8 established;
	__u8 has_owner;
};

// UDP counters, keyed by (socket, remote address). User space reads and
// deletes idle entries.
struct udp_key {
	__u64 sk;
	__u8 raddr[16];
	__u16 rport;
	__u16 family;
	__u32 pad;
};

struct udp_val {
	struct owner o;
	__u64 first_ns;
	__u64 last_ns;
	__u64 bytes_in;
	__u64 bytes_out;
	__u64 pkts_in;
	__u64 pkts_out;
	__u8 laddr[16];
	__u16 lport;
	__u8 dir; // who sent first
	__u8 pad[5];
};


// Mentions struct event so the Go code generator emits a matching Go type.
const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB; if user space falls behind, events drop
} events SEC(".maps");

// LRU maps evict the oldest entry when full instead of failing, so a burst
// of connections can never make the kernel side stop working.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct conn);
} conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u16); // listening port
	__type(value, struct owner);
} listeners SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct udp_key);
	__type(value, struct udp_val);
} udp_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u16); // local UDP port
	__type(value, struct owner);
} udp_owner SEC(".maps");

// fill_owner records the current process. Only valid in process context
// (syscalls), not in packet-receive interrupts.
static __always_inline void fill_owner(struct owner *o)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(t, real_parent);

	o->tgid = bpf_get_current_pid_tgid() >> 32;
	o->ppid = BPF_CORE_READ(parent, tgid);
	o->cgroup = bpf_get_current_cgroup_id();
	bpf_get_current_comm(o->comm, sizeof(o->comm));
	bpf_core_read_str(o->pcomm, sizeof(o->pcomm), &parent->comm);
}

// read_addrs copies the socket's local and remote address and ports.
static __always_inline void read_addrs(const struct sock *sk, __u16 family,
				       __u8 *saddr, __u8 *daddr, __u16 *sport, __u16 *dport)
{
	if (family == AF_INET) {
		BPF_CORE_READ_INTO((__u32 *)saddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO((__u32 *)daddr, sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO((struct in6_addr *)saddr, sk, __sk_common.skc_v6_rcv_saddr);
		BPF_CORE_READ_INTO((struct in6_addr *)daddr, sk, __sk_common.skc_v6_daddr);
	}
	*sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	*dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

static __always_inline void emit_tcp(const struct sock *sk, struct conn *c, __u8 kind, __u16 family)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return; // ring buffer full: drop rather than wait
	__builtin_memset(e, 0, sizeof(*e));
	e->sk = (__u64)sk;
	e->kind = kind;
	e->family = family;
	e->dir = c->dir;
	e->established = c->established;
	e->start_ns = c->start_ns;
	e->o = c->o;
	read_addrs(sk, family, e->saddr, e->daddr, &e->sport, &e->dport);
	if (e->sport == 0 && c->lport != 0) {
		__builtin_memcpy(e->saddr, c->laddr, 16);
		e->sport = c->lport;
	}
	if (kind == EV_TCP_CLOSE) {
		const struct tcp_sock *tp = (const struct tcp_sock *)sk;
		e->end_ns = bpf_ktime_get_boot_ns();
		// Counted from sequence numbers, so the SYN/FIN can add 1-2 bytes.
		// Retransmissions are not double counted.
		e->bytes_in = BPF_CORE_READ(tp, bytes_received);
		e->bytes_out = BPF_CORE_READ(tp, bytes_acked);
		e->pkts_in = BPF_CORE_READ(tp, segs_in);
		e->pkts_out = BPF_CORE_READ(tp, segs_out);
	}
	bpf_ringbuf_submit(e, 0);
}

// Every TCP state change on the machine passes through this tracepoint.
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(on_tcp_state, const struct sock *sk, const int oldstate, const int newstate)
{
	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
		return 0;
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	__u64 key = (__u64)sk;

	// listen(): remember which program owns the port, for inbound connections.
	if (newstate == TCP_LISTEN) {
		struct owner o = {};
		fill_owner(&o);
		__u16 port = BPF_CORE_READ(sk, __sk_common.skc_num);
		bpf_map_update_elem(&listeners, &port, &o, BPF_ANY);
		return 0;
	}
	if (oldstate == TCP_LISTEN && newstate == TCP_CLOSE) {
		__u16 port = BPF_CORE_READ(sk, __sk_common.skc_num);
		bpf_map_delete_elem(&listeners, &port);
		return 0;
	}

	// connect(): we are inside the calling program's syscall.
	if (newstate == TCP_SYN_SENT) {
		struct conn c = {};
		fill_owner(&c.o);
		c.start_ns = bpf_ktime_get_boot_ns();
		c.dir = DIR_OUT;
		c.has_owner = 1;
		bpf_map_update_elem(&conns, &key, &c, BPF_ANY);
		emit_tcp(sk, &c, EV_TCP_OPEN, family);
		return 0;
	}

	// Inbound: the kernel creates the new socket in SYN_RECV (copied from
	// the listening socket, so oldstate is LISTEN) when the handshake's last
	// packet arrives. That runs in packet-receive context, not in the
	// server program, so the owner comes from the listening port instead.
	if (newstate == TCP_SYN_RECV) {
		struct conn c = {};
		c.start_ns = bpf_ktime_get_boot_ns();
		c.dir = DIR_IN;
		__u16 port = BPF_CORE_READ(sk, __sk_common.skc_num);
		struct owner *lo = bpf_map_lookup_elem(&listeners, &port);
		if (lo) {
			c.o = *lo;
			c.has_owner = 1;
		}
		bpf_map_update_elem(&conns, &key, &c, BPF_NOEXIST);
		// Sent even without an owner (tgid 0): user space then looks the
		// listening port up in /proc.
		emit_tcp(sk, &c, EV_TCP_OPEN, family);
		return 0;
	}

	struct conn *c = bpf_map_lookup_elem(&conns, &key);
	if (!c)
		return 0; // a connection that started before trafficam did

	if (newstate == TCP_ESTABLISHED) {
		c->established = 1;
		// Remember the local address now: by the time the state becomes
		// CLOSE the kernel has already released the local port.
		__u8 dummy[16];
		__u16 dp;
		read_addrs(sk, family, c->laddr, dummy, &c->lport, &dp);
		return 0;
	}
	if (newstate == TCP_CLOSE) {
		emit_tcp(sk, c, EV_TCP_CLOSE, family);
		bpf_map_delete_elem(&conns, &key);
	}
	return 0;
}

// Fallback owner for inbound connections whose listener we never saw
// (it started listening before trafficam): the first program to read or
// write the socket owns it.
static __always_inline int claim_tcp(struct sock *sk)
{
	__u64 key = (__u64)sk;
	struct conn *c = bpf_map_lookup_elem(&conns, &key);
	if (!c || c->has_owner)
		return 0;
	fill_owner(&c->o);
	c->has_owner = 1;
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	emit_tcp(sk, c, EV_TCP_OPEN, family);
	return 0;
}

// Only the first argument is read, so these work whatever the kernel's
// argument list for these functions looks like.
SEC("fentry/tcp_sendmsg")
int BPF_PROG(on_tcp_sendmsg, struct sock *sk)
{
	return claim_tcp(sk);
}

SEC("fentry/tcp_recvmsg")
int BPF_PROG(on_tcp_recvmsg, struct sock *sk)
{
	return claim_tcp(sk);
}

// udp_account adds one sent or received datagram to the counter table.
static __always_inline int udp_account(struct sock *sk, struct msghdr *msg, int bytes, __u8 dir)
{
	if (bytes <= 0)
		return 0; // the call failed; nothing went over the wire

	struct udp_key k = {};
	k.sk = (__u64)sk;

	// Unconnected sockets (most DNS clients) name the peer per message;
	// msg_name points at the kernel's own copy of that address.
	void *name = BPF_CORE_READ(msg, msg_name);
	if (name) {
		unsigned short fam = 0;
		bpf_probe_read_kernel(&fam, sizeof(fam), name);
		if (fam == AF_INET) {
			struct sockaddr_in sa = {};
			bpf_probe_read_kernel(&sa, sizeof(sa), name);
			__builtin_memcpy(k.raddr, &sa.sin_addr, 4);
			k.rport = bpf_ntohs(sa.sin_port);
			k.family = AF_INET;
		} else if (fam == AF_INET6) {
			struct sockaddr_in6 sa = {};
			bpf_probe_read_kernel(&sa, sizeof(sa), name);
			__builtin_memcpy(k.raddr, &sa.sin6_addr, 16);
			k.rport = bpf_ntohs(sa.sin6_port);
			k.family = AF_INET6;
		}
	}
	__u16 skfam = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (k.family == 0) {
		// Connected socket: the peer is stored on the socket.
		__u8 dummy[16];
		__u16 sp;
		k.family = skfam;
		read_addrs(sk, skfam, dummy, k.raddr, &sp, &k.rport);
	}
	if (k.rport == 0)
		return 0; // peer unknown

	__u64 now = bpf_ktime_get_boot_ns();
	struct udp_val *v = bpf_map_lookup_elem(&udp_flows, &k);
	if (!v) {
		struct udp_val nv = {};
		__u16 dp;
		__u8 dummy[16];
		fill_owner(&nv.o);
		nv.first_ns = now;
		nv.last_ns = now;
		nv.dir = dir;
		read_addrs(sk, skfam, nv.laddr, dummy, &nv.lport, &dp);
		bpf_map_update_elem(&udp_flows, &k, &nv, BPF_NOEXIST);
		bpf_map_update_elem(&udp_owner, &nv.lport, &nv.o, BPF_ANY);

		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			__builtin_memset(e, 0, sizeof(*e));
			e->sk = (__u64)sk;
			e->kind = EV_UDP_OPEN;
			e->family = k.family;
			e->dir = dir;
			e->start_ns = now;
			e->o = nv.o;
			__builtin_memcpy(e->saddr, nv.laddr, 16);
			__builtin_memcpy(e->daddr, k.raddr, 16);
			e->sport = nv.lport;
			e->dport = k.rport;
			bpf_ringbuf_submit(e, 0);
		}
		v = bpf_map_lookup_elem(&udp_flows, &k);
		if (!v)
			return 0;
	}
	v->last_ns = now;
	if (dir == DIR_OUT) {
		__sync_fetch_and_add(&v->bytes_out, bytes);
		__sync_fetch_and_add(&v->pkts_out, 1);
	} else {
		__sync_fetch_and_add(&v->bytes_in, bytes);
		__sync_fetch_and_add(&v->pkts_in, 1);
	}
	return 0;
}

// fexit = runs right after the function returns. We use fexit for sends
// because a brand-new socket only gets its local port during the first send.
//
// The argument lists of these functions change between kernels (for
// example Linux 7.0 dropped addr_len from udp_recvmsg), and in an fexit
// program the return value sits right after the last argument. So instead
// of naming every argument we read only the first two (sk, msg), which
// every version has, and get the return value with bpf_get_func_ret().
static __always_inline int udp_exit(unsigned long long *ctx, __u8 dir, bool v4_only)
{
	struct sock *sk = (struct sock *)ctx[0];
	struct msghdr *msg = (struct msghdr *)ctx[1];
	__u64 ret = 0;

	// An IPv6 socket sending to an IPv4 peer goes udpv6_sendmsg -> udp_sendmsg.
	// Count it once, in the IPv6 hook.
	if (v4_only && BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET)
		return 0;
	bpf_get_func_ret(ctx, &ret);
	return udp_account(sk, msg, (int)ret, dir);
}

SEC("fexit/udp_sendmsg")
int on_udp_sendmsg(unsigned long long *ctx)
{
	return udp_exit(ctx, DIR_OUT, true);
}

SEC("fexit/udpv6_sendmsg")
int on_udpv6_sendmsg(unsigned long long *ctx)
{
	return udp_exit(ctx, DIR_OUT, false);
}

SEC("fexit/udp_recvmsg")
int on_udp_recvmsg(unsigned long long *ctx)
{
	return udp_exit(ctx, DIR_IN, false);
}

SEC("fexit/udpv6_recvmsg")
int on_udpv6_recvmsg(unsigned long long *ctx)
{
	return udp_exit(ctx, DIR_IN, false);
}
