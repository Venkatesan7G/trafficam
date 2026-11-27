/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-or-later */
/*
 * vmlinux_min.h: the few kernel types trafficam's eBPF program reads.
 *
 * Normally eBPF programs include a generated vmlinux.h (several MB) with every
 * kernel type. We only need a handful of fields, so we declare just those.
 *
 * The magic is __attribute__((preserve_access_index)), which turns on CO-RE
 * ("Compile Once, Run Everywhere"): field offsets written here are NOT used
 * as-is. At load time the loader looks up each field BY NAME in the running
 * kernel's own type info (/sys/kernel/btf/vmlinux) and patches the real
 * offset in. So these structs may list fields in any order and skip
 * everything we do not need; only the names and types must match.
 */
#ifndef TRAFFICAM_VMLINUX_MIN_H
#define TRAFFICAM_VMLINUX_MIN_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef _Bool bool;
#define true 1
#define false 0

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

#define AF_INET 2
#define AF_INET6 10

/* TCP states (include/net/tcp_states.h). These numbers are UAPI-stable. */
enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_CLOSE = 7,
	TCP_LISTEN = 10,
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

/* In the kernel these sit inside anonymous unions/structs; CO-RE finds them
 * by name anyway. */
struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num; /* local port, host byte order */
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol; /* IPPROTO_TCP, IPPROTO_UDP, ... (a plain u16 since 5.6) */
} __attribute__((preserve_access_index));

struct tcp_sock {
	__u64 bytes_received; /* payload bytes received */
	__u64 bytes_acked;    /* payload bytes sent and acknowledged */
	__u32 segs_in;
	__u32 segs_out;
} __attribute__((preserve_access_index));

struct msghdr {
	void *msg_name; /* destination/source address, kernel copy */
	int msg_namelen;
} __attribute__((preserve_access_index));

struct task_struct {
	int pid;  /* thread id */
	int tgid; /* process id as users know it */
	struct task_struct *real_parent;
	char comm[16];
} __attribute__((preserve_access_index));

/* UAPI socket address layouts: fixed by the ABI, so no CO-RE needed. */
struct sockaddr_in {
	unsigned short sin_family;
	__be16 sin_port;
	__be32 sin_addr;
	__u8 pad[8];
};

struct sockaddr_in6 {
	unsigned short sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

#endif
