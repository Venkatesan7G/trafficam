//go:build linux

package linuxebpf

// `go generate ./internal/collector/linuxebpf` compiles bpf/trafficam.bpf.c
// with clang and writes trafficam_bpfel*.go/.o (Go bindings + bytecode).
// The generated files are committed, so a normal `go build` does not need
// clang. Re-run this after editing the C file (needs clang and libbpf-dev).
//
//go:generate go tool bpf2go -tags linux -target amd64,arm64 -type event -type udp_key -type udp_val -type owner trafficam bpf/trafficam.bpf.c -- -O2 -g -Wall -Werror -I bpf
