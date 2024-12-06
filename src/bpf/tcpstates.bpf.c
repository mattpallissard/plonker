#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "tcpstates.h"

#define MAX_ENTRIES 10240
#define AF_INET 2
#define AF_INET6 10

const volatile short target_family = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u16);
	__type(value, __u16);
} sports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, __u8);
} states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
	struct sock *sk = (struct sock *)ctx->skaddr;
	__u16 family = ctx->family;
	__u16 sport = ctx->sport;
	__u16 allport = 0;
	__u8 seen = 1;
	__u16 dport = ctx->dport;
	__u64 *tsp, srtt_us, ts;
	__u16 protocol = ctx->protocol;
	struct event event = {};
	struct tcp_sock *tp;

	if (ctx->protocol != IPPROTO_TCP)
		return 0;

	if (!bpf_map_lookup_elem(&sports, &sport) &&
	    !bpf_map_lookup_elem(&sports, &allport))
		return 0;

	// start tracking from the LISTEN state.
	if (ctx->oldstate == TCP_LISTEN) {
		bpf_map_update_elem(&states, &sk, &seen, BPF_ANY);
		return 0;
	}

	// we only care about ESTABLISHED TCP sessions from here on out
	if (ctx->newstate != TCP_ESTABLISHED) {

                bpf_trace_printk("Here!\0", 6);
		return 0;
        }

	// and only ones that have originated from the TCP_LISTEN state,
	// preventing us from logging outbound connections
	if (!bpf_map_lookup_elem(&states, &sk))
		return 0;

	ts = bpf_ktime_get_ns();

	tp = (struct tcp_sock *)(sk);

	srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;
	event.srtt_us = srtt_us;
	event.ts = ts;
	event.family = family;
	event.protocol = protocol;
	// swap source and dest due to packet direction
	event.sport = dport;
	event.dport = sport;

	if (family == AF_INET) {
		// swap source and dest due to packet direction
		bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr),
				      &sk->__sk_common.skc_daddr);
		bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr),
				      &sk->__sk_common.skc_rcv_saddr);
	} else { // implied AF_INET6 due to IPPROTO_TCP above
		// swap source and dest due to packet direction
		bpf_probe_read_kernel(
			&event.saddr, sizeof(event.saddr),
			&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(
			&event.daddr, sizeof(event.daddr),
			&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

	bpf_map_delete_elem(&states, &sk);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
