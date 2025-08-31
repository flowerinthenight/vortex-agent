//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"

#include "vortex.h"

#ifndef __BPF_VORTEX_BASE_C
#define __BPF_VORTEX_BASE_C

extern int LINUX_KERNEL_VERSION __kconfig;

/* Event structure to be sent to userspace. */
struct event {
    __u8 comm[TASK_COMM_LEN]; /* for debugging only */
    __u8 buf[EVENT_BUF_LEN];
    __s64 total_len;
    __s64 chunk_len;
    __u64 seq_num;
    __u32 chunk_idx;
    __u32 type;
    __u32 tgid;
    __u32 pid;
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __be16 dport;
    __u64 message_id;
};

/* Map to store events for userspace consumption. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
    __type(value, struct event);
} events SEC(".maps");

/* Basic stats data. */
struct events_stats_t {
    __u64 sent;
    __u64 lost;
};

/* Map for basic stats. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);                   /* always 0 */
    __type(value, struct events_stats_t); /* stats */
} events_stats SEC(".maps");

/* Arbitrary sequence number for events; to help with debugging chunks. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);   /* always 0 */
    __type(value, __u64); /* sequence num */
} seq SEC(".maps");

/*
 * Map to control which TGIDs are traced. A key of TGID_ENABLE_ALL means
 * all TGIDs are traced. Otherwise, only trace whatever's in the map.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  /* TGID */
    __type(value, __u8); /* unused */
} tgids_to_trace SEC(".maps");

struct pid_tgid_rw_k {
    __u64 pid_tgid;
    __u32 rw_flag; /* 0 = read, 1 = write */
};

/*
 * Map to store the {read|written} pointer for SSL_{read|write}[_ex].
 * The value is a pointer to the "bytes {read|written}" value.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct pid_tgid_rw_k);
    __type(value, __u64);
} ssl_rw_ex_p4 SEC(".maps");

/*
 * NOTE:
 * The following struct defs are for associating SSL_writes and SSL_reads to
 * socket information. This makes it limited to apps that are "BIO-native",
 * or those that use their TLS/SSL libraries to handle the networking
 * alongside crypto.
 *
 * Unfortunately, this won't support "BIO-custom apps", or those that only
 * use the TLS/SSL libraries for crypto, and handle networking by themselves.
 *
 * Anyway, this is easier to implement than using offsets, which is very
 * error-prone and requires a lot of maintenance. We might need to do offsets
 * in the future, for those BIO-custom apps.
 */

/* Callstack context information. */
struct ssl_callstack_v {
    uintptr_t buf; /* instead of (char *), which bpf2go doesn't support */
    int len;
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __be16 dport;
};

/* Active on SSL_{write|read}[_ex] entry, removed on SSL_{write|read}[_ex] exit. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct pid_tgid_rw_k);
    __type(value, struct ssl_callstack_v);
} ssl_callstack SEC(".maps");

/* Value for the fd_connect map. */
struct fd_connect_v {
    __u32 fd;
    uintptr_t sk; /* instead of (struct sock *), which bpf2go doesn't support */
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __be16 dport;
};

/* Check if a PID/TGID's fd has called connect on socket. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct fd_connect_v);
} fd_connect SEC(".maps");

/* Active on cgroup/connect4, removed on cgroup/sock_release. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct bpf_sock *); /* sk */
    __type(value, __u64);           /* pid_tgid */
} sk_to_pid_tgid SEC(".maps");

/* Indicates that our tc-based SNI trace filtering is enabled. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);   /* always 0 */
    __type(value, __u32); /* unused */
} tc_sni_trace_on SEC(".maps");

/* Per PID/TGID: we found the SNI, and if tracing is allowed (AI). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);  /* pid_tgid */
    __type(value, __u8); /* 1st bit = default, 2nd bit = SNI allowed */
} tc_sni_trace SEC(".maps");

struct h2_k {
    __u64 pid_tgid;
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __be16 dport;
};

/* Activated in SSL_write[_ex] when HTTP/2. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct h2_k);
    __type(value, __u8); /* 1st bit = data frames found previously (read) */
} is_h2 SEC(".maps");

/* NOTE: temp only */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, char *);
    __type(value, __u32);
} readbuf_len SEC(".maps");

static __always_inline __u64 get_seq() {
    __u32 seq_key = 0;
    __u64 *seq_ptr = bpf_map_lookup_elem(&seq, &seq_key);
    if (!seq_ptr) {
        __u64 init_val = 0;
        bpf_map_update_elem(&seq, &seq_key, &init_val, BPF_ANY);
        return 0;
    }

    *seq_ptr += 1;
    return *seq_ptr;
}

/* Set process information in the event structure. */
static __always_inline void set_proc_info(struct event *event) {
    __builtin_memset(event->comm, 0, sizeof(event->comm));
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid & 0xFFFFFFFF;
    event->tgid = pid_tgid >> 32;
}

/* Are we tracing this TGID? */
static __always_inline int should_trace_tgid(__u32 tgid) {
    __u32 all = TGID_ENABLE_ALL;
    if (bpf_map_lookup_elem(&tgids_to_trace, &all) == NULL)
        if (bpf_map_lookup_elem(&tgids_to_trace, &tgid) == NULL)
            return VORTEX_NO_TRACE;

    return VORTEX_TRACE;
}

/* Check if tracing is allowed through our tc-based SNI filter. */
static __always_inline int should_sni_trace(__u64 pid_tgid) {
    __u32 key = 0;
    if (bpf_map_lookup_elem(&tc_sni_trace_on, &key) == NULL)
        return VORTEX_TRACE;

    __u8 *trace = bpf_map_lookup_elem(&tc_sni_trace, &pid_tgid);
    if (trace)
        if ((*trace & 0x2) != 0x2)
            return VORTEX_NO_TRACE;

    return VORTEX_TRACE;
}

/* Our wrapper to bpf_ringbuf_reserve() to track lost packets. */
static __always_inline void *rb_events_reserve_with_stats() {
    void *rb = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (rb)
        return rb;

    __u32 key = 0;
    struct events_stats_t *stats;
    stats = bpf_map_lookup_elem(&events_stats, &key);
    if (!stats) {
        struct events_stats_t n_stats = {.sent = 0, .lost = 1};
        bpf_map_update_elem(&events_stats, &key, &n_stats, BPF_ANY);
        return rb;
    }

    __sync_fetch_and_add(&stats->lost, 1);
#if DEBUG_BPF_PRINTK == 1
    bpf_printk("rb_events_reserve_with_stats: lost=%llu", stats->lost);
#endif

    return rb;
}

/* Our wrapper to bpf_ringbuf_submit() to track sent packets. */
static __always_inline void rb_events_submit_with_stats(void *event, __u64 flags) {
    bpf_ringbuf_submit(event, flags);

    __u32 key = 0;
    struct events_stats_t *stats;
    stats = bpf_map_lookup_elem(&events_stats, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->sent, 1);
        return;
    }

    struct events_stats_t n_stats = {.sent = 1, .lost = 0};
    bpf_map_update_elem(&events_stats, &key, &n_stats, BPF_ANY);
}

#endif /* __BPF_VORTEX_BASE_C */
