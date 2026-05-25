// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef SOCK_RAW
#define SOCK_RAW 3
#endif
#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif
#ifndef AF_PACKET
#define AF_PACKET 17
#endif

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef IPPROTO_RAW
#define IPPROTO_RAW 255
#endif
#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif

#define RW_BPF_EVENT_CONNECT 1
#define RW_BPF_EVENT_SOCKET 2
#define RW_BPF_EVENT_SYSCALL 3

#define RW_BPF_KIND_PTRACE 1
#define RW_BPF_KIND_PVM_WRITE 2
#define RW_BPF_KIND_PVM_READ 3
#define RW_BPF_KIND_MPROTECT_EXEC 4
#define RW_BPF_KIND_MMAP_EXEC 5
#define RW_BPF_KIND_MEMFD_CREATE 6
#define RW_BPF_KIND_EXECVE 7
#define RW_BPF_KIND_EXECVEAT 8
#define RW_BPF_KIND_CHMOD 9
#define RW_BPF_KIND_FCHMODAT 10
#define RW_BPF_KIND_UNLINK 11
#define RW_BPF_KIND_UNLINKAT 12

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct trace_event_raw_sys_enter
{
    __u64 unused;
    long id;
    unsigned long args[6];
};

struct rw_bpf_event
{
    __u32 event_type;
    __u32 kind;
    __u32 pid;
    __u32 tgid;
    __u16 family;
    __u16 port;
    __u32 sock_type;
    __u32 protocol;
    __u32 ipv4;
    unsigned char ipv6[16];
    __u64 a0;
    __u64 a1;
    __u64 a2;
    __u64 a3;
    char comm[16];
    char str[160];
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void fill_common(struct rw_bpf_event* ev, __u32 event_type, __u32 kind)
{
    __u64 id = bpf_get_current_pid_tgid();
    ev->event_type = event_type;
    ev->kind = kind;
    ev->pid = (__u32)id;
    ev->tgid = (__u32)(id >> 32);
    ev->family = 0;
    ev->port = 0;
    ev->sock_type = 0;
    ev->protocol = 0;
    ev->ipv4 = 0;
    ev->a0 = 0;
    ev->a1 = 0;
    ev->a2 = 0;
    ev->a3 = 0;
    __builtin_memset(ev->ipv6, 0, sizeof(ev->ipv6));
    __builtin_memset(ev->str, 0, sizeof(ev->str));
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
}

static __always_inline struct rw_bpf_event* reserve_syscall_event(__u32 kind)
{
    struct rw_bpf_event* ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);

    if (!ev)
    {
        return 0;
    }

    fill_common(ev, RW_BPF_EVENT_SYSCALL, kind);
    return ev;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int rw_trace_connect(struct trace_event_raw_sys_enter* ctx)
{
    void* uaddr = (void*)ctx->args[1];
    __u16 family = 0;

    if (!uaddr)
    {
        return 0;
    }

    if (bpf_probe_read_user(&family, sizeof(family), uaddr) != 0)
    {
        return 0;
    }

    if (family != AF_INET && family != AF_INET6)
    {
        return 0;
    }

    struct rw_bpf_event* ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
    {
        return 0;
    }

    fill_common(ev, RW_BPF_EVENT_CONNECT, 0);
    ev->family = family;

    if (family == AF_INET)
    {
        struct sockaddr_in sin = {};
        if (bpf_probe_read_user(&sin, sizeof(sin), uaddr) == 0)
        {
            ev->port = bpf_ntohs(sin.sin_port);
            ev->ipv4 = sin.sin_addr.s_addr;
        }
    }
    else
    {
        struct sockaddr_in6 sin6 = {};
        if (bpf_probe_read_user(&sin6, sizeof(sin6), uaddr) == 0)
        {
            ev->port = bpf_ntohs(sin6.sin6_port);
            __builtin_memcpy(ev->ipv6, &sin6.sin6_addr, sizeof(ev->ipv6));
        }
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int rw_trace_socket(struct trace_event_raw_sys_enter* ctx)
{
    __u32 family = (__u32)ctx->args[0];
    __u32 sock_type = (__u32)ctx->args[1];
    __u32 protocol = (__u32)ctx->args[2];
    __u32 base_type = sock_type & SOCK_TYPE_MASK;

    if (base_type != SOCK_RAW && family != AF_PACKET && protocol != IPPROTO_RAW)
    {
        return 0;
    }

    struct rw_bpf_event* ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
    {
        return 0;
    }

    fill_common(ev, RW_BPF_EVENT_SOCKET, 0);
    ev->family = (__u16)family;
    ev->sock_type = sock_type;
    ev->protocol = protocol;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int rw_trace_ptrace(struct trace_event_raw_sys_enter* ctx)
{
    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_PTRACE);
    if (!ev)
    {
        return 0;
    }

    ev->a0 = ctx->args[0];
    ev->a1 = ctx->args[1];
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int rw_trace_process_vm_writev(struct trace_event_raw_sys_enter* ctx)
{
    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_PVM_WRITE);
    if (!ev)
    {
        return 0;
    }

    ev->a0 = ctx->args[0];
    ev->a1 = ctx->args[1];
    ev->a2 = ctx->args[3];
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int rw_trace_process_vm_readv(struct trace_event_raw_sys_enter* ctx)
{
    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_PVM_READ);
    if (!ev)
    {
        return 0;
    }

    ev->a0 = ctx->args[0];
    ev->a1 = ctx->args[1];
    ev->a2 = ctx->args[3];
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int rw_trace_mprotect(struct trace_event_raw_sys_enter* ctx)
{
    __u64 prot = ctx->args[2];
    if ((prot & PROT_EXEC) == 0)
    {
        return 0;
    }

    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_MPROTECT_EXEC);
    if (!ev)
    {
        return 0;
    }

    ev->a0 = ctx->args[0];
    ev->a1 = ctx->args[1];
    ev->a2 = prot;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int rw_trace_mmap(struct trace_event_raw_sys_enter* ctx)
{
    __u64 prot = ctx->args[2];
    if ((prot & PROT_EXEC) == 0)
    {
        return 0;
    }

    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_MMAP_EXEC);
    if (!ev)
    {
        return 0;
    }

    ev->a0 = ctx->args[0];
    ev->a1 = ctx->args[1];
    ev->a2 = prot;
    ev->a3 = ctx->args[3];
    ev->protocol = (__u32)ctx->args[4];
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int rw_trace_memfd_create(struct trace_event_raw_sys_enter* ctx)
{
    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_MEMFD_CREATE);
    if (!ev)
    {
        return 0;
    }

    ev->a0 = ctx->args[1];
    bpf_probe_read_user_str(ev->str, sizeof(ev->str), (void*)ctx->args[0]);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int rw_trace_execve(struct trace_event_raw_sys_enter* ctx)
{
    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_EXECVE);
    if (!ev)
    {
        return 0;
    }

    bpf_probe_read_user_str(ev->str, sizeof(ev->str), (void*)ctx->args[0]);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int rw_trace_execveat(struct trace_event_raw_sys_enter* ctx)
{
    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_EXECVEAT);
    if (!ev)
    {
        return 0;
    }

    ev->a0 = ctx->args[4];
    bpf_probe_read_user_str(ev->str, sizeof(ev->str), (void*)ctx->args[1]);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int rw_trace_chmod(struct trace_event_raw_sys_enter* ctx)
{
    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_CHMOD);
    if (!ev)
    {
        return 0;
    }

    ev->a0 = ctx->args[1];
    bpf_probe_read_user_str(ev->str, sizeof(ev->str), (void*)ctx->args[0]);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int rw_trace_fchmodat(struct trace_event_raw_sys_enter* ctx)
{
    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_FCHMODAT);
    if (!ev)
    {
        return 0;
    }

    ev->a0 = ctx->args[2];
    bpf_probe_read_user_str(ev->str, sizeof(ev->str), (void*)ctx->args[1]);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int rw_trace_unlink(struct trace_event_raw_sys_enter* ctx)
{
    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_UNLINK);
    if (!ev)
    {
        return 0;
    }

    bpf_probe_read_user_str(ev->str, sizeof(ev->str), (void*)ctx->args[0]);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int rw_trace_unlinkat(struct trace_event_raw_sys_enter* ctx)
{
    struct rw_bpf_event* ev = reserve_syscall_event(RW_BPF_KIND_UNLINKAT);
    if (!ev)
    {
        return 0;
    }

    bpf_probe_read_user_str(ev->str, sizeof(ev->str), (void*)ctx->args[1]);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}
