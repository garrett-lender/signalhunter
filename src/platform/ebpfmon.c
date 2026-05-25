#define _GNU_SOURCE
#include "signalhunter.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifdef RW_WITH_EBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

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

struct rw_bpf_event
{
    unsigned int event_type;
    unsigned int kind;
    unsigned int pid;
    unsigned int tgid;
    unsigned short family;
    unsigned short port;
    unsigned int sock_type;
    unsigned int protocol;
    unsigned int ipv4;
    unsigned char ipv6[16];
    unsigned long long a0;
    unsigned long long a1;
    unsigned long long a2;
    unsigned long long a3;
    char comm[16];
    char str[160];
};

static struct bpf_object* g_obj;
static struct bpf_link* g_links[64];
static size_t g_link_count;
static struct ring_buffer* g_rb;
static const rw_config_t* g_runtime_cfg;
static int g_ebpf_loaded;
static unsigned long long g_events_seen;
static unsigned long long g_connect_seen;
static unsigned long long g_socket_seen;
static unsigned long long g_syscall_seen;

#define RW_EBPF_CONNECT_TRACKS 2048

typedef struct
{
    int pid;
    char comm[16];
    char ip[RW_MAX_IP_STR];
    unsigned int port;
    time_t last_seen;
    double intervals[16];
    size_t interval_count;
    size_t total_seen;
    int already_alerted;
} rw_ebpf_connect_track_t;

static rw_ebpf_connect_track_t g_connect_tracks[RW_EBPF_CONNECT_TRACKS];
static size_t g_connect_track_count;

static rw_ebpf_connect_track_t* get_or_create_connect_track(int pid, const char* comm,
                                                            const char* ip, unsigned int port)
{
    for (size_t i = 0; i < g_connect_track_count; i++)
    {
        rw_ebpf_connect_track_t* t = &g_connect_tracks[i];
        if (t->pid == pid && t->port == port && strcmp(t->ip, ip) == 0)
        {
            return t;
        }
    }

    if (g_connect_track_count >= RW_EBPF_CONNECT_TRACKS)
    {
        return NULL;
    }

    rw_ebpf_connect_track_t* t = &g_connect_tracks[g_connect_track_count++];
    memset(t, 0, sizeof(*t));
    t->pid = pid;
    t->port = port;
    t->last_seen = time(NULL);
    snprintf(t->comm, sizeof(t->comm), "%s", comm ? comm : "<unknown>");
    snprintf(t->ip, sizeof(t->ip), "%s", ip ? ip : "<unknown>");
    return t;
}

static double ebpf_avg_interval(const rw_ebpf_connect_track_t* t)
{
    if (!t || t->interval_count == 0)
    {
        return 0.0;
    }
    
    double sum = 0.0;
    for (size_t i = 0; i < t->interval_count; i++)
    {
        sum += t->intervals[i];
    }
    
    return sum / (double)t->interval_count;
}

static double ebpf_interval_jitter(const rw_ebpf_connect_track_t* t)
{
    if (!t || t->interval_count < 2)
    {
        return 999999.0;
    }
    
    double avg = ebpf_avg_interval(t);
    double sum = 0.0;
    for (size_t i = 0; i < t->interval_count; i++)
    {
        double d = t->intervals[i] - avg;
        if (d < 0)
        {
            d = -d;
        }
        
        sum += d;
    }

    return sum / (double)t->interval_count;
}

static int ebpf_score_connect_track(const rw_ebpf_connect_track_t* t)
{
    int score = 0;
    if (!t)
    {
        return 0;
    }

    if (t->total_seen >= 4)
    {
        score += 25;
    }

    if (t->interval_count >= 3)
    {
        double avg = ebpf_avg_interval(t);
        double jitter = ebpf_interval_jitter(t);
        if (avg >= 1.0 && avg <= 600.0 && jitter <= avg * 0.30)
        {
            score += 60;
        }
    }

    if (t->port == 80 || t->port == 443 || t->port == 8080 || t->port == 8443)
    {
        score += 5;
    }

    if (score > 100)
    {
        score = 100;
    }

    return score;
}

static void update_ebpf_connect_track(int pid, const char* comm, const char* ip, unsigned int port,
                                      const rw_config_t* cfg)
{
    rw_ebpf_connect_track_t* t = get_or_create_connect_track(pid, comm, ip, port);
    if (!t)
    {
        return;
    }

    time_t now = time(NULL);
    if (now > t->last_seen)
    {
        double interval = difftime(now, t->last_seen);
        if (interval >= 1.0)
        {
            if (t->interval_count < 16)
            {
                t->intervals[t->interval_count++] = interval;
            }
            else
            {
                memmove(&t->intervals[0], &t->intervals[1], sizeof(double) * 15);
            }

            t->intervals[15] = interval;
        }
        t->last_seen = now;
    }

    t->total_seen++;

    int score = ebpf_score_connect_track(t);
    if (score > 0)
    {
        char reason[256];
        snprintf(reason, sizeof(reason), "dst=%s:%u seen=%zu avg=%.2f jitter=%.2f", t->ip, t->port,
                 t->total_seen, ebpf_avg_interval(t), ebpf_interval_jitter(t));
        rw_score_add(t->pid, t->comm, NULL, cfg, "EBPF_CONNECT", reason, score);
    }

    int alert_threshold = cfg && cfg->case_threshold > 0 ? cfg->case_threshold : 85;
    if (score >= alert_threshold && !t->already_alerted)
    {
        t->already_alerted = 1;
        rw_log_alert(
            "eBPF possible beacon pid=%d comm=%s dst=%s:%u seen=%zu avg=%.2f jitter=%.2f score=%d",
            t->pid, t->comm, t->ip, t->port, t->total_seen, ebpf_avg_interval(t),
            ebpf_interval_jitter(t), score);

        if (rw_case_has(t->pid))
        {
            rw_case_event(t->pid, score, cfg, "EBPF_BEACON_DETAIL",
                          "comm=%s dst=%s:%u seen=%zu avg=%.2f jitter=%.2f", t->comm, t->ip,
                          t->port, t->total_seen, ebpf_avg_interval(t), ebpf_interval_jitter(t));
        }
        
        printf("\n[ALERT] eBPF possible beaconing behavior\n");
        printf("  PID:         %d\n", t->pid);
        printf("  COMM:        %s\n", t->comm);
        printf("  Destination: %s:%u\n", t->ip, t->port);
        printf("  Seen:        %zu connects\n", t->total_seen);
        printf("  Avg Int:     %.2fs\n", ebpf_avg_interval(t));
        printf("  Jitter:      %.2fs\n", ebpf_interval_jitter(t));
        printf("  Score:       %d/100\n", score);
    }
}

static const char* family_name(unsigned int family)
{
    switch (family)
    {
        case AF_INET:
            return "AF_INET";
        case AF_INET6:
            return "AF_INET6";
        case AF_PACKET:
            return "AF_PACKET";
        case AF_NETLINK:
            return "AF_NETLINK";
        default:
            return "AF_OTHER";
    }
}

static const char* syscall_kind_name(unsigned int kind)
{
    switch (kind)
    {
        case RW_BPF_KIND_PTRACE:
            return "ptrace";
        case RW_BPF_KIND_PVM_WRITE:
            return "process_vm_writev";
        case RW_BPF_KIND_PVM_READ:
            return "process_vm_readv";
        case RW_BPF_KIND_MPROTECT_EXEC:
            return "mprotect(PROT_EXEC)";
        case RW_BPF_KIND_MMAP_EXEC:
            return "mmap(PROT_EXEC)";
        case RW_BPF_KIND_MEMFD_CREATE:
            return "memfd_create";
        case RW_BPF_KIND_EXECVE:
            return "execve";
        case RW_BPF_KIND_EXECVEAT:
            return "execveat";
        case RW_BPF_KIND_CHMOD:
            return "chmod";
        case RW_BPF_KIND_FCHMODAT:
            return "fchmodat";
        case RW_BPF_KIND_UNLINK:
            return "unlink";
        case RW_BPF_KIND_UNLINKAT:
            return "unlinkat";
        default:
            return "unknown";
    }
}

static int bpf_path_is_suspicious(const char* path)
{
    return rw_suspicious_path(path) || strstr(path, "/etc/cron") ||
           strstr(path, "/var/spool/cron") || strstr(path, "/.ssh/") || strstr(path, "/systemd/");
}

static void handle_socket_event(const struct rw_bpf_event* ev, const rw_config_t* cfg)
{
    rw_log_alert(
        "eBPF raw/packet socket syscall pid=%u tgid=%u comm=%s family=%s(%u) type=%u protocol=%u",
        ev->pid, ev->tgid, ev->comm, family_name(ev->family), ev->family, ev->sock_type,
        ev->protocol);
    rw_score_add((int)ev->tgid, ev->comm, NULL, cfg, "EBPF_RAW_SOCKET", family_name(ev->family),
                 95);
    if (!cfg || cfg->log_raw)
    {
        rw_log_network("ebpf_socket pid=%u tgid=%u comm=%s family=%s(%u) type=%u protocol=%u",
                       ev->pid, ev->tgid, ev->comm, family_name(ev->family), ev->family,
                       ev->sock_type, ev->protocol);
    }
    printf("\n[ALERT] eBPF raw/packet socket syscall\n");
    printf("  PID:      %u\n", ev->tgid);
    printf("  TID:      %u\n", ev->pid);
    printf("  COMM:     %s\n", ev->comm);
    printf("  Family:   %s (%u)\n", family_name(ev->family), ev->family);
    printf("  Type:     %u\n", ev->sock_type);
    printf("  Protocol: %u\n", ev->protocol);

    if (rw_case_has((int)ev->tgid))
    {
        rw_case_event((int)ev->tgid, 95, cfg, "EBPF_RAW_SOCKET_DETAIL",
                      "comm=%s family=%s(%u) type=%u protocol=%u", ev->comm,
                      family_name(ev->family), ev->family, ev->sock_type, ev->protocol);
    }  
}

static void handle_connect_event(const struct rw_bpf_event* ev, const rw_config_t* cfg)
{
    char ip[RW_MAX_IP_STR] = {0};
    if (ev->family == AF_INET)
    {
        struct in_addr a;
        a.s_addr = ev->ipv4;
        inet_ntop(AF_INET, &a, ip, sizeof(ip));
    }
    else if (ev->family == AF_INET6)
    {
        inet_ntop(AF_INET6, ev->ipv6, ip, sizeof(ip));
    }
    else
    {
        snprintf(ip, sizeof(ip), "family-%u", ev->family);
    }

    if (cfg && cfg->log_network)
        rw_log_network("ebpf_connect pid=%u tgid=%u comm=%s dst=%s:%u", ev->pid, ev->tgid, ev->comm,
                       ip, ev->port);
    {
        if (cfg && cfg->verbose)
        {
            printf("\n[eBPF] connect pid=%u tgid=%u comm=%s dst=%s:%u\n", ev->pid, ev->tgid,
                   ev->comm, ip, ev->port);
        }
    }

    update_ebpf_connect_track((int)ev->tgid, ev->comm, ip, ev->port, cfg);
}

static void handle_syscall_event(const struct rw_bpf_event* ev, const rw_config_t* cfg)
{
    char detail[512];
    const char* kind = syscall_kind_name(ev->kind);
    int alert = 1;

    switch (ev->kind)
    {
        case RW_BPF_KIND_PTRACE:
            snprintf(detail, sizeof(detail), "request=%llu target_pid=%llu", ev->a0, ev->a1);
            break;
        case RW_BPF_KIND_PVM_WRITE:
        case RW_BPF_KIND_PVM_READ:
            snprintf(detail, sizeof(detail), "target_pid=%llu local_iov=%llu remote_iov=%llu",
                     ev->a0, ev->a1, ev->a2);
            break;
        case RW_BPF_KIND_MPROTECT_EXEC:
            snprintf(detail, sizeof(detail), "addr=0x%llx len=%llu prot=0x%llx", ev->a0, ev->a1,
                     ev->a2);
            break;
        case RW_BPF_KIND_MMAP_EXEC:
            snprintf(detail, sizeof(detail),
                     "addr=0x%llx len=%llu prot=0x%llx flags=0x%llx fd=%lld", ev->a0, ev->a1,
                     ev->a2, ev->a3, (long long)ev->protocol);
            break;
        case RW_BPF_KIND_MEMFD_CREATE:
            snprintf(detail, sizeof(detail), "name=%s flags=0x%llx",
                     ev->str[0] ? ev->str : "<unknown>", ev->a0);
            break;
        case RW_BPF_KIND_EXECVE:
        case RW_BPF_KIND_EXECVEAT:
            snprintf(detail, sizeof(detail), "path=%s flags=0x%llx",
                     ev->str[0] ? ev->str : "<unknown>", ev->a0);
            alert = bpf_path_is_suspicious(ev->str);
            if (!alert && cfg && cfg->verbose && cfg->log_syscalls)
            {
                rw_log_event("exec pid=%u comm=%s path=%s", ev->tgid, ev->comm, ev->str);
            }

            break;
        case RW_BPF_KIND_CHMOD:
        case RW_BPF_KIND_FCHMODAT:
            snprintf(detail, sizeof(detail), "path=%s mode=0%llo",
                     ev->str[0] ? ev->str : "<unknown>", ev->a0);
            alert = bpf_path_is_suspicious(ev->str) ||
                    ((ev->a0 & 0111) != 0 && rw_suspicious_path(ev->str));
            break;
        case RW_BPF_KIND_UNLINK:
        case RW_BPF_KIND_UNLINKAT:
            snprintf(detail, sizeof(detail), "path=%s", ev->str[0] ? ev->str : "<unknown>");
            alert = bpf_path_is_suspicious(ev->str);
            break;
        default:
            snprintf(detail, sizeof(detail), "a0=%llu a1=%llu a2=%llu", ev->a0, ev->a1, ev->a2);
            break;
    }

    if (alert)
    {
        rw_syscall_alert((int)ev->tgid, ev->comm, kind, detail, cfg);
    }
}

static int handle_bpf_event(void* ctx, void* data, size_t len)
{
    const rw_config_t* cfg = ctx ? (const rw_config_t*)ctx : g_runtime_cfg;
    if (len < sizeof(struct rw_bpf_event))
    {
        return 0;
    }
    
    const struct rw_bpf_event* ev = data;
    g_events_seen++;
    if (ev->event_type == RW_BPF_EVENT_SOCKET)
    {
        g_socket_seen++;
        handle_socket_event(ev, cfg);
    }
    else if (ev->event_type == RW_BPF_EVENT_CONNECT)
    {
        g_connect_seen++;
        handle_connect_event(ev, cfg);
    }
    else if (ev->event_type == RW_BPF_EVENT_SYSCALL)
    {
        g_syscall_seen++;
        handle_syscall_event(ev, cfg);
    }

    return 0;
}

int rw_ebpf_init_backend(void)
{
    struct bpf_object_open_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);

    g_events_seen = 0;
    g_connect_seen = 0;
    g_socket_seen = 0;
    g_syscall_seen = 0;
    g_ebpf_loaded = 0;

    g_obj = bpf_object__open_file("signalhunter_ebpf.bpf.o", &opts);
    long err = libbpf_get_error(g_obj);
    if (err)
    {
        g_obj = NULL;
        errno = err < 0 ? (int)-err : (int)err;
        return -1;
    }

    if (!g_obj)
    {
        errno = ENOENT;
        return -1;
    }

    if (bpf_object__load(g_obj) != 0)
    {
        int saved = errno ? errno : EINVAL;
        bpf_object__close(g_obj);
        g_obj = NULL;
        errno = saved;
        return -1;
    }

    struct bpf_program* prog;
    bpf_object__for_each_program(prog, g_obj)
    {
        if (g_link_count >= sizeof(g_links) / sizeof(g_links[0]))
        {
            break;
        }
        
        struct bpf_link* link = bpf_program__attach(prog);
        err = libbpf_get_error(link);
        if (err)
        {
            rw_log_info("eBPF attach failed for program %s: %ld; continuing",
                        bpf_program__name(prog), err);
            continue;
        }

        if (link)
        {
            g_links[g_link_count++] = link;
        }
    }

    if (g_link_count == 0)
    {
        rw_ebpf_shutdown();
        errno = ENOENT;
        return -1;
    }

    struct bpf_map* map = bpf_object__find_map_by_name(g_obj, "events");
    if (!map)
    {
        rw_ebpf_shutdown();
        errno = ENOENT;
        return -1;
    }

    g_rb = ring_buffer__new(bpf_map__fd(map), handle_bpf_event, NULL, NULL);
    err = libbpf_get_error(g_rb);
    if (err)
    {
        g_rb = NULL;
        rw_ebpf_shutdown();
        errno = err < 0 ? (int)-err : (int)err;
        return -1;
    }
    if (!g_rb)
    {
        rw_ebpf_shutdown();
        return -1;
    }

    g_ebpf_loaded = 1;
    rw_log_info("eBPF attached programs=%zu", g_link_count);
    return 0;
}

void rw_ebpf_print_status(void)
{
    if (!g_ebpf_loaded)
    {
        printf("[ebpf] status: disabled or unavailable\n");
        return;
    }

    printf("[ebpf] status: loaded links=%zu events=%llu connect=%llu socket=%llu syscall=%llu\n",
           g_link_count, g_events_seen, g_connect_seen, g_socket_seen, g_syscall_seen);
}

void rw_ebpf_selftest_hint(void)
{
    printf("eBPF self-test commands you can run in another terminal:\n");
    printf("  curl -s https://example.com >/dev/null        # should increment connect events\n");
    printf("  python3 - <<'PY'\nimport socket\ntry:\n s=socket.socket(socket.AF_INET, "
           "socket.SOCK_RAW, socket.IPPROTO_RAW)\n print('raw socket opened')\nexcept "
           "PermissionError as e:\n print('permission denied, try sudo')\nPY\n");
    printf("  sudo python3 - <<'PY'\nimport mmap\nm=mmap.mmap(-1, 4096, "
           "prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)\nprint('RWX mmap created')\nPY\n");
}

void rw_ebpf_poll(int fd, const rw_config_t* cfg)
{
    (void)fd;
    g_runtime_cfg = cfg;

    if (g_rb)
    {
        int rc = ring_buffer__poll(g_rb, 0);
        if (rc < 0 && rc != -EINTR)
        {
            fprintf(stderr, "[warn] eBPF ring poll failed: %d\n", rc);
        }
    }
}

void rw_ebpf_shutdown(void)
{
    g_ebpf_loaded = 0;
    if (g_rb)
    {
        ring_buffer__free(g_rb);
        g_rb = NULL;
    }

    for (size_t i = 0; i < g_link_count; i++)
    {
        if (g_links[i])
        {
            bpf_link__destroy(g_links[i]);
        }

        g_links[i] = NULL;
    }

    g_link_count = 0;
    if (g_obj)
    {
        bpf_object__close(g_obj);
        g_obj = NULL;
    }
}

#else
int rw_ebpf_init_backend(void)
{
    errno = ENOSYS;
    return -1;
}

void rw_ebpf_poll(int fd, const rw_config_t* cfg)
{
    (void)fd;
    (void)cfg;
}

void rw_ebpf_shutdown(void)
{
}

void rw_ebpf_print_status(void)
{
    printf("[ebpf] status: not compiled in; rebuild with make ebpf\n");
}

void rw_ebpf_selftest_hint(void)
{
    printf("eBPF is not compiled in; rebuild with make ebpf first.\n");
}
#endif
