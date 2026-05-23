#define _GNU_SOURCE
#include "signalhunter.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TCP_ESTABLISHED 0x01
#define TCP_SYN_SENT 0x02

#define RW_RAW_ALERT_CACHE 1024
#define RW_SYN_TRACKS 1024

typedef struct
{
    int pid;
    unsigned long inode;
} rw_raw_alert_key_t;

typedef struct
{
    int pid;
    char exe[RW_MAX_PATH];
    time_t window_start;
    size_t syn_count;
    size_t unique_count;
    char keys[64][160];
    int already_alerted;
} rw_syn_track_t;

static rw_conn_track_t g_tracks[RW_MAX_TRACKS];
static size_t g_track_count = 0;
static rw_raw_alert_key_t g_raw_alerts[RW_RAW_ALERT_CACHE];
static size_t g_raw_alert_count = 0;
static rw_syn_track_t g_syn_tracks[RW_SYN_TRACKS];
static size_t g_syn_track_count = 0;

size_t rw_collect_inode_owners(rw_inode_owner_t* owners, size_t max_owners)
{
    DIR* proc = opendir("/proc");
    if (!proc)
    {
        return 0;
    }

    size_t count = 0;
    struct dirent* de;
    while ((de = readdir(proc)) != NULL && count < max_owners)
    {
        if (!rw_is_numeric(de->d_name))
        {
            continue;
        }
        int pid = atoi(de->d_name);

        char fd_dir[128];
        snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
        DIR* fds = opendir(fd_dir);
        if (!fds)
        {
            continue;
        }

        char exe[RW_MAX_PATH];
        rw_read_exe_path(pid, exe, sizeof(exe));

        struct dirent* fd_de;
        while ((fd_de = readdir(fds)) != NULL && count < max_owners)
        {
            if (fd_de->d_name[0] == '.')
            {
                continue;
            }
            char fd_path[RW_MAX_PATH];
            char link_target[256];
            int npath = snprintf(fd_path, sizeof(fd_path), "%s/%s", fd_dir, fd_de->d_name);
            if (npath < 0 || (size_t)npath >= sizeof(fd_path))
            {
                continue;
            }
            ssize_t n = readlink(fd_path, link_target, sizeof(link_target) - 1);
            if (n < 0)
            {
                continue;
            }
            link_target[n] = '\0';

            unsigned long inode = 0;
            if (sscanf(link_target, "socket:[%lu]", &inode) == 1)
            {
                owners[count].pid = pid;
                owners[count].inode = inode;
                snprintf(owners[count].exe, sizeof(owners[count].exe), "%s", exe);
                count++;
            }
        }
        closedir(fds);
    }
    closedir(proc);
    return count;
}

static int find_owner_by_inode(const rw_inode_owner_t* owners, size_t owner_count,
                               unsigned long inode, rw_inode_owner_t* out)
{
    for (size_t i = 0; i < owner_count; i++)
    {
        if (owners[i].inode == inode)
        {
            *out = owners[i];
            return 1;
        }
    }
    return 0;
}

static int hex_byte(const char* s, unsigned char* out)
{
    unsigned int v = 0;
    if (sscanf(s, "%2x", &v) != 1)
    {
        return -1;
    }
    *out = (unsigned char)v;
    return 0;
}

static int proc_tcp4_hex_to_str(const char* hex, char* out, size_t out_len)
{
    if (!hex || strlen(hex) < 8)
    {
        return -1;
    }
    unsigned char b[4];
    if (hex_byte(hex + 6, &b[0]) || hex_byte(hex + 4, &b[1]) || hex_byte(hex + 2, &b[2]) ||
        hex_byte(hex + 0, &b[3]))
        return -1;
    return inet_ntop(AF_INET, b, out, out_len) ? 0 : -1;
}

static int proc_tcp6_hex_to_str(const char* hex, char* out, size_t out_len)
{
    if (!hex || strlen(hex) < 32)
    {
        return -1;
    }
    unsigned char b[16];
    for (int word = 0; word < 4; word++)
    {
        const char* p = hex + (word * 8);
        if (hex_byte(p + 6, &b[word * 4 + 0]) || hex_byte(p + 4, &b[word * 4 + 1]) ||
            hex_byte(p + 2, &b[word * 4 + 2]) || hex_byte(p + 0, &b[word * 4 + 3]))
            return -1;
    }
    return inet_ntop(AF_INET6, b, out, out_len) ? 0 : -1;
}

static int is_browser_exe(const char* exe)
{
    if (!exe)
    {
        return 0;
    }
    return strstr(exe, "/firefox") || strstr(exe, "/chrome") || strstr(exe, "/chromium") ||
           strstr(exe, "/brave") || strstr(exe, "/msedge") || strstr(exe, "/opera") ||
           strstr(exe, "/lib/firefox/") || strstr(exe, "/snap/firefox/");
}

static int is_stable_browser_port(unsigned int port)
{
    return port == 80 || port == 443 || port == 8443 || port == 8080;
}

static size_t collect_tcp_file(const char* path, int family, const rw_inode_owner_t* owners,
                               size_t owner_count, rw_conn_event_t* events, size_t max_events)
{
    FILE* fp = fopen(path, "r");
    if (!fp)
    {
        return 0;
    }

    char line[1024];
    if (!fgets(line, sizeof(line), fp))
    {
        fclose(fp);
        return 0;
    }

    size_t count = 0;
    while (fgets(line, sizeof(line), fp) && count < max_events)
    {
        char local_addr[80] = {0};
        char remote_addr[80] = {0};
        unsigned int local_port = 0;
        unsigned int remote_port = 0;
        unsigned int state = 0;
        unsigned long inode = 0;

        int matched =
            sscanf(line, " %*d: %79[0-9A-Fa-f]:%X %79[0-9A-Fa-f]:%X %X %*s %*s %*s %*s %*s %lu",
                   local_addr, &local_port, remote_addr, &remote_port, &state, &inode);

        if (matched != 6)
        {
            continue;
        }
        if (state != TCP_ESTABLISHED && state != TCP_SYN_SENT)
        {
            continue;
        }

        rw_inode_owner_t owner;
        if (!find_owner_by_inode(owners, owner_count, inode, &owner))
        {
            continue;
        }

        char dst_ip[RW_MAX_IP_STR];
        int rc = (family == AF_INET) ? proc_tcp4_hex_to_str(remote_addr, dst_ip, sizeof(dst_ip))
                                     : proc_tcp6_hex_to_str(remote_addr, dst_ip, sizeof(dst_ip));
        if (rc != 0)
        {
            continue;
        }

        if (strcmp(dst_ip, "0.0.0.0") == 0 || strcmp(dst_ip, "::") == 0)
        {
            continue;
        }

        events[count].pid = owner.pid;
        events[count].inode = inode;
        events[count].dst_port = remote_port;
        events[count].state = state;
        events[count].family = family;
        events[count].seen_at = time(NULL);
        snprintf(events[count].dst_ip, sizeof(events[count].dst_ip), "%s", dst_ip);
        snprintf(events[count].exe, sizeof(events[count].exe), "%s", owner.exe);
        count++;
    }

    fclose(fp);
    return count;
}

size_t rw_collect_tcp_events(const rw_inode_owner_t* owners, size_t owner_count,
                             rw_conn_event_t* events, size_t max_events)
{
    size_t count = 0;
    count += collect_tcp_file("/proc/net/tcp", AF_INET, owners, owner_count, events + count,
                              max_events - count);
    if (count < max_events)
    {
        count += collect_tcp_file("/proc/net/tcp6", AF_INET6, owners, owner_count, events + count,
                                  max_events - count);
    }
    return count;
}

static int raw_alert_seen(int pid, unsigned long inode)
{
    for (size_t i = 0; i < g_raw_alert_count; i++)
    {
        if (g_raw_alerts[i].pid == pid && g_raw_alerts[i].inode == inode)
        {
            return 1;
        }
    }
    if (g_raw_alert_count < RW_RAW_ALERT_CACHE)
    {
        g_raw_alerts[g_raw_alert_count].pid = pid;
        g_raw_alerts[g_raw_alert_count].inode = inode;
        g_raw_alert_count++;
    }
    return 0;
}

static void scan_raw_file(const char* path, const char* kind, const rw_inode_owner_t* owners,
                          size_t owner_count, const rw_config_t* cfg)
{
    FILE* fp = fopen(path, "r");
    if (!fp)
    {
        return;
    }
    char line[1024];
    if (!fgets(line, sizeof(line), fp))
    {
        fclose(fp);
        return;
    }

    while (fgets(line, sizeof(line), fp))
    {
        unsigned long inode = 0;
        /* inode is the final field for /proc/net/raw and /proc/net/raw6 on normal Linux. */
        char* last = strrchr(line, ' ');
        while (last && *last == ' ')
        {
            last--;
        }
        if (sscanf(line, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu", &inode) != 1)
        {
            /* More robust fallback: walk tokens and keep the last numeric token. */
            char tmp[1024];
            snprintf(tmp, sizeof(tmp), "%s", line);
            char* save = NULL;
            char* tok = strtok_r(tmp, " \t\n", &save);
            while (tok)
            {
                char* end = NULL;
                unsigned long v = strtoul(tok, &end, 10);
                if (end && *end == '\0')
                {
                    inode = v;
                }
                tok = strtok_r(NULL, " \t\n", &save);
            }
        }
        if (inode == 0)
        {
            continue;
        }

        rw_inode_owner_t owner;
        if (!find_owner_by_inode(owners, owner_count, inode, &owner))
        {
            continue;
        }
        if (raw_alert_seen(owner.pid, inode))
        {
            continue;
        }

        rw_log_alert("raw socket detected kind=%s pid=%d exe=%s inode=%lu", kind, owner.pid,
                     owner.exe, inode);
        rw_score_add(owner.pid, NULL, owner.exe, cfg, "RAW_SOCKET", kind, 95);
        if (rw_case_has(owner.pid))
            rw_case_event(owner.pid, 95, cfg, "RAW_SOCKET_DETAIL", "kind=%s exe=%s inode=%lu", kind,
                          owner.exe, inode);
        if (!cfg || cfg->log_raw)
            rw_log_network("raw_socket kind=%s pid=%d exe=%s inode=%lu", kind, owner.pid, owner.exe,
                           inode);
        printf("\n[ALERT] Raw socket detected\n");
        printf("  Kind:  %s\n", kind);
        printf("  PID:   %d\n", owner.pid);
        printf("  EXE:   %s\n", owner.exe);
        printf("  Inode: %lu\n", inode);
        if (cfg && cfg->stop_suspicious)
        {
            rw_log_alert("stopping raw-socket pid=%d via SIGSTOP", owner.pid);
            int rc = kill(owner.pid, SIGSTOP);
            rw_case_action(owner.pid, cfg, "SIGSTOP", rc == 0 ? 0 : errno, "raw/packet socket");
            if (rc != 0)
            {
                rw_log_alert("SIGSTOP failed pid=%d errno=%d", owner.pid, errno);
            }
        }
    }
    fclose(fp);
}

static void scan_packet_file(const rw_inode_owner_t* owners, size_t owner_count,
                             const rw_config_t* cfg)
{
    FILE* fp = fopen("/proc/net/packet", "r");
    if (!fp)
    {
        return;
    }
    char line[1024];
    if (!fgets(line, sizeof(line), fp))
    {
        fclose(fp);
        return;
    }

    while (fgets(line, sizeof(line), fp))
    {
        unsigned long inode = 0;
        char tmp[1024];
        snprintf(tmp, sizeof(tmp), "%s", line);
        char* save = NULL;
        char* tok = strtok_r(tmp, " \t\n", &save);
        while (tok)
        {
            char* end = NULL;
            unsigned long v = strtoul(tok, &end, 10);
            if (end && *end == '\0')
            {
                inode = v;
            }
            tok = strtok_r(NULL, " \t\n", &save);
        }
        if (inode == 0)
        {
            continue;
        }
        rw_inode_owner_t owner;
        if (!find_owner_by_inode(owners, owner_count, inode, &owner))
        {
            continue;
        }
        if (raw_alert_seen(owner.pid, inode))
        {
            continue;
        }
        rw_log_alert("packet socket detected pid=%d exe=%s inode=%lu", owner.pid, owner.exe, inode);
        rw_score_add(owner.pid, NULL, owner.exe, cfg, "PACKET_SOCKET", "packet/raw capture socket",
                     95);
        if (rw_case_has(owner.pid))
            rw_case_event(owner.pid, 95, cfg, "PACKET_SOCKET_DETAIL", "exe=%s inode=%lu", owner.exe,
                          inode);
        if (!cfg || cfg->log_raw)
        {
            rw_log_network("packet_socket pid=%d exe=%s inode=%lu", owner.pid, owner.exe, inode);
        }
        printf("\n[ALERT] Packet/raw capture socket detected\n");
        printf("  PID:   %d\n", owner.pid);
        printf("  EXE:   %s\n", owner.exe);
        printf("  Inode: %lu\n", inode);
        if (cfg && cfg->stop_suspicious)
        {
            rw_log_alert("stopping packet-socket pid=%d via SIGSTOP", owner.pid);
            int rc = kill(owner.pid, SIGSTOP);
            rw_case_action(owner.pid, cfg, "SIGSTOP", rc == 0 ? 0 : errno, "raw/packet socket");
            if (rc != 0)
            {
                rw_log_alert("SIGSTOP failed pid=%d errno=%d", owner.pid, errno);
            }
        }
    }
    fclose(fp);
}

void rw_scan_raw_sockets(const rw_inode_owner_t* owners, size_t owner_count, const rw_config_t* cfg)
{
    scan_raw_file("/proc/net/raw", "raw4", owners, owner_count, cfg);
    scan_raw_file("/proc/net/raw6", "raw6", owners, owner_count, cfg);
    scan_packet_file(owners, owner_count, cfg);
}

static rw_conn_track_t* get_or_create_track(const rw_conn_event_t* ev)
{
    for (size_t i = 0; i < g_track_count; i++)
    {
        rw_conn_track_t* t = &g_tracks[i];
        if (t->pid == ev->pid && t->dst_port == ev->dst_port && strcmp(t->dst_ip, ev->dst_ip) == 0)
        {
            return t;
        }
    }
    if (g_track_count >= RW_MAX_TRACKS)
    {
        return NULL;
    }

    rw_conn_track_t* t = &g_tracks[g_track_count++];
    memset(t, 0, sizeof(*t));
    t->pid = ev->pid;
    t->dst_port = ev->dst_port;
    t->last_seen = ev->seen_at;
    snprintf(t->exe, sizeof(t->exe), "%s", ev->exe);
    snprintf(t->dst_ip, sizeof(t->dst_ip), "%s", ev->dst_ip);
    return t;
}

static rw_syn_track_t* get_or_create_syn_track(int pid, const char* exe, time_t now)
{
    for (size_t i = 0; i < g_syn_track_count; i++)
    {
        if (g_syn_tracks[i].pid == pid)
        {
            return &g_syn_tracks[i];
        }
    }
    if (g_syn_track_count >= RW_SYN_TRACKS)
    {
        return NULL;
    }
    rw_syn_track_t* t = &g_syn_tracks[g_syn_track_count++];
    memset(t, 0, sizeof(*t));
    t->pid = pid;
    t->window_start = now;
    snprintf(t->exe, sizeof(t->exe), "%s", exe ? exe : "<unknown>");
    return t;
}

static void update_syn_scan_track(const rw_conn_event_t* ev, const rw_config_t* cfg)
{
    time_t now = ev->seen_at;
    rw_syn_track_t* t = get_or_create_syn_track(ev->pid, ev->exe, now);
    if (!t)
    {
        return;
    }

    if (now - t->window_start > 30)
    {
        t->window_start = now;
        t->syn_count = 0;
        t->unique_count = 0;
        t->already_alerted = 0;
        memset(t->keys, 0, sizeof(t->keys));
    }

    t->syn_count++;
    char key[160];
    snprintf(key, sizeof(key), "%s:%u", ev->dst_ip, ev->dst_port);
    int known = 0;
    for (size_t i = 0; i < t->unique_count; i++)
    {
        if (strcmp(t->keys[i], key) == 0)
        {
            known = 1;
            break;
        }
    }
    if (!known && t->unique_count < 64)
    {
        snprintf(t->keys[t->unique_count], sizeof(t->keys[t->unique_count]), "%s", key);
        t->unique_count++;
    }

    int threshold_unique = is_browser_exe(t->exe) ? 48 : 20;
    int threshold_syn = is_browser_exe(t->exe) ? 80 : 30;
    if (!t->already_alerted && t->unique_count >= (size_t)threshold_unique &&
        t->syn_count >= (size_t)threshold_syn)
    {
        t->already_alerted = 1;
        rw_log_alert("possible synscan pid=%d exe=%s syn_sent=%zu unique_targets=%zu window=30s",
                     t->pid, t->exe, t->syn_count, t->unique_count);
        rw_score_add(t->pid, NULL, t->exe, cfg, "SYNSCAN",
                     "many SYN_SENT connections to unique targets", 90);
        if (rw_case_has(t->pid))
            rw_case_event(t->pid, 90, cfg, "SYNSCAN_DETAIL",
                          "exe=%s syn_sent=%zu unique_targets=%zu window=30s", t->exe, t->syn_count,
                          t->unique_count);
        printf("\n[ALERT] Possible SYN-scan behavior\n");
        printf("  PID:            %d\n", t->pid);
        printf("  EXE:            %s\n", t->exe);
        printf("  SYN_SENT seen:  %zu\n", t->syn_count);
        printf("  Unique targets: %zu\n", t->unique_count);
        printf("  Window:         30s\n");
        rw_scan_injection_pid(t->pid, 1, cfg);
        if (cfg && cfg->stop_suspicious)
        {
            rw_log_alert("stopping synscan pid=%d via SIGSTOP", t->pid);
            int rc = kill(t->pid, SIGSTOP);
            rw_case_action(t->pid, cfg, "SIGSTOP", rc == 0 ? 0 : errno, "synscan");
            if (rc != 0)
            {
                rw_log_alert("SIGSTOP failed pid=%d errno=%d", t->pid, errno);
            }
        }
    }
}

static double avg_interval(const rw_conn_track_t* t)
{
    if (t->interval_count == 0)
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

static double interval_jitter(const rw_conn_track_t* t)
{
    if (t->interval_count < 2)
    {
        return 999999.0;
    }
    double avg = avg_interval(t);
    double sum = 0.0;
    for (size_t i = 0; i < t->interval_count; i++)
    {
        double diff = t->intervals[i] - avg;
        if (diff < 0)
        {
            diff = -diff;
        }
        sum += diff;
    }
    return sum / (double)t->interval_count;
}

static int score_track(const rw_conn_track_t* t)
{
    int score = 0;
    int browser = is_browser_exe(t->exe);

    if (t->total_seen >= 4)
    {
        score += browser ? 5 : 25;
    }

    if (t->interval_count >= 3)
    {
        double avg = avg_interval(t);
        double jitter = interval_jitter(t);
        if (avg >= 2.0 && avg <= 600.0 && jitter <= avg * 0.30)
        {
            score += browser ? 10 : 60;
        }
    }

    if (is_stable_browser_port(t->dst_port))
    {
        score += browser ? 0 : 5;
    }
    if (rw_suspicious_path(t->exe))
    {
        score += 30;
    }

    /* Browsers make lots of repeated HTTPS connections. Do not beacon-alert on
     * browser traffic unless there is another strong signal, such as suspicious
     * executable path. */
    if (browser && !rw_suspicious_path(t->exe) && score < 85)
    {
        return 0;
    }

    return score > 100 ? 100 : score;
}

void rw_update_track(const rw_conn_event_t* ev, const rw_config_t* cfg)
{
    if (ev->state == TCP_SYN_SENT)
    {
        if (cfg && cfg->log_synscan)
            rw_log_network("syn_sent pid=%d exe=%s dst=%s:%u", ev->pid, ev->exe, ev->dst_ip,
                           ev->dst_port);
        update_syn_scan_track(ev, cfg);
        return;
    }

    rw_conn_track_t* t = get_or_create_track(ev);
    if (!t)
    {
        return;
    }

    if (ev->seen_at > t->last_seen)
    {
        double interval = difftime(ev->seen_at, t->last_seen);
        if (interval >= 1.0)
        {
            if (t->interval_count < 16)
            {
                t->intervals[t->interval_count++] = interval;
            }
            else
            {
                memmove(&t->intervals[0], &t->intervals[1], sizeof(double) * 15);
                t->intervals[15] = interval;
            }
            t->last_seen = ev->seen_at;
        }
    }

    t->total_seen++;

    if (cfg && cfg->log_network)
    {
        rw_log_network("tcp_established pid=%d exe=%s dst=%s:%u seen=%zu", ev->pid, ev->exe,
                       ev->dst_ip, ev->dst_port, t->total_seen);
    }
    if (cfg && cfg->verbose)
    {
        printf("[NET] pid=%d exe=%s dst=%s:%u seen=%zu\n", ev->pid, ev->exe, ev->dst_ip,
               ev->dst_port, t->total_seen);
    }

    int score = score_track(t);

    if (score > 0)
    {
        char reason[256];
        snprintf(reason, sizeof(reason), "dst=%s:%u seen=%zu avg=%.2f jitter=%.2f", t->dst_ip,
                 t->dst_port, t->total_seen, avg_interval(t), interval_jitter(t));
        rw_score_add(t->pid, NULL, t->exe, cfg, "PROC_TCP", reason, score);
    }

    int alert_threshold = cfg && cfg->case_threshold > 0 ? cfg->case_threshold : 60;
    if (score >= alert_threshold && !t->already_alerted)
    {
        t->already_alerted = 1;
        rw_log_alert(
            "possible beaconing pid=%d exe=%s dst=%s:%u seen=%zu avg=%.2f jitter=%.2f score=%d",
            t->pid, t->exe, t->dst_ip, t->dst_port, t->total_seen, avg_interval(t),
            interval_jitter(t), score);
        if (rw_case_has(t->pid))
            rw_case_event(t->pid, score, cfg, "BEACON_DETAIL",
                          "exe=%s dst=%s:%u seen=%zu avg=%.2f jitter=%.2f", t->exe, t->dst_ip,
                          t->dst_port, t->total_seen, avg_interval(t), interval_jitter(t));
        printf("\n[ALERT] Possible beaconing behavior\n");
        printf("  PID:         %d\n", t->pid);
        printf("  EXE:         %s\n", t->exe);
        printf("  Destination: %s:%u\n", t->dst_ip, t->dst_port);
        printf("  Seen:        %zu times\n", t->total_seen);
        printf("  Avg Int:     %.2fs\n", avg_interval(t));
        printf("  Jitter:      %.2fs\n", interval_jitter(t));
        printf("  Score:       %d/100\n", score);

        printf("\n[auto] Running injection scan for PID %d\n", t->pid);
        rw_scan_injection_pid(t->pid, 1, cfg);
        printf("\n[auto] Inspecting suspicious PID %d\n", t->pid);
        rw_inspect_process(t->pid);

        if (cfg->stop_suspicious)
        {
            rw_log_alert("stopping suspicious pid=%d via SIGSTOP", t->pid);
            printf("\n[auto] --stop-suspicious enabled: sending SIGSTOP to PID %d\n", t->pid);
            int rc = kill(t->pid, SIGSTOP);
            rw_case_action(t->pid, cfg, "SIGSTOP", rc == 0 ? 0 : errno, "beacon score=%d", score);
            if (rc != 0)
            {
                perror("kill SIGSTOP");
                rw_log_alert("SIGSTOP failed pid=%d", t->pid);
            }
        }
        else
        {
            printf("\n[auto] Process was NOT stopped. SignalHunter is alert-only by default.\n");
        }
    }
}
