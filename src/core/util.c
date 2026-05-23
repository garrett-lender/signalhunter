#define _GNU_SOURCE
#include "signalhunter.h"
#include "sha256.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int rw_is_numeric(const char* s)
{
    if (!s || !*s)
    {
        return 0;
    }
    for (; *s; s++)
    {
        if (!isdigit((unsigned char)*s))
        {
            return 0;
        }
    }
    return 1;
}

int rw_read_link_path(const char* path, char* out, size_t out_len)
{
    ssize_t n = readlink(path, out, out_len - 1);
    if (n < 0)
    {
        return -1;
    }
    out[n] = '\0';
    return 0;
}

void rw_read_exe_path(int pid, char* out, size_t out_len)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    if (rw_read_link_path(path, out, out_len) != 0)
    {
        snprintf(out, out_len, "<unknown>");
    }
}

int rw_suspicious_path(const char* path)
{
    if (!path)
    {
        return 0;
    }
    return strstr(path, "/tmp/") || strstr(path, "/dev/shm/") || strstr(path, "/var/tmp/") ||
           strstr(path, "/.cache/") || strstr(path, "/memfd:");
}

int rw_sha256_file(const char* path, char out_hex[65])
{

    FILE* fp = fopen(path, "rb");
    if (!fp)
    {
        return -1;
    }

    uint8_t buf[65536];
    uint8_t hash[32];
    sha256_ctx_t ctx;

    sha256_init(&ctx);

    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
    {
        sha256_update(&ctx, buf, n);
    }

    fclose(fp);

    sha256_final(&ctx, hash);

    for (size_t i = 0; i < 32; i++)
    {
        sprintf(&out_hex[i * 2], "%02x", hash[i]);
    }

    out_hex[64] = '\0';
    return 0;
}

int rw_copy_file(const char* src, const char* dst)
{
    int in_fd = open(src, O_RDONLY);
    if (in_fd < 0)
    {
        return -1;
    }

    int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out_fd < 0)
    {
        close(in_fd);
        return -1;
    }

    char buf[RW_COPY_BUF_SIZE];
    while (1)
    {
        ssize_t n = read(in_fd, buf, sizeof(buf));
        if (n == 0)
        {
            break;
        }
        if (n < 0)
        {
            close(in_fd);
            close(out_fd);
            return -1;
        }

        ssize_t off = 0;
        while (off < n)
        {
            ssize_t written = write(out_fd, buf + off, (size_t)(n - off));
            if (written < 0)
            {
                close(in_fd);
                close(out_fd);
                return -1;
            }
            off += written;
        }
    }

    close(in_fd);
    close(out_fd);
    return 0;
}

#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>

#define RW_DEFAULT_LOG_MAX_BYTES (10L * 1024L * 1024L)
#define RW_DEFAULT_LOG_ARCHIVES 5
#define RW_DEFAULT_LOG_RATE_SECONDS 10
#define RW_DEDUP_SLOTS 512

typedef struct
{
    FILE* fp;
    char path[RW_MAX_PATH];
    const char* level;
    int pri;
} rw_log_sink_t;

typedef struct
{
    unsigned long hash;
    time_t last_emit;
    unsigned int suppressed;
} rw_dedup_slot_t;

static rw_log_sink_t g_log_main;
static rw_log_sink_t g_log_alerts;
static rw_log_sink_t g_log_network;
static rw_log_sink_t g_log_injection;
static rw_log_sink_t g_log_events;
static rw_log_sink_t g_log_scores;
static rw_dedup_slot_t g_dedup[RW_DEDUP_SLOTS];
static int g_use_syslog = 0;
static long g_log_max_bytes = RW_DEFAULT_LOG_MAX_BYTES;
static int g_log_archives = RW_DEFAULT_LOG_ARCHIVES;
static int g_log_rate_seconds = RW_DEFAULT_LOG_RATE_SECONDS;

static unsigned long fnv1a(const char* s)
{
    unsigned long h = 1469598103934665603UL;
    while (s && *s)
    {
        h ^= (unsigned char)*s++;
        h *= 1099511628211UL;
    }
    return h;
}

static int ensure_dir(const char* dir)
{
    if (mkdir(dir, 0755) != 0 && errno != EEXIST)
    {
        return -1;
    }
    return 0;
}

static int open_log_file(rw_log_sink_t* sink, const char* dir, const char* name, const char* level,
                         int pri)
{
    int n = snprintf(sink->path, sizeof(sink->path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(sink->path))
    {
        return -1;
    }
    sink->fp = fopen(sink->path, "a");
    sink->level = level;
    sink->pri = pri;
    return sink->fp ? 0 : -1;
}

static void rotate_if_needed(rw_log_sink_t* sink)
{
    if (!sink || !sink->fp || g_log_max_bytes <= 0)
    {
        return;
    }
    long pos = ftell(sink->fp);
    if (pos >= 0 && pos < g_log_max_bytes)
    {
        return;
    }

    fclose(sink->fp);
    sink->fp = NULL;

    if (g_log_archives < 1)
    {
        sink->fp = fopen(sink->path, "w");
        return;
    }

    char old_path[RW_MAX_PATH * 2];
    char new_path[RW_MAX_PATH * 2];

    snprintf(old_path, sizeof(old_path), "%s.%d", sink->path, g_log_archives);
    unlink(old_path);

    for (int i = g_log_archives - 1; i >= 1; i--)
    {
        snprintf(old_path, sizeof(old_path), "%s.%d", sink->path, i);
        snprintf(new_path, sizeof(new_path), "%s.%d", sink->path, i + 1);
        rename(old_path, new_path);
    }

    snprintf(new_path, sizeof(new_path), "%s.1", sink->path);
    rename(sink->path, new_path);
    sink->fp = fopen(sink->path, "a");
}

int rw_log_init(const char* log_dir, int use_syslog)
{
    const char* dir = log_dir && *log_dir ? log_dir : "logs";
    if (ensure_dir(dir) != 0)
    {
        return -1;
    }

    char cases_dir[RW_MAX_PATH];
    int n = snprintf(cases_dir, sizeof(cases_dir), "%s/cases", dir);
    if (n > 0 && (size_t)n < sizeof(cases_dir))
    {
        ensure_dir(cases_dir);
    }

    if (open_log_file(&g_log_main, dir, "signalhunter.log", "INFO", LOG_INFO) != 0)
    {
        return -1;
    }
    if (open_log_file(&g_log_alerts, dir, "alerts.log", "ALERT", LOG_WARNING) != 0)
    {
        return -1;
    }
    if (open_log_file(&g_log_network, dir, "network.log", "NET", LOG_INFO) != 0)
    {
        return -1;
    }
    if (open_log_file(&g_log_injection, dir, "injection.log", "INJECTION", LOG_WARNING) != 0)
    {
        return -1;
    }
    if (open_log_file(&g_log_events, dir, "events.log", "EVENT", LOG_INFO) != 0)
    {
        return -1;
    }
    if (open_log_file(&g_log_scores, dir, "scores.log", "SCORE", LOG_INFO) != 0)
    {
        return -1;
    }

    const char* max_env = getenv("RW_LOG_MAX_BYTES");
    const char* archives_env = getenv("RW_LOG_ARCHIVES");
    const char* rate_env = getenv("RW_LOG_RATE_SECONDS");
    if (max_env && *max_env)
    {
        g_log_max_bytes = atol(max_env);
    }
    if (archives_env && *archives_env)
    {
        g_log_archives = atoi(archives_env);
    }
    if (rate_env && *rate_env)
    {
        g_log_rate_seconds = atoi(rate_env);
    }
    if (g_log_max_bytes < 0)
    {
        g_log_max_bytes = RW_DEFAULT_LOG_MAX_BYTES;
    }
    if (g_log_archives < 0)
    {
        g_log_archives = RW_DEFAULT_LOG_ARCHIVES;
    }
    if (g_log_rate_seconds < 0)
    {
        g_log_rate_seconds = RW_DEFAULT_LOG_RATE_SECONDS;
    }

    g_use_syslog = use_syslog;
    if (g_use_syslog)
    {
        openlog("signalhunter", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

    rw_log_info("logger initialized dir=%s syslog=%s max_bytes=%ld archives=%d rate_seconds=%d",
                dir, use_syslog ? "yes" : "no", g_log_max_bytes, g_log_archives,
                g_log_rate_seconds);
    return 0;
}

void rw_log_close(void)
{
    rw_log_sink_t* sinks[] = {&g_log_main,      &g_log_alerts, &g_log_network,
                              &g_log_injection, &g_log_events, &g_log_scores};
    for (size_t i = 0; i < sizeof(sinks) / sizeof(sinks[0]); i++)
    {
        if (sinks[i]->fp)
        {
            fclose(sinks[i]->fp);
        }
        sinks[i]->fp = NULL;
    }
    if (g_use_syslog)
    {
        closelog();
    }
}

static void timestamp_now(char* buf, size_t len)
{
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tmv);
}

static int should_emit_line(const char* level, const char* msg, unsigned int* suppressed_out)
{
    if (g_log_rate_seconds == 0)
    {
        return 1;
    }
    char key[4608];
    snprintf(key, sizeof(key), "%s:%s", level ? level : "", msg ? msg : "");
    unsigned long h = fnv1a(key);
    size_t idx = h % RW_DEDUP_SLOTS;
    time_t now = time(NULL);
    rw_dedup_slot_t* slot = &g_dedup[idx];

    if (slot->hash == h && now - slot->last_emit < g_log_rate_seconds)
    {
        slot->suppressed++;
        return 0;
    }

    if (slot->hash == h && slot->suppressed > 0 && suppressed_out)
    {
        *suppressed_out = slot->suppressed;
    }
    slot->hash = h;
    slot->last_emit = now;
    slot->suppressed = 0;
    return 1;
}

static void write_line(rw_log_sink_t* sink, const char* level, const char* msg,
                       unsigned int suppressed)
{
    if (!sink || !sink->fp)
    {
        return;
    }
    rotate_if_needed(sink);
    if (!sink->fp)
    {
        return;
    }
    char ts[64];
    timestamp_now(ts, sizeof(ts));
    fprintf(sink->fp, "[%s] [%s] %s", ts, level, msg);
    if (suppressed > 0)
    {
        fprintf(sink->fp, " suppressed_repeats=%u", suppressed);
    }
    fputc('\n', sink->fp);
    fflush(sink->fp);
}

static void vlog_to(rw_log_sink_t* sink, const char* level, int syslog_pri, const char* fmt,
                    va_list ap)
{
    char msg[4096];
    vsnprintf(msg, sizeof(msg), fmt, ap);

    unsigned int suppressed = 0;
    if (!should_emit_line(level, msg, &suppressed))
    {
        return;
    }

    write_line(sink, level, msg, suppressed);
    if (&g_log_main != sink)
    {
        write_line(&g_log_main, level, msg, 0);
    }
    if (g_use_syslog)
    {
        syslog(syslog_pri, "%s", msg);
    }
}

void rw_log_console(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

void rw_log_info(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog_to(&g_log_main, "INFO", LOG_INFO, fmt, ap);
    va_end(ap);
}

void rw_log_alert(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog_to(&g_log_alerts, "ALERT", LOG_WARNING, fmt, ap);
    va_end(ap);
}

void rw_log_network(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog_to(&g_log_network, "NET", LOG_INFO, fmt, ap);
    va_end(ap);
}

void rw_log_injection(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog_to(&g_log_injection, "INJECTION", LOG_WARNING, fmt, ap);
    va_end(ap);
}

void rw_log_event(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog_to(&g_log_events, "EVENT", LOG_INFO, fmt, ap);
    va_end(ap);
}

void rw_log_score(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog_to(&g_log_scores, "SCORE", LOG_INFO, fmt, ap);
    va_end(ap);
}

void rw_syscall_alert(int pid, const char* comm, const char* kind, const char* detail,
                      const rw_config_t* cfg)
{
    const char* safe_comm = comm && *comm ? comm : "<unknown>";
    const char* safe_kind = kind && *kind ? kind : "suspicious_syscall";
    const char* safe_detail = detail && *detail ? detail : "";

    rw_log_alert("suspicious syscall pid=%d comm=%s kind=%s detail=%s", pid, safe_comm, safe_kind,
                 safe_detail);
    if (!cfg || cfg->log_syscalls)
    {
        rw_log_event("suspicious_syscall pid=%d comm=%s kind=%s detail=%s", pid, safe_comm,
                     safe_kind, safe_detail);
    }

    printf("\n[ALERT] Suspicious syscall observed\n");
    printf("  PID:    %d\n", pid);
    printf("  COMM:   %s\n", safe_comm);
    printf("  Type:   %s\n", safe_kind);
    if (safe_detail[0])
    {
        printf("  Detail: %s\n", safe_detail);
    }

    int score = 75;
    if (strstr(safe_kind, "ptrace") || strstr(safe_kind, "process_vm_writev") ||
        strstr(safe_kind, "mprotect") || strstr(safe_kind, "mmap"))
        score = 85;
    rw_score_add(pid, safe_comm, NULL, cfg, "SYSCALL", safe_kind, score);
    if (rw_case_has(pid))
        rw_case_event(pid, score, cfg, "SYSCALL_DETAIL", "comm=%s kind=%s detail=%s", safe_comm,
                      safe_kind, safe_detail);
}
