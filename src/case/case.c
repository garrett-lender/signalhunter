#define _GNU_SOURCE
#include "signalhunter.h"
#include "memscan.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define RW_MAX_CASES 512

typedef struct
{
    int pid;
    int max_score;
    char dir[RW_MAX_PATH];
} rw_case_t;

static rw_case_t g_cases[RW_MAX_CASES];
static size_t g_case_count = 0;

static void case_timestamp(char* buf, size_t len, const char* fmt)
{
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(buf, len, fmt, &tmv);
}

static int mkdir_if_needed(const char* path)
{
    if (mkdir(path, 0755) == 0)
    {
        return 0;
    }
    return errno == EEXIST ? 0 : -1;
}

static rw_case_t* find_case(int pid)
{
    for (size_t i = 0; i < g_case_count; i++)
    {
        if (g_cases[i].pid == pid)
        {
            return &g_cases[i];
        }
    }
    return NULL;
}

int rw_case_has(int pid)
{
    return find_case(pid) != NULL;
}

static void write_proc_file_to_case(int pid, const char* name, const char* dst_name)
{
    rw_case_t* c = find_case(pid);
    if (!c)
    {
        return;
    }

    char src[128];
    char dst[RW_MAX_PATH];
    snprintf(src, sizeof(src), "/proc/%d/%s", pid, name);
    int n = snprintf(dst, sizeof(dst), "%s/%s", c->dir, dst_name);
    if (n < 0 || (size_t)n >= sizeof(dst))
    {
        return;
    }
    if (rw_copy_file(src, dst) != 0)
    {
        FILE* fp = fopen(dst, "w");
        if (fp)
        {
            fprintf(fp, "%s unavailable: %s\n", name, strerror(errno));
            fclose(fp);
        }
    }
}

static void write_fd_listing_to_case(int pid)
{
    rw_case_t* c = find_case(pid);
    if (!c)
    {
        return;
    }

    char fd_dir[128];
    char out_path[RW_MAX_PATH];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
    int n = snprintf(out_path, sizeof(out_path), "%s/fds.txt", c->dir);
    if (n < 0 || (size_t)n >= sizeof(out_path))
    {
        return;
    }

    FILE* out = fopen(out_path, "w");
    if (!out)
    {
        return;
    }

    DIR* dir = opendir(fd_dir);
    if (!dir)
    {
        fprintf(out, "fd directory unavailable: %s\n", strerror(errno));
        fclose(out);
        return;
    }

    struct dirent* de;
    while ((de = readdir(dir)) != NULL)
    {
        if (de->d_name[0] == '.')
        {
            continue;
        }
        char fd_path[RW_MAX_PATH];
        char target[RW_MAX_PATH];
        n = snprintf(fd_path, sizeof(fd_path), "%s/%s", fd_dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(fd_path))
        {
            continue;
        }
        if (rw_read_link_path(fd_path, target, sizeof(target)) == 0)
        {
            fprintf(out, "%s -> %s\n", de->d_name, target);
        }
    }

    closedir(dir);
    fclose(out);
}

static void dump_exe_to_case(int pid)
{
    rw_case_t* c = find_case(pid);
    if (!c)
    {
        return;
    }

    char src[128];
    char dst[RW_MAX_PATH];
    snprintf(src, sizeof(src), "/proc/%d/exe", pid);
    int n = snprintf(dst, sizeof(dst), "%s/exe.dump", c->dir);
    if (n < 0 || (size_t)n >= sizeof(dst))
    {
        return;
    }

    if (rw_copy_file(src, dst) == 0)
    {
        char hash[65];
        if (rw_sha256_file(dst, hash) == 0)
        {
            char hp[RW_MAX_PATH];
            n = snprintf(hp, sizeof(hp), "%s/exe.sha256", c->dir);
            if (n >= 0 && (size_t)n < sizeof(hp))
            {
                FILE* fp = fopen(hp, "w");
                if (fp)
                {
                    fprintf(fp, "%s  exe.dump\n", hash);
                    fclose(fp);
                }
            }
        }
    }
}

static void snapshot_case(int pid, const rw_config_t* cfg)
{
    rw_case_t* c = find_case(pid);

    write_proc_file_to_case(pid, "cmdline", "cmdline.bin");
    write_proc_file_to_case(pid, "status", "status.txt");
    write_proc_file_to_case(pid, "maps", "maps.txt");
    write_proc_file_to_case(pid, "environ", "environ.bin");
    write_fd_listing_to_case(pid);
    dump_exe_to_case(pid);

    if (c)
    {
        (void)rw_lineage_write_case(pid, c->dir);
        (void)rw_event_write_timeline(pid, c->dir);

        sh_memscan_request_t memreq = {0};
        memreq.pid = pid;
        memreq.case_dir = c->dir;
        memreq.cfg = cfg;
        memreq.freeze_process = 0;
        memreq.max_region_bytes = SH_MEMSCAN_MAX_REGION_DUMP;
        (void)sh_memscan_pid(&memreq);
    }
}

static rw_case_t* create_case(int pid, int score, const rw_config_t* cfg, const char* reason)
{
    if (g_case_count >= RW_MAX_CASES)
    {
        return NULL;
    }

    const char* base = (cfg && cfg->log_dir && *cfg->log_dir) ? cfg->log_dir : "logs";
    char cases_dir[RW_MAX_PATH];
    int n = snprintf(cases_dir, sizeof(cases_dir), "%s/cases", base);
    if (n < 0 || (size_t)n >= sizeof(cases_dir))
    {
        return NULL;
    }

    if (mkdir_if_needed(base) != 0)
    {
        return NULL;
    }
    if (mkdir_if_needed(cases_dir) != 0)
    {
        return NULL;
    }

    char ts[64];
    case_timestamp(ts, sizeof(ts), "%Y%m%d_%H%M%S");

    rw_case_t* c = &g_cases[g_case_count];
    memset(c, 0, sizeof(*c));
    c->pid = pid;
    c->max_score = score;

    n = snprintf(c->dir, sizeof(c->dir), "%s/pid_%d_%s", cases_dir, pid, ts);
    if (n < 0 || (size_t)n >= sizeof(c->dir))
    {
        return NULL;
    }
    if (mkdir_if_needed(c->dir) != 0)
    {
        return NULL;
    }

    g_case_count++;

    char exe[RW_MAX_PATH];
    rw_read_exe_path(pid, exe, sizeof(exe));

    char path[RW_MAX_PATH];
    n = snprintf(path, sizeof(path), "%s/case.log", c->dir);
    if (n >= 0 && (size_t)n < sizeof(path))
    {
        FILE* fp = fopen(path, "a");
        if (fp)
        {
            char human_ts[64];
            case_timestamp(human_ts, sizeof(human_ts), "%Y-%m-%d %H:%M:%S");
            fprintf(fp, "[%s] [CASE_OPEN] pid=%d score=%d exe=%s reason=%s\n", human_ts, pid, score,
                    exe, reason ? reason : "<none>");
            fclose(fp);
        }
    }

    rw_log_alert("case opened pid=%d score=%d dir=%s reason=%s", pid, score, c->dir,
                 reason ? reason : "<none>");
    printf("\n[case] opened %s\n", c->dir);
    snapshot_case(pid, cfg);
    return c;
}

static rw_case_t* get_or_create_case(int pid, int score, const rw_config_t* cfg, const char* reason)
{
    rw_case_t* c = find_case(pid);
    if (c)
    {
        if (score > c->max_score)
        {
            c->max_score = score;
        }
        return c;
    }

    int threshold = (cfg && cfg->case_threshold > 0) ? cfg->case_threshold : 60;
    if (score < threshold)
    {
        return NULL;
    }

    return create_case(pid, score, cfg, reason);
}

static void case_vlog(rw_case_t* c, int score, const char* category, const char* fmt, va_list ap)
{
    if (!c)
    {
        return;
    }
    char msg[4096];
    vsnprintf(msg, sizeof(msg), fmt, ap);

    char path[RW_MAX_PATH];
    int n = snprintf(path, sizeof(path), "%s/case.log", c->dir);
    if (n < 0 || (size_t)n >= sizeof(path))
    {
        return;
    }

    FILE* fp = fopen(path, "a");
    if (!fp)
    {
        return;
    }

    char ts[64];
    case_timestamp(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S");
    fprintf(fp, "[%s] [%s] score=%d %s\n", ts, category ? category : "EVENT", score, msg);
    fclose(fp);
}

void rw_case_event(int pid, int score, const rw_config_t* cfg, const char* category,
                   const char* fmt, ...)
{
    const char* reason = category && *category ? category : "event";
    rw_case_t* c = get_or_create_case(pid, score, cfg, reason);
    if (!c)
    {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    case_vlog(c, score, category, fmt, ap);
    va_end(ap);

    (void)rw_lineage_write_case(pid, c->dir);
    (void)rw_event_write_timeline(pid, c->dir);
}

void rw_case_action(int pid, const rw_config_t* cfg, const char* action, int result,
                    const char* fmt, ...)
{
    rw_case_t* c = get_or_create_case(pid, 100, cfg, action ? action : "action");
    if (!c)
    {
        return;
    }

    char detail[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);

    char path[RW_MAX_PATH];
    int n = snprintf(path, sizeof(path), "%s/actions.log", c->dir);
    if (n >= 0 && (size_t)n < sizeof(path))
    {
        FILE* fp = fopen(path, "a");
        if (fp)
        {
            char ts[64];
            case_timestamp(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S");
            fprintf(fp, "[%s] action=%s result=%d detail=%s\n", ts, action ? action : "action",
                    result, detail);
            fclose(fp);
        }
    }

    rw_case_event(pid, 100, cfg, "ACTION", "action=%s result=%d detail=%s",
                  action ? action : "action", result, detail);
}
