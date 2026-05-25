#define _GNU_SOURCE
#include "signalhunter.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define RW_MAX_PROCS 4096
#define RW_DECAY_SECONDS 30
#define RW_DECAY_AMOUNT 1

#define RW_FINDING_RWX              (1ULL << 0)
#define RW_FINDING_MEMFD            (1ULL << 1)
#define RW_FINDING_NOP              (1ULL << 2)
#define RW_FINDING_BEACON           (1ULL << 3)
#define RW_FINDING_RAW_SOCKET       (1ULL << 4)
#define RW_FINDING_SYNSCAN          (1ULL << 5)
#define RW_FINDING_TMP_EXEC         (1ULL << 6)
#define RW_FINDING_PTRACE           (1ULL << 7)
#define RW_FINDING_PROCESS_VM       (1ULL << 8)
#define RW_FINDING_PE_ELF           (1ULL << 9)
#define RW_FINDING_SUSPICIOUS_FILE  (1ULL << 10)
#define RW_FINDING_EXEC_MEMORY      (1ULL << 11)

static rw_proc_score_t g_scores[RW_MAX_PROCS];
static size_t g_score_count;

static const char* category_name(rw_risk_category_t cat)
{
    switch (cat)
    {
        case RW_RISK_MEMORY:
            return "memory";
        case RW_RISK_NETWORK:
            return "network";
        case RW_RISK_PROCESS:
            return "process";
        case RW_RISK_FILESYSTEM:
            return "filesystem";
        case RW_RISK_LINEAGE:
            return "lineage";
        default:
            return "unknown";
    }
}

static int clamp_int(int value, int low, int high)
{
    if (value < low)
    {
        return low;
    }

    if (value > high)
    {
        return high;
    }

    return value;
}

static int contains_ci(const char* haystack, const char* needle)
{
    size_t needle_len;

    if (!haystack || !needle)
    {
        return 0;
    }

    needle_len = strlen(needle);

    if (needle_len == 0)
    {
        return 1;
    }

    for (const char* p = haystack; *p; p++)
    {
        size_t i;

        for (i = 0; i < needle_len; i++)
        {
            unsigned char hc = (unsigned char)p[i];
            unsigned char nc = (unsigned char)needle[i];

            if (hc == 0)
            {
                return 0;
            }

            if (tolower(hc) != tolower(nc))
            {
                break;
            }
        }

        if (i == needle_len)
        {
            return 1;
        }
    }

    return 0;
}

static int is_browser_like(const char* comm, const char* exe)
{
    return contains_ci(comm, "firefox") ||
           contains_ci(comm, "chrome") ||
           contains_ci(comm, "chromium") ||
           contains_ci(comm, "web content") ||
           contains_ci(comm, "isolated web") ||
           contains_ci(exe, "/firefox") ||
           contains_ci(exe, "/chrome") ||
           contains_ci(exe, "/chromium");
}

static rw_proc_score_t* find_proc(int pid)
{
    for (size_t i = 0; i < g_score_count; i++)
    {
        if (g_scores[i].pid == pid)
        {
            return &g_scores[i];
        }
    }

    return NULL;
}

static rw_proc_score_t* create_proc(int pid, const char* comm, const char* exe)
{
    rw_proc_score_t* p;

    if (g_score_count >= RW_MAX_PROCS)
    {
        return NULL;
    }

    p = &g_scores[g_score_count++];
    memset(p, 0, sizeof(*p));

    p->pid = pid;
    p->first_seen = time(NULL);
    p->last_seen = p->first_seen;
    p->last_decay = p->first_seen;
    snprintf(p->comm, sizeof(p->comm), "%s", comm && *comm ? comm : "<unknown>");

    if (exe && *exe)
    {
        snprintf(p->exe, sizeof(p->exe), "%s", exe);
    }
    else
    {
        rw_read_exe_path(pid, p->exe, sizeof(p->exe));
    }

    return p;
}

void rw_score_init(void)
{
    memset(g_scores, 0, sizeof(g_scores));
    g_score_count = 0;
}

rw_proc_score_t* rw_score_get(int pid)
{
    return find_proc(pid);
}

static void decay_proc(rw_proc_score_t* p)
{
    time_t now;

    if (!p || p->last_decay == 0)
    {
        return;
    }

    now = time(NULL);

    while ((now - p->last_decay) >= RW_DECAY_SECONDS)
    {
        for (int i = 0; i < RW_RISK_CATEGORY_COUNT; i++)
        {
            if (p->category_scores[i] > 0)
            {
                p->category_scores[i] -= RW_DECAY_AMOUNT;
                p->category_scores[i] = clamp_int(p->category_scores[i], 0, 100);
            }
        }

        if (p->risk_floor > 0)
        {
            p->risk_floor -= RW_DECAY_AMOUNT;
            p->risk_floor = clamp_int(p->risk_floor, 0, 100);
        }

        p->last_decay += RW_DECAY_SECONDS;
    }
}

void rw_score_decay_all(const rw_config_t* cfg)
{
    (void)cfg;

    for (size_t i = 0; i < g_score_count; i++)
    {
        decay_proc(&g_scores[i]);
    }
}

static rw_risk_category_t classify_category(const char* category, const char* reason)
{
    if (contains_ci(category, "mem") ||
        contains_ci(category, "inject") ||
        contains_ci(reason, "rwx") ||
        contains_ci(reason, "memfd") ||
        contains_ci(reason, "nop") ||
        contains_ci(reason, "elf") ||
        contains_ci(reason, "pe header"))
    {
        return RW_RISK_MEMORY;
    }

    if (contains_ci(category, "net") ||
        contains_ci(category, "tcp") ||
        contains_ci(category, "connect") ||
        contains_ci(category, "raw_socket") ||
        contains_ci(category, "packet_socket") ||
        contains_ci(category, "synscan") ||
        contains_ci(reason, "beacon") ||
        contains_ci(reason, "socket"))
    {
        return RW_RISK_NETWORK;
    }

    if (contains_ci(category, "file") ||
        contains_ci(reason, "chmod") ||
        contains_ci(reason, "/tmp/") ||
        contains_ci(reason, "/dev/shm/"))
    {
        return RW_RISK_FILESYSTEM;
    }

    if (contains_ci(category, "lineage") ||
        contains_ci(reason, "parent") ||
        contains_ci(reason, "child") ||
        contains_ci(reason, "process tree"))
    {
        return RW_RISK_LINEAGE;
    }

    return RW_RISK_PROCESS;
}

static unsigned long long classify_flags(const char* category, const char* reason)
{
    unsigned long long flags = 0;

    if (contains_ci(reason, "rwx"))
    {
        flags |= RW_FINDING_RWX | RW_FINDING_EXEC_MEMORY;
    }

    if (contains_ci(reason, "memfd"))
    {
        flags |= RW_FINDING_MEMFD | RW_FINDING_EXEC_MEMORY;
    }

    if (contains_ci(reason, "nop") || contains_ci(reason, "shellcode"))
    {
        flags |= RW_FINDING_NOP;
    }

    if (contains_ci(reason, "beacon") || contains_ci(reason, "reconnect") || contains_ci(category, "connect"))
    {
        flags |= RW_FINDING_BEACON;
    }

    if (contains_ci(category, "raw_socket") || contains_ci(reason, "raw"))
    {
        flags |= RW_FINDING_RAW_SOCKET;
    }

    if (contains_ci(category, "packet_socket") || contains_ci(reason, "packet"))
    {
        flags |= RW_FINDING_RAW_SOCKET;
    }

    if (contains_ci(category, "synscan") || contains_ci(reason, "syn_sent") || contains_ci(reason, "scan"))
    {
        flags |= RW_FINDING_SYNSCAN;
    }

    if (contains_ci(reason, "/tmp/") || contains_ci(reason, "/dev/shm/") || contains_ci(reason, "temporary"))
    {
        flags |= RW_FINDING_TMP_EXEC | RW_FINDING_SUSPICIOUS_FILE;
    }

    if (contains_ci(reason, "ptrace") || contains_ci(category, "ptrace"))
    {
        flags |= RW_FINDING_PTRACE;
    }

    if (contains_ci(reason, "process_vm") || contains_ci(category, "process_vm"))
    {
        flags |= RW_FINDING_PROCESS_VM;
    }

    if (contains_ci(reason, "elf header") || contains_ci(reason, "pe header"))
    {
        flags |= RW_FINDING_PE_ELF | RW_FINDING_EXEC_MEMORY;
    }

    return flags;
}

static int default_floor_for_finding(const char* category, const char* reason, int points)
{
    int floor = 0;

    if (contains_ci(reason, "process is being ptraced") || contains_ci(reason, "ptrace"))
    {
        floor = 90;
    }
    else if (contains_ci(category, "raw_socket") || contains_ci(category, "packet_socket"))
    {
        floor = 90;
    }
    else if (contains_ci(reason, "process_vm_writev"))
    {
        floor = 85;
    }
    else if (contains_ci(reason, "executable memfd"))
    {
        floor = 78;
    }
    else if (contains_ci(reason, "rwx"))
    {
        floor = 75;
    }
    else if (contains_ci(reason, "nop") || contains_ci(reason, "shellcode"))
    {
        floor = 70;
    }
    else if (points >= 90)
    {
        floor = 80;
    }

    return floor;
}

static int normalized_points(const rw_proc_score_t* p,
                             rw_risk_category_t cat,
                             const char* category,
                             const char* reason,
                             int points)
{
    int out = points;

    if (contains_ci(category, "ebpf_connect") && points > 25)
    {
        out = 25;
    }

    if (is_browser_like(p->comm, p->exe) && cat == RW_RISK_MEMORY)
    {
        if (contains_ci(reason, "mmap") || contains_ci(reason, "prot_exec"))
        {
            out = out / 3;
        }
    }

    if (out < 1)
    {
        out = 1;
    }

    if (out > 100)
    {
        out = 100;
    }

    return out;
}

static int has_flags(const rw_proc_score_t* p, unsigned long long flags)
{
    return (p->finding_flags & flags) == flags;
}

static int compute_correlation_bonus(const rw_proc_score_t* p)
{
    int bonus = 0;

    if (has_flags(p, RW_FINDING_MEMFD | RW_FINDING_NOP))
    {
        bonus += 25;
    }

    if (has_flags(p, RW_FINDING_EXEC_MEMORY | RW_FINDING_BEACON))
    {
        bonus += 20;
    }

    if (has_flags(p, RW_FINDING_RWX | RW_FINDING_RAW_SOCKET))
    {
        bonus += 25;
    }

    if (has_flags(p, RW_FINDING_TMP_EXEC | RW_FINDING_BEACON))
    {
        bonus += 20;
    }

    if (has_flags(p, RW_FINDING_RAW_SOCKET | RW_FINDING_SYNSCAN))
    {
        bonus += 20;
    }

    if (has_flags(p, RW_FINDING_PTRACE | RW_FINDING_PROCESS_VM))
    {
        bonus += 25;
    }

    if (has_flags(p, RW_FINDING_TMP_EXEC | RW_FINDING_EXEC_MEMORY))
    {
        bonus += 15;
    }

    if (has_flags(p, RW_FINDING_PE_ELF | RW_FINDING_RWX))
    {
        bonus += 15;
    }

    return clamp_int(bonus, 0, 60);
}

static int compute_weighted_score(const rw_proc_score_t* p)
{
    int weighted;
    int max_cat = 0;

    weighted = (p->category_scores[RW_RISK_MEMORY] * 30) +
               (p->category_scores[RW_RISK_NETWORK] * 25) +
               (p->category_scores[RW_RISK_PROCESS] * 20) +
               (p->category_scores[RW_RISK_FILESYSTEM] * 15) +
               (p->category_scores[RW_RISK_LINEAGE] * 10);

    weighted /= 100;

    for (int i = 0; i < RW_RISK_CATEGORY_COUNT; i++)
    {
        if (p->category_scores[i] > max_cat)
        {
            max_cat = p->category_scores[i];
        }
    }

    /*
     * A single category can be enough to open a case if it becomes very strong.
     * This keeps critical memory-only or network-only behavior from being
     * artificially capped below an 85 threshold, while correlations still make
     * mixed behavior score higher and explain better.
     */
    if ((max_cat * 85) / 100 > weighted)
    {
        weighted = (max_cat * 85) / 100;
    }

    return clamp_int(weighted, 0, 100);
}

static void recompute_score(rw_proc_score_t* p)
{
    int weighted;
    int final_score;

    p->correlation_bonus = compute_correlation_bonus(p);
    weighted = compute_weighted_score(p);
    final_score = weighted + p->correlation_bonus;

    if (p->risk_floor > final_score)
    {
        final_score = p->risk_floor;
    }

    p->score = clamp_int(final_score, 0, 100);

    if (p->score > p->peak_score)
    {
        p->peak_score = p->score;
    }
}

int rw_score_add(int pid,
                 const char* comm,
                 const char* exe,
                 const rw_config_t* cfg,
                 const char* category,
                 const char* reason,
                 int points)
{
    rw_proc_score_t* p;
    rw_risk_category_t cat;
    unsigned long long flags;
    int before;
    int normalized;
    int threshold;
    int floor;

    if (pid <= 0 || points <= 0)
    {
        return 0;
    }

    p = find_proc(pid);

    if (!p)
    {
        p = create_proc(pid, comm, exe);

        if (!p)
        {
            return 0;
        }
    }

    decay_proc(p);

    if (comm && *comm)
    {
        snprintf(p->comm, sizeof(p->comm), "%s", comm);
    }

    if (exe && *exe && strcmp(exe, "<unknown>") != 0)
    {
        snprintf(p->exe, sizeof(p->exe), "%s", exe);
    }

    before = p->score;
    cat = classify_category(category, reason);
    flags = classify_flags(category, reason);
    normalized = normalized_points(p, cat, category, reason, points);
    floor = default_floor_for_finding(category, reason, points);

    p->category_scores[cat] = clamp_int(p->category_scores[cat] + normalized, 0, 100);
    p->finding_flags |= flags;

    if (floor > p->risk_floor)
    {
        p->risk_floor = floor;
    }

    p->last_seen = time(NULL);
    recompute_score(p);

    if (p->event_count < sizeof(p->events) / sizeof(p->events[0]))
    {
        rw_score_event_t* ev = &p->events[p->event_count++];
        ev->ts = p->last_seen;
        ev->points = normalized;
        ev->total_score = p->score;
        ev->category_score = p->category_scores[cat];
        ev->correlation_bonus = p->correlation_bonus;
        snprintf(ev->category, sizeof(ev->category), "%s", category && *category ? category : category_name(cat));
        snprintf(ev->reason, sizeof(ev->reason), "%s", reason && *reason ? reason : "unknown");
    }

    threshold = cfg && cfg->case_threshold > 0 ? cfg->case_threshold : 60;

    rw_log_score("pid=%d comm=%s exe=%s risk=%d peak=%d delta=%d raw_points=%d before=%d threshold=%d bucket=%s bucket_score=%d corr=%d floor=%d category=%s reason=%s",
                 pid,
                 p->comm,
                 p->exe,
                 p->score,
                 p->peak_score,
                 normalized,
                 points,
                 before,
                 threshold,
                 category_name(cat),
                 p->category_scores[cat],
                 p->correlation_bonus,
                 p->risk_floor,
                 category && *category ? category : "unknown",
                 reason && *reason ? reason : "unknown");

    rw_event_addf(pid,
                  category && *category ? category : "score",
                  "risk=%d before=%d delta=%d raw_points=%d peak=%d threshold=%d bucket=%s bucket_score=%d corr=%d floor=%d comm=%s exe=%s reason=%s",
                  p->score,
                  before,
                  normalized,
                  points,
                  p->peak_score,
                  threshold,
                  category_name(cat),
                  p->category_scores[cat],
                  p->correlation_bonus,
                  p->risk_floor,
                  p->comm,
                  p->exe,
                  reason && *reason ? reason : "unknown");

    if (cfg && cfg->verbose)
    {
        printf("[score] pid=%d risk=%d +%d bucket=%s bucket_score=%d corr=%d reason=%s\n",
               pid,
               p->score,
               normalized,
               category_name(cat),
               p->category_scores[cat],
               p->correlation_bonus,
               reason && *reason ? reason : "unknown");
    }

    if (p->score >= threshold)
    {
        if (!p->case_opened)
        {
            p->case_opened = 1;
            rw_log_alert("case threshold crossed pid=%d risk=%d threshold=%d category=%s reason=%s",
                         pid,
                         p->score,
                         threshold,
                         category && *category ? category : "unknown",
                         reason && *reason ? reason : "unknown");
        }

        rw_case_event(pid,
                      p->score,
                      cfg,
                      category && *category ? category : "SCORE",
                      "risk=%d delta=%d raw_points=%d peak=%d bucket=%s bucket_score=%d corr=%d floor=%d comm=%s exe=%s reason=%s",
                      p->score,
                      normalized,
                      points,
                      p->peak_score,
                      category_name(cat),
                      p->category_scores[cat],
                      p->correlation_bonus,
                      p->risk_floor,
                      p->comm,
                      p->exe,
                      reason && *reason ? reason : "unknown");
    }
    else if (rw_case_has(pid))
    {
        rw_case_event(pid,
                      p->score,
                      cfg,
                      category && *category ? category : "SCORE",
                      "below_threshold_update risk=%d delta=%d raw_points=%d peak=%d bucket=%s bucket_score=%d corr=%d floor=%d comm=%s exe=%s reason=%s",
                      p->score,
                      normalized,
                      points,
                      p->peak_score,
                      category_name(cat),
                      p->category_scores[cat],
                      p->correlation_bonus,
                      p->risk_floor,
                      p->comm,
                      p->exe,
                      reason && *reason ? reason : "unknown");
    }

    return p->score;
}

static void write_correlation(FILE* fp, const rw_proc_score_t* p, unsigned long long flags, const char* text, int bonus)
{
    if (has_flags(p, flags))
    {
        fprintf(fp, "  +%d %s\n", bonus, text);
    }
}

int rw_score_write_case(int pid, const char* case_dir)
{
    rw_proc_score_t* p;
    char path[RW_MAX_PATH];
    int n;
    FILE* fp;

    if (!case_dir || !*case_dir)
    {
        return -1;
    }

    p = find_proc(pid);

    if (!p)
    {
        return -1;
    }

    n = snprintf(path, sizeof(path), "%s/risk_summary.txt", case_dir);

    if (n < 0 || (size_t)n >= sizeof(path))
    {
        return -1;
    }

    fp = fopen(path, "w");

    if (!fp)
    {
        return -1;
    }

    fprintf(fp, "pid=%d\n", p->pid);
    fprintf(fp, "comm=%s\n", p->comm);
    fprintf(fp, "exe=%s\n", p->exe);
    fprintf(fp, "current_risk=%d\n", p->score);
    fprintf(fp, "peak_risk=%d\n", p->peak_score);
    fprintf(fp, "risk_floor=%d\n", p->risk_floor);
    fprintf(fp, "correlation_bonus=%d\n", p->correlation_bonus);
    fprintf(fp, "finding_flags=0x%llx\n\n", p->finding_flags);

    fprintf(fp, "Category scores:\n");

    for (int i = 0; i < RW_RISK_CATEGORY_COUNT; i++)
    {
        fprintf(fp, "  %-10s %d\n", category_name((rw_risk_category_t)i), p->category_scores[i]);
    }

    fprintf(fp, "\nCorrelations:\n");
    write_correlation(fp, p, RW_FINDING_MEMFD | RW_FINDING_NOP, "executable memfd + NOP/shellcode pattern", 25);
    write_correlation(fp, p, RW_FINDING_EXEC_MEMORY | RW_FINDING_BEACON, "executable memory anomaly + beacon/connect behavior", 20);
    write_correlation(fp, p, RW_FINDING_RWX | RW_FINDING_RAW_SOCKET, "RWX memory + raw/packet socket", 25);
    write_correlation(fp, p, RW_FINDING_TMP_EXEC | RW_FINDING_BEACON, "temporary-path execution + beacon/connect behavior", 20);
    write_correlation(fp, p, RW_FINDING_RAW_SOCKET | RW_FINDING_SYNSCAN, "raw/packet socket + scan-like behavior", 20);
    write_correlation(fp, p, RW_FINDING_PTRACE | RW_FINDING_PROCESS_VM, "ptrace + process_vm activity", 25);
    write_correlation(fp, p, RW_FINDING_TMP_EXEC | RW_FINDING_EXEC_MEMORY, "temporary-path artifact + executable memory", 15);
    write_correlation(fp, p, RW_FINDING_PE_ELF | RW_FINDING_RWX, "PE/ELF header in RWX/suspicious memory", 15);

    fprintf(fp, "\nRecent score events:\n");

    for (size_t i = 0; i < p->event_count; i++)
    {
        rw_score_event_t* ev = &p->events[i];
        fprintf(fp,
                "  [%ld] total=%d delta=%d category_score=%d corr=%d category=%s reason=%s\n",
                (long)ev->ts,
                ev->total_score,
                ev->points,
                ev->category_score,
                ev->correlation_bonus,
                ev->category,
                ev->reason);
    }

    fclose(fp);

    n = snprintf(path, sizeof(path), "%s/score_timeline.log", case_dir);

    if (n < 0 || (size_t)n >= sizeof(path))
    {
        return 0;
    }

    fp = fopen(path, "w");

    if (!fp)
    {
        return 0;
    }

    for (size_t i = 0; i < p->event_count; i++)
    {
        rw_score_event_t* ev = &p->events[i];
        fprintf(fp,
                "[%ld] total=%d delta=%d category_score=%d corr=%d category=%s reason=%s\n",
                (long)ev->ts,
                ev->total_score,
                ev->points,
                ev->category_score,
                ev->correlation_bonus,
                ev->category,
                ev->reason);
    }

    fclose(fp);

    return 0;
}
