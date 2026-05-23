#define _GNU_SOURCE
#include "signalhunter.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define RW_MAX_PROCS 4096
#define RW_DECAY_SECONDS 30
#define RW_DECAY_AMOUNT 1

static rw_proc_score_t g_scores[RW_MAX_PROCS];
static size_t g_score_count;

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
    if (g_score_count >= RW_MAX_PROCS)
    {
        return NULL;
    }
    rw_proc_score_t* p = &g_scores[g_score_count++];
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
    time_t now = time(NULL);
    if (!p || p->last_decay == 0)
    {
        return;
    }
    while ((now - p->last_decay) >= RW_DECAY_SECONDS)
    {
        if (p->score > 0)
        {
            p->score -= RW_DECAY_AMOUNT;
            if (p->score < 0)
            {
                p->score = 0;
            }
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

int rw_score_add(int pid, const char* comm, const char* exe, const rw_config_t* cfg,
                 const char* category, const char* reason, int points)
{
    if (pid <= 0 || points <= 0)
    {
        return 0;
    }

    rw_proc_score_t* p = find_proc(pid);
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

    int before = p->score;
    p->score += points;
    if (p->score > 100)
    {
        p->score = 100;
    }
    if (p->score > p->peak_score)
    {
        p->peak_score = p->score;
    }
    p->last_seen = time(NULL);

    if (p->event_count < sizeof(p->events) / sizeof(p->events[0]))
    {
        rw_score_event_t* ev = &p->events[p->event_count++];
        ev->ts = p->last_seen;
        ev->points = points;
        ev->total_score = p->score;
        snprintf(ev->category, sizeof(ev->category), "%s",
                 category && *category ? category : "unknown");
        snprintf(ev->reason, sizeof(ev->reason), "%s", reason && *reason ? reason : "unknown");
    }

    int threshold = cfg && cfg->case_threshold > 0 ? cfg->case_threshold : 60;

    rw_log_score("pid=%d comm=%s exe=%s total=%d peak=%d delta=%d before=%d threshold=%d "
                 "category=%s reason=%s",
                 pid, p->comm, p->exe, p->score, p->peak_score, points, before, threshold,
                 category && *category ? category : "unknown",
                 reason && *reason ? reason : "unknown");

    rw_event_addf(pid, category && *category ? category : "score",
                  "score delta=%d before=%d total=%d peak=%d threshold=%d comm=%s exe=%s reason=%s",
                  points, before, p->score, p->peak_score, threshold, p->comm, p->exe,
                  reason && *reason ? reason : "unknown");

    if (cfg && cfg->verbose)
    {
        printf("[score] pid=%d total=%d +%d category=%s reason=%s\n", pid, p->score, points,
               category && *category ? category : "unknown",
               reason && *reason ? reason : "unknown");
    }

    if (p->score >= threshold)
    {
        if (!p->case_opened)
        {
            p->case_opened = 1;
            rw_log_alert(
                "case threshold crossed pid=%d score=%d threshold=%d category=%s reason=%s", pid,
                p->score, threshold, category && *category ? category : "unknown",
                reason && *reason ? reason : "unknown");
        }
        rw_case_event(pid, p->score, cfg, category && *category ? category : "SCORE",
                      "cumulative_score=%d delta=%d peak=%d comm=%s exe=%s reason=%s", p->score,
                      points, p->peak_score, p->comm, p->exe,
                      reason && *reason ? reason : "unknown");
    }
    else if (rw_case_has(pid))
    {
        rw_case_event(
            pid, p->score, cfg, category && *category ? category : "SCORE",
            "below_threshold_update cumulative_score=%d delta=%d peak=%d comm=%s exe=%s reason=%s",
            p->score, points, p->peak_score, p->comm, p->exe,
            reason && *reason ? reason : "unknown");
    }

    return p->score;
}
