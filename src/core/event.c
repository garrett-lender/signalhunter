#define _GNU_SOURCE

#include "event.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define RW_MAX_EVENTS 16384
#define RW_EVENT_CATEGORY_LEN 64
#define RW_EVENT_DETAIL_LEN 512

typedef struct
{
    time_t ts;
    int pid;
    char category[RW_EVENT_CATEGORY_LEN];
    char detail[RW_EVENT_DETAIL_LEN];
} rw_event_record_t;

static rw_event_record_t g_events[RW_MAX_EVENTS];
static size_t g_event_count;
static size_t g_event_next;

static void write_time(FILE *fp, time_t ts)
{
    char buf[64];
    struct tm tmv;

    localtime_r(&ts, &tmv);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    fprintf(fp, "%s", buf);
}

void rw_event_init(void)
{
    memset(g_events, 0, sizeof(g_events));
    g_event_count = 0;
    g_event_next = 0;
}

void rw_event_add(int pid, const char *category, const char *detail)
{
    if (pid <= 0)
    {
        return;
    }

    rw_event_record_t *ev = &g_events[g_event_next];
    memset(ev, 0, sizeof(*ev));

    ev->ts = time(NULL);
    ev->pid = pid;
    snprintf(ev->category, sizeof(ev->category), "%s",
             category && *category ? category : "event");
    snprintf(ev->detail, sizeof(ev->detail), "%s",
             detail && *detail ? detail : "<none>");

    g_event_next = (g_event_next + 1) % RW_MAX_EVENTS;

    if (g_event_count < RW_MAX_EVENTS)
    {
        g_event_count++;
    }
}

void rw_event_addf(int pid, const char *category, const char *fmt, ...)
{
    char detail[RW_EVENT_DETAIL_LEN];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);

    rw_event_add(pid, category, detail);
}

int rw_event_write_timeline(int case_pid, const char *case_dir)
{
    if (case_pid <= 0 || !case_dir || !*case_dir)
    {
        return -1;
    }

    char path[RW_MAX_PATH];
    int n = snprintf(path, sizeof(path), "%s/timeline.txt", case_dir);

    if (n < 0 || (size_t)n >= sizeof(path))
    {
        return -1;
    }

    FILE *fp = fopen(path, "w");

    if (!fp)
    {
        return -1;
    }

    fprintf(fp, "Timeline for case pid %d\n", case_pid);
    fprintf(fp, "=========================\n\n");
    fprintf(fp, "timestamp\tpid\tcategory\tdetail\n");

    size_t start = 0;

    if (g_event_count == RW_MAX_EVENTS)
    {
        start = g_event_next;
    }

    for (size_t i = 0; i < g_event_count; i++)
    {
        size_t idx = (start + i) % RW_MAX_EVENTS;
        const rw_event_record_t *ev = &g_events[idx];

        if (ev->pid <= 0)
        {
            continue;
        }

        if (!rw_lineage_is_related(case_pid, ev->pid))
        {
            continue;
        }

        write_time(fp, ev->ts);
        fprintf(fp, "\t%d\t%s\t%s\n", ev->pid, ev->category, ev->detail);
    }

    fclose(fp);
    return 0;
}
