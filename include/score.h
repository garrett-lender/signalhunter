#ifndef SIGNALHUNTER_SCORE_H
#define SIGNALHUNTER_SCORE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define RW_MAX_EVENT_REASON 256
#define RW_MAX_EVENTS 256
#define RW_MAX_CASE_DIR 512

typedef struct
{
    time_t ts;
    int points;
    char category[64];
    char reason[RW_MAX_EVENT_REASON];
} rw_score_event_t;

typedef struct
{
    int pid;

    char comm[64];
    char exe[512];

    int score;
    int peak_score;

    time_t first_seen;
    time_t last_seen;
    time_t last_decay;

    int case_opened;

    char case_dir[RW_MAX_CASE_DIR];

    size_t event_count;

    rw_score_event_t events[RW_MAX_EVENTS];
} rw_proc_score_t;

void rw_score_init(void);

void rw_score_add(int pid, const char* comm, const char* exe, const char* category,
                  const char* reason, int points);

void rw_score_decay_all(void);

rw_proc_score_t* rw_score_get(int pid);

#endif
