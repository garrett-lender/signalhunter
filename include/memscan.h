#ifndef SIGNALHUNTER_MEMSCAN_H
#define SIGNALHUNTER_MEMSCAN_H

#include <stddef.h>

#define SH_MEMSCAN_MAX_REGION_DUMP (1024U * 1024U)

typedef struct
{
    int pid;
    const char* case_dir;
    const void* cfg;
    int freeze_process;
    size_t max_region_bytes;
} sh_memscan_request_t;

int sh_memscan_pid(const sh_memscan_request_t* req);

#endif
