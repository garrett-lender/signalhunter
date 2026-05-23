#ifndef SIGNALHUNTER_SHELLCODE_H
#define SIGNALHUNTER_SHELLCODE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define SH_SHELLCODE_MAX_FINDINGS 32

typedef struct
{
    int score;
    int finding_count;
    char arch_hint[64];
    char findings[SH_SHELLCODE_MAX_FINDINGS][128];
} sh_shellcode_report_t;

void sh_shellcode_scan(const uint8_t* buf, size_t len, sh_shellcode_report_t* report);
void sh_shellcode_write_report(FILE* fp, const sh_shellcode_report_t* report);

#endif
