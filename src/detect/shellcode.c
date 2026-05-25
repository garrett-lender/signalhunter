#define _GNU_SOURCE
#include "shellcode.h"

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

static void add_finding(sh_shellcode_report_t* r, int points, const char* msg)
{
    if (!r || !msg)
    {
        return;
    }
    if (r->finding_count < SH_SHELLCODE_MAX_FINDINGS)
    {
        snprintf(r->findings[r->finding_count], sizeof(r->findings[r->finding_count]), "%s",
                 msg);
        r->finding_count++;
    }

    r->score += points;
    if (r->score > 100)
    {
        r->score = 100;
    }
}

static int has_run_byte(const uint8_t* buf, size_t len, uint8_t v, size_t needed)
{
    size_t run = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (buf[i] == v)
        {
            run++;
            if (run >= needed)
            {
                return 1;
            }
        }
        else
        {
            run = 0;
        }
    }
    return 0;
}

static int has_pattern(const uint8_t* buf, size_t len, const uint8_t* pat, size_t pat_len)
{
    if (!buf || !pat || pat_len == 0 || len < pat_len)
    {
        return 0;
    }

    for (size_t i = 0; i <= len - pat_len; i++)
    {
        if (memcmp(buf + i, pat, pat_len) == 0)
        {
            return 1;
        }
    }

    return 0;
}

static int repeated_pattern(const uint8_t* buf, size_t len, const uint8_t* pat, size_t pat_len,
                            size_t repeat)
{
    if (!buf || !pat || pat_len == 0 || repeat == 0 || len < pat_len * repeat)
    {
        return 0;
    }

    for (size_t i = 0; i <= len - (pat_len * repeat); i++)
    {
        size_t ok = 1;
        for (size_t r = 0; r < repeat; r++)
        {
            if (memcmp(buf + i + (r * pat_len), pat, pat_len) != 0)
            {
                ok = 0;
                break;
            }
        }

        if (ok)
        {
            return 1;
        }
    }
    return 0;
}

static uint32_t rd32_le(const uint8_t* p)
{
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint32_t rd32_be(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
}

static int mips_syscall_word(uint32_t w)
{
    return (w & 0x3fU) == 0x0cU;
}

static void scan_x86(const uint8_t* buf, size_t len, sh_shellcode_report_t* r)
{
    static const uint8_t syscall_pat[] = {0x0f, 0x05};
    static const uint8_t int80_pat[] = {0xcd, 0x80};
    static const uint8_t binsh[] = "/bin/sh";
    static const uint8_t mov_rax_syscall[] = {0x48, 0xc7, 0xc0};

    if (has_run_byte(buf, len, 0x90, 16))
    {
        add_finding(r, 25, "x86/x64 NOP sled: >=16 consecutive 0x90 bytes");
    }

    if (has_run_byte(buf, len, 0x90, 32))
    {
        add_finding(r, 20, "x86/x64 long NOP sled: >=32 consecutive 0x90 bytes");
    }

    if (has_pattern(buf, len, syscall_pat, sizeof(syscall_pat)))
    {
        add_finding(r, 25, "x86_64 syscall instruction pattern: 0f 05");
    }

    if (has_pattern(buf, len, int80_pat, sizeof(int80_pat)))
    {
        add_finding(r, 25, "x86 int 0x80 syscall pattern: cd 80");
    }

    if (has_pattern(buf, len, binsh, sizeof(binsh) - 1))
    {
        add_finding(r, 20, "shell string present: /bin/sh");
    }

    if (has_pattern(buf, len, mov_rax_syscall, sizeof(mov_rax_syscall)))
    {
        add_finding(r, 10, "x64 syscall setup pattern: mov rax, imm32");
    }
}

static void scan_arm64(const uint8_t* buf, size_t len, sh_shellcode_report_t* r)
{
    static const uint8_t nop_le[] = {0x1f, 0x20, 0x03, 0xd5};
    static const uint8_t nop_be[] = {0xd5, 0x03, 0x20, 0x1f};
    static const uint8_t svc_le[] = {0x01, 0x00, 0x00, 0xd4};
    static const uint8_t svc_be[] = {0xd4, 0x00, 0x00, 0x01};

    if (repeated_pattern(buf, len, nop_le, sizeof(nop_le), 8) ||
        repeated_pattern(buf, len, nop_be, sizeof(nop_be), 8))
    {
        add_finding(r, 25, "ARM64 NOP sled: repeated NOP instructions");
    }

    if (has_pattern(buf, len, svc_le, sizeof(svc_le)) ||
        has_pattern(buf, len, svc_be, sizeof(svc_be)))
    {
        add_finding(r, 25, "ARM64 syscall pattern: svc #0");
    }
}

static void scan_arm32_thumb(const uint8_t* buf, size_t len, sh_shellcode_report_t* r)
{
    static const uint8_t arm_nop_le[] = {0x00, 0xf0, 0x20, 0xe3};
    static const uint8_t arm_nop_be[] = {0xe3, 0x20, 0xf0, 0x00};
    static const uint8_t thumb_nop_le[] = {0x00, 0xbf};
    static const uint8_t thumb_nop_be[] = {0xbf, 0x00};
    static const uint8_t arm_svc_le[] = {0x00, 0x00, 0x00, 0xef};
    static const uint8_t arm_svc_be[] = {0xef, 0x00, 0x00, 0x00};

    if (repeated_pattern(buf, len, arm_nop_le, sizeof(arm_nop_le), 8) ||
        repeated_pattern(buf, len, arm_nop_be, sizeof(arm_nop_be), 8))
    {
        add_finding(r, 20, "ARM NOP sled: repeated ARM NOP instructions");
    }

    if (repeated_pattern(buf, len, thumb_nop_le, sizeof(thumb_nop_le), 12) ||
        repeated_pattern(buf, len, thumb_nop_be, sizeof(thumb_nop_be), 12))
    {
        add_finding(r, 20, "Thumb NOP sled: repeated Thumb NOP instructions");
    }

    if (has_pattern(buf, len, arm_svc_le, sizeof(arm_svc_le)) ||
        has_pattern(buf, len, arm_svc_be, sizeof(arm_svc_be)))
    {
        add_finding(r, 20, "ARM syscall pattern: svc/swi");
    }

    for (size_t i = 0; i + 1 < len; i++)
    {
        if (buf[i] == 0xdf)
        {
            add_finding(r, 10, "Thumb syscall-like pattern: svc immediate");
            break;
        }
    }
}

static void scan_mips(const uint8_t* buf, size_t len, sh_shellcode_report_t* r)
{
    size_t zero_words = 0;
    size_t max_zero_words = 0;
    int saw_syscall = 0;

    for (size_t i = 0; i + 3 < len; i += 4)
    {
        uint32_t le = rd32_le(buf + i);
        uint32_t be = rd32_be(buf + i);

        if (le == 0 || be == 0)
        {
            zero_words++;
            if (zero_words > max_zero_words)
            {
                max_zero_words = zero_words;
            }
        }
        else
        {
            zero_words = 0;
        }

        if (mips_syscall_word(le) || mips_syscall_word(be))
        {
            saw_syscall = 1;
        }
    }

    if (max_zero_words >= 8)
    {
        add_finding(r, 20, "MIPS NOP sled: repeated zero-word NOPs");
    }

    if (saw_syscall)
    {
        add_finding(r, 20, "MIPS syscall instruction pattern");
    }
}

void sh_shellcode_scan(const uint8_t* buf, size_t len, sh_shellcode_report_t* report)
{
    struct utsname uts;
    if (!report)
    {
        return;
    }

    memset(report, 0, sizeof(*report));

    if (uname(&uts) == 0)
    {
        strncpy(report->arch_hint, uts.machine, sizeof(report->arch_hint) - 1);
        report->arch_hint[sizeof(report->arch_hint) - 1] = '\0';
    }
    else
    {
        snprintf(report->arch_hint, sizeof(report->arch_hint), "unknown");
    }

    if (!buf || len == 0)
    {
        return;
    }

    /* Apply all heuristics. Patterns are endian-aware where instruction words matter. */
    scan_x86(buf, len, report);
    scan_arm64(buf, len, report);
    scan_arm32_thumb(buf, len, report);
    scan_mips(buf, len, report);
}

void sh_shellcode_write_report(FILE* fp, const sh_shellcode_report_t* report)
{
    if (!fp || !report)
    {
        return;
    }

    fprintf(fp, "shellcode_arch_hint=%s shellcode_score=%d shellcode_findings=%d\n",
            report->arch_hint, report->score, report->finding_count);

    for (int i = 0; i < report->finding_count; i++)
    {
        fprintf(fp, "shellcode_indicator=%s\n", report->findings[i]);
    }
}
