#define _GNU_SOURCE

#include "memscan.h"
#include "shellcode.h"
#include "signalhunter.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    unsigned long start;
    unsigned long end;
    char perms[8];
    char path[RW_MAX_PATH];
} sh_map_region_t;

static int interesting_mapping(const sh_map_region_t *r)
{
    int has_x = strchr(r->perms, 'x') != NULL;
    int has_w = strchr(r->perms, 'w') != NULL;
    int has_path = r->path[0] != '\0';

    if (has_x && has_w) return 1;
    if (has_x && !has_path) return 1;
    if (has_x && strstr(r->path, "(deleted)")) return 1;
    if (has_x && strstr(r->path, "/memfd:")) return 1;
    if (has_x && rw_suspicious_path(r->path)) return 1;

    return 0;
}

static int parse_maps_line(const char *line, sh_map_region_t *r)
{
    char range[64] = {0};
    char map_path[RW_MAX_PATH] = {0};
    int n;

    memset(r, 0, sizeof(*r));

    n = sscanf(line, "%63s %7s %*s %*s %*s %511[^\n]", range, r->perms, map_path);
    if (n < 2) return -1;

    if (sscanf(range, "%lx-%lx", &r->start, &r->end) != 2) return -1;

    if (n == 3) snprintf(r->path, sizeof(r->path), "%s", map_path);

    return 0;
}

static int read_region(int memfd, unsigned long start, uint8_t *buf, size_t len)
{
    size_t done = 0;

    while (done < len) {
        ssize_t n = pread(memfd, buf + done, len - done, (off_t)(start + done));
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        done += (size_t)n;
    }

    return (int)done;
}

static int has_elf_header(const uint8_t *buf, size_t len)
{
    return len >= 4 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F';
}

static int has_pe_header(const uint8_t *buf, size_t len)
{
    if (len < 0x40) return 0;
    if (buf[0] != 'M' || buf[1] != 'Z') return 0;

    uint32_t peoff = (uint32_t)buf[0x3c] |
                     ((uint32_t)buf[0x3d] << 8) |
                     ((uint32_t)buf[0x3e] << 16) |
                     ((uint32_t)buf[0x3f] << 24);

    if ((size_t)peoff + 4 > len) return 0;
    return buf[peoff] == 'P' && buf[peoff + 1] == 'E' && buf[peoff + 2] == 0 && buf[peoff + 3] == 0;
}

static void write_hex_sample(FILE *fp, const uint8_t *buf, size_t len)
{
    size_t n = len < 64 ? len : 64;
    for (size_t i = 0; i < n; i++) {
        fprintf(fp, "%02x%c", buf[i], ((i + 1) % 16) == 0 ? '\n' : ' ');
    }
    if (n % 16 != 0) fputc('\n', fp);
}

static void extract_interesting_strings(FILE *fp, const uint8_t *buf, size_t len)
{
    char s[512];
    size_t pos = 0;

    for (size_t i = 0; i < len; i++) {
        if ((isprint(buf[i]) || buf[i] == '\t') && pos + 1 < sizeof(s)) {
            s[pos++] = (char)buf[i];
            continue;
        }

        if (pos >= 5) {
            s[pos] = '\0';
            if (strstr(s, "http://") || strstr(s, "https://") || strstr(s, "/bin/") ||
                strstr(s, "/tmp/") || strstr(s, "socket") || strstr(s, "connect") ||
                strstr(s, "exec") || strstr(s, "LD_PRELOAD") || strstr(s, "memfd") ||
                strstr(s, "/dev/shm")) {
                fprintf(fp, "%s\n", s);
            }
        }
        pos = 0;
    }

    if (pos >= 5) {
        s[pos] = '\0';
        fprintf(fp, "%s\n", s);
    }
}

static void dump_region(const char *case_dir, int idx, const uint8_t *buf, size_t len)
{
    char path[RW_MAX_PATH];
    int n = snprintf(path, sizeof(path), "%s/mem_region_%03d.bin", case_dir, idx);
    if (n < 0 || (size_t)n >= sizeof(path)) return;

    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    fwrite(buf, 1, len, fp);
    fclose(fp);
}

int sh_memscan_pid(const sh_memscan_request_t *req)
{
    const rw_config_t *cfg;
    char maps_path[128];
    char mem_path[128];
    char findings_path[RW_MAX_PATH];
    char strings_path[RW_MAX_PATH];
    FILE *maps = NULL;
    FILE *findings = NULL;
    FILE *strings = NULL;
    int memfd = -1;
    int stopped = 0;
    int findings_count = 0;
    int region_idx = 0;

    if (!req || req->pid <= 0 || !req->case_dir) return -1;
    cfg = (const rw_config_t *)req->cfg;

    if (req->freeze_process) {
        if (kill(req->pid, SIGSTOP) == 0) {
            stopped = 1;
            usleep(100000);
        }
    }

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", req->pid);
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", req->pid);
    snprintf(findings_path, sizeof(findings_path), "%s/memory_findings.txt", req->case_dir);
    snprintf(strings_path, sizeof(strings_path), "%s/memory_strings.txt", req->case_dir);

    findings = fopen(findings_path, "a");
    if (!findings) goto out;

    fprintf(findings, "memory scan pid=%d time=%ld\n", req->pid, (long)time(NULL));

    maps = fopen(maps_path, "r");
    if (!maps) {
        fprintf(findings, "maps unavailable: %s\n", strerror(errno));
        goto out;
    }

    memfd = open(mem_path, O_RDONLY);
    if (memfd < 0) {
        fprintf(findings, "mem unavailable: %s\n", strerror(errno));
        goto out;
    }

    strings = fopen(strings_path, "a");

    char line[4096];
    while (fgets(line, sizeof(line), maps)) {
        sh_map_region_t r;
        if (parse_maps_line(line, &r) != 0) continue;
        if (!interesting_mapping(&r)) continue;

        size_t region_len = r.end > r.start ? (size_t)(r.end - r.start) : 0;
        if (region_len == 0) continue;

        size_t cap = req->max_region_bytes;
        if (cap == 0 || cap > SH_MEMSCAN_MAX_REGION_DUMP) cap = SH_MEMSCAN_MAX_REGION_DUMP;
        size_t to_read = region_len < cap ? region_len : cap;

        uint8_t *buf = malloc(to_read);
        if (!buf) {
            fprintf(findings, "malloc failed region=%lx-%lx\n", r.start, r.end);
            continue;
        }

        int nread = read_region(memfd, r.start, buf, to_read);
        if (nread <= 0) {
            fprintf(findings, "read failed region=%lx-%lx perms=%s path=%s err=%s\n",
                    r.start, r.end, r.perms, r.path, strerror(errno));
            free(buf);
            continue;
        }

        fprintf(findings, "\nregion=%lx-%lx read=%d/%zu perms=%s path=%s\n",
                r.start, r.end, nread, to_read, r.perms, r.path);
        write_hex_sample(findings, buf, (size_t)nread);

        if (has_elf_header(buf, (size_t)nread)) {
            fprintf(findings, "indicator=ELF header in suspicious mapping\n");
            rw_score_add(req->pid, NULL, NULL, cfg, "memory", "ELF header in suspicious mapping", 60);
            findings_count++;
        }

        if (has_pe_header(buf, (size_t)nread)) {
            fprintf(findings, "indicator=PE header in suspicious mapping\n");
            rw_score_add(req->pid, NULL, NULL, cfg, "memory", "PE header in suspicious mapping", 60);
            findings_count++;
        }

        if (strchr(r.perms, 'x') && strchr(r.perms, 'w')) {
            fprintf(findings, "indicator=RWX mapping scanned\n");
            rw_score_add(req->pid, NULL, NULL, cfg, "memory", "RWX mapping scanned", 25);
            findings_count++;
        }

        if (strstr(r.path, "/memfd:")) {
            fprintf(findings, "indicator=executable memfd mapping scanned\n");
            rw_score_add(req->pid, NULL, NULL, cfg, "memory", "executable memfd mapping scanned", 35);
            findings_count++;
        }

        sh_shellcode_report_t sc;
        sh_shellcode_scan(buf, (size_t)nread, &sc);
        if (sc.finding_count > 0) {
            sh_shellcode_write_report(findings, &sc);
            rw_score_add(req->pid, NULL, NULL, cfg, "memory", "shellcode-like byte patterns in suspicious mapping", sc.score >= 60 ? 60 : sc.score);
            findings_count += sc.finding_count;
        }

        if (strings) {
            fprintf(strings, "\n# region=%lx-%lx perms=%s path=%s\n", r.start, r.end, r.perms, r.path);
            extract_interesting_strings(strings, buf, (size_t)nread);
        }

        dump_region(req->case_dir, region_idx++, buf, (size_t)nread);
        free(buf);
    }

out:
    if (findings) {
        fprintf(findings, "\nfindings=%d\n", findings_count);
        fclose(findings);
    }
    if (strings) fclose(strings);
    if (memfd >= 0) close(memfd);
    if (maps) fclose(maps);
    if (stopped) kill(req->pid, SIGCONT);
    return findings_count;
}
