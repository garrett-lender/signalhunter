#define _GNU_SOURCE
#include "signalhunter.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rw_scan_injection_pid(int pid, int verbose, const rw_config_t *cfg) {
    char path[128];
    char exe[RW_MAX_PATH];
    char line[2048];
    int findings = 0;

    rw_read_exe_path(pid, exe, sizeof(exe));
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (verbose) printf("[scan] PID %d maps unavailable: %s\n", pid, strerror(errno));
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        char perms[8] = {0};
        char map_path[RW_MAX_PATH] = {0};
        sscanf(line, "%*s %7s %*s %*s %*s %511[^\n]", perms, map_path);

        int has_r = strchr(perms, 'r') != NULL;
        int has_w = strchr(perms, 'w') != NULL;
        int has_x = strchr(perms, 'x') != NULL;
        int has_path = map_path[0] != '\0';

        const char *reason = NULL;
        if (has_r && has_w && has_x) reason = "RWX memory mapping";
        /* RX anonymous mappings are common on modern Linux (vDSO/JIT/runtime stubs).
         * Treat RWX as high-signal, but do not alert on plain anonymous RX by
         * itself to avoid flooding on browsers and runtimes. */
        else if (has_x && !has_path) reason = NULL;
        else if (has_x && strstr(map_path, "(deleted)")) reason = "deleted executable mapping";
        else if (has_x && strstr(map_path, "/memfd:")) reason = "executable memfd mapping";
        else if (has_x && rw_suspicious_path(map_path)) reason = "executable mapping from suspicious path";

        if (reason) {
            findings++;
            rw_log_injection("pid=%d exe=%s reason=%s map=%s", pid, exe, reason, line);
            rw_score_add(pid, NULL, exe, cfg, "INJECTION", reason, 80);
            if (rw_case_has(pid)) rw_case_event(pid, 80, cfg, "INJECTION_DETAIL", "exe=%s reason=%s map=%s", exe, reason, line);
            printf("\n[INJECTION?] PID %d\n", pid);
            printf("  EXE:    %s\n", exe);
            printf("  Reason: %s\n", reason);
            printf("  Map:    %s", line);
        }
    }
    fclose(fp);

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fp = fopen(path, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            int tracer = 0;
            if (sscanf(line, "TracerPid:\t%d", &tracer) == 1 && tracer != 0) {
                findings++;
                rw_log_injection("pid=%d exe=%s reason=process is being ptraced tracer=%d", pid, exe, tracer);
                rw_score_add(pid, NULL, exe, cfg, "INJECTION", "process is being ptraced", 90);
                if (rw_case_has(pid)) rw_case_event(pid, 90, cfg, "INJECTION_DETAIL", "exe=%s reason=process is being ptraced tracer=%d", exe, tracer);
                printf("\n[INJECTION?] PID %d\n", pid);
                printf("  EXE:       %s\n", exe);
                printf("  Reason:    process is being ptraced\n");
                printf("  TracerPid: %d\n", tracer);
            }
        }
        fclose(fp);
    }

    if (verbose && findings == 0) {
        printf("[scan] PID %d: no obvious injection indicators found\n", pid);
    }
    return findings;
}

int rw_scan_all_injection(const rw_config_t *cfg) {
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return 0;
    }

    struct dirent *de;
    int total = 0;
    while ((de = readdir(proc)) != NULL) {
        if (!rw_is_numeric(de->d_name)) continue;
        total += rw_scan_injection_pid(atoi(de->d_name), 0, cfg);
    }
    closedir(proc);

    if (total > 0) {
        rw_log_injection("full scan complete findings=%d", total);
        printf("\n[scan-all] Injection scan complete. Findings: %d\n", total);
    }
    return total;
}
