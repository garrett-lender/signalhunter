#define _GNU_SOURCE
#include "signalhunter.h"
#include "module.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void rw_monitor_all(const rw_config_t* cfg)
{
    if (cfg->log_max_bytes > 0)
    {
        char b[64];
        snprintf(b, sizeof(b), "%ld", cfg->log_max_bytes);
        setenv("RW_LOG_MAX_BYTES", b, 1);
    }
    if (cfg->log_archives >= 0)
    {
        char b[64];
        snprintf(b, sizeof(b), "%d", cfg->log_archives);
        setenv("RW_LOG_ARCHIVES", b, 1);
    }
    if (cfg->log_rate_seconds >= 0)
    {
        char b[64];
        snprintf(b, sizeof(b), "%d", cfg->log_rate_seconds);
        setenv("RW_LOG_RATE_SECONDS", b, 1);
    }

    if (rw_log_init(cfg->log_dir, cfg->use_syslog) != 0)
    {
        fprintf(stderr, "[warn] logger init failed; continuing with console only\n");
    }
    rw_score_init();
    rw_event_init();
    rw_lineage_init();
    rw_lineage_refresh_procfs();

    time_t last_full_injection_scan = 0;
    time_t last_self_scan = 0;
    rw_modules_init_all(cfg);

    printf("SignalHunter daemon started.\n");
    printf("Watching all visible processes.\n");
    printf("Poll interval: %ds\n", cfg->poll_seconds);
    printf("Always-on modules: /proc net scan, beacon scoring, injection scan, self-integrity\n");
    printf("Plugin modules: ");
    rw_modules_print_active();
    printf("\n");
    printf("Action mode: %s\n",
           cfg->stop_suspicious ? "SIGSTOP suspicious processes" : "alert-only");
    printf("Logs: %s/{signalhunter,alerts,network,injection,events}.log%s\n", cfg->log_dir,
           cfg->use_syslog ? " and syslog/journald" : "");
    printf("Case files: %s/cases/ when score >= %d\n", cfg->log_dir, cfg->case_threshold);
    rw_log_info("daemon started poll=%d action=%s log_network=%s", cfg->poll_seconds,
                cfg->stop_suspicious ? "stop" : "alert-only", cfg->log_network ? "yes" : "no");

    while (1)
    {
        time_t now = time(NULL);

        rw_inode_owner_t* owners = calloc(RW_MAX_ITEMS, sizeof(*owners));
        rw_conn_event_t* events = calloc(RW_MAX_ITEMS, sizeof(*events));
        if (!owners || !events)
        {
            fprintf(stderr, "[fatal] allocation failed while preparing scan buffers\n");
            free(owners);
            free(events);
            sleep((unsigned int)cfg->poll_seconds);
            continue;
        }

        rw_lineage_refresh_procfs();

        size_t owner_count = rw_collect_inode_owners(owners, RW_MAX_ITEMS);
        size_t event_count = rw_collect_tcp_events(owners, owner_count, events, RW_MAX_ITEMS);

        for (size_t i = 0; i < event_count; i++)
        {
            rw_update_track(&events[i], cfg);
        }
        rw_scan_raw_sockets(owners, owner_count, cfg);

        free(events);
        free(owners);

        rw_modules_poll_all(cfg);

        rw_score_decay_all(cfg);

        if (now - last_self_scan >= 5)
        {
            rw_scan_injection_pid(getpid(), 0, cfg);
            last_self_scan = now;
        }

        if (cfg->injection_scan_seconds > 0 &&
            now - last_full_injection_scan >= cfg->injection_scan_seconds)
        {
            rw_scan_all_injection(cfg);
            last_full_injection_scan = now;
        }

        sleep((unsigned int)cfg->poll_seconds);
    }
}

void rw_usage(const char* argv0)
{
    printf("Usage:\n");
    printf("  %s [options]\n", argv0);
    printf("  %s monitor [poll_seconds] [options]\n", argv0);
    printf("  %s inspect <pid>\n", argv0);
    printf("  %s scan-injection <pid>\n", argv0);
    printf("  %s scan-all-injection\n", argv0);
    printf("  %s ebpf-status\n", argv0);
    printf("  %s ebpf-selftest\n", argv0);
    printf("\nOptions:\n");
    printf("  --no-proc-events       disable proc connector backend\n");
    printf("  --no-fanotify          disable fanotify backend\n");
    printf("  --no-ebpf              disable eBPF backend\n");
    printf("  --stop-suspicious      send SIGSTOP after high-confidence network alert\n");
    printf("  --verbose              print extra fork/exit/file activity\n");
    printf("  --quiet-network        do not write every TCP observation to network.log\n");
    printf("  --quiet-raw            do not write raw socket detections to network.log; alerts "
           "still fire\n");
    printf("  --quiet-syn            do not write SYN_SENT observations to network.log; alerts "
           "still fire\n");
    printf("  --quiet-syscalls       do not write suspicious syscall observations to events.log; "
           "alerts still fire\n");
    printf("  --syslog               also write to syslog/journald; view with journalctl -t "
           "signalhunter\n");
    printf("  --case-threshold <n>   create per-process case file at score n, default: 60\n");
    printf("  --injection-scan-seconds <n> full maps/injection scan interval, default: 30; 0 "
           "disables\n");
    printf("  --log-dir <dir>        log directory, default: logs\n");
    printf("  --log-max-bytes <n>   rotate each log after n bytes, default: 10485760\n");
    printf("  --log-archives <n>    keep n rotated archives, default: 5\n");
    printf("  --log-rate-seconds <n> suppress identical log lines within n seconds, default: 10; 0 "
           "disables\n");
    printf("  --no-whitelist         disable whitelist/trust reduction module\n");
    printf("  --whitelist <file>     whitelist rule file, default: config/whitelist.conf\n");
    printf("  --whitelist-percent <n> score percent for whitelisted processes, default: 25\n");
    printf("  --no-dynamic-plugins disable dlopen() plugin loading\n");
    printf("  --plugin-dir <dir>    plugin directory, default: plugins\n");
    printf("  --module-config <file> module config file, default: config/modules.conf\n");
}

static void parse_options(int argc, char** argv, int start, rw_config_t* cfg)
{
    for (int i = start; i < argc; i++)
    {
        if (strcmp(argv[i], "--no-proc-events") == 0)
        {
            cfg->enable_proc_events = 0;
        }
        else if (strcmp(argv[i], "--no-fanotify") == 0)
        {
            cfg->enable_fanotify = 0;
        }
        else if (strcmp(argv[i], "--no-ebpf") == 0)
        {
            cfg->enable_ebpf = 0;
        }
        else if (strcmp(argv[i], "--stop-suspicious") == 0)
        {
            cfg->stop_suspicious = 1;
        }
        else if (strcmp(argv[i], "--verbose") == 0)
        {
            cfg->verbose = 1;
        }
        else if (strcmp(argv[i], "--quiet-network") == 0)
        {
            cfg->log_network = 0;
        }
        else if (strcmp(argv[i], "--quiet-raw") == 0)
        {
            cfg->log_raw = 0;
        }
        else if (strcmp(argv[i], "--quiet-syn") == 0)
        {
            cfg->log_synscan = 0;
        }
        else if (strcmp(argv[i], "--quiet-syscalls") == 0)
        {
            cfg->log_syscalls = 0;
        }
        else if (strcmp(argv[i], "--syslog") == 0)
        {
            cfg->use_syslog = 1;
        }
        else if (strcmp(argv[i], "--no-whitelist") == 0)
        {
            cfg->enable_whitelist = 0;
        }
        else if (strcmp(argv[i], "--no-dynamic-plugins") == 0)
        {
            cfg->enable_dynamic_plugins = 0;
        }
        else if (strcmp(argv[i], "--case-threshold") == 0)
        {
            if (i + 1 < argc)
            {
                cfg->case_threshold = atoi(argv[++i]);
                if (cfg->case_threshold < 1)
                {
                    cfg->case_threshold = 60;
                }
                if (cfg->case_threshold > 100)
                {
                    cfg->case_threshold = 100;
                }
            }
            else
            {
                fprintf(stderr, "[warn] --case-threshold requires a number\n");
            }
        }
        else if (strcmp(argv[i], "--injection-scan-seconds") == 0)
        {
            if (i + 1 < argc)
            {
                cfg->injection_scan_seconds = atoi(argv[++i]);
                if (cfg->injection_scan_seconds < 0)
                {
                    cfg->injection_scan_seconds = 0;
                }
            }
            else
            {
                fprintf(stderr, "[warn] --injection-scan-seconds requires a number\n");
            }
        }
        else if (strcmp(argv[i], "--log-dir") == 0)
        {
            if (i + 1 < argc)
            {
                cfg->log_dir = argv[++i];
            }
            else
            {
                fprintf(stderr, "[warn] --log-dir requires a directory\n");
            }
        }
        else if (strcmp(argv[i], "--log-max-bytes") == 0)
        {
            if (i + 1 < argc)
            {
                cfg->log_max_bytes = atol(argv[++i]);
                if (cfg->log_max_bytes < 0)
                {
                    cfg->log_max_bytes = 0;
                }
            }
            else
            {
                fprintf(stderr, "[warn] --log-max-bytes requires a number\n");
            }
        }
        else if (strcmp(argv[i], "--log-archives") == 0)
        {
            if (i + 1 < argc)
            {
                cfg->log_archives = atoi(argv[++i]);
                if (cfg->log_archives < 0)
                {
                    cfg->log_archives = 0;
                }
            }
            else
            {
                fprintf(stderr, "[warn] --log-archives requires a number\n");
            }
        }
        else if (strcmp(argv[i], "--log-rate-seconds") == 0)
        {
            if (i + 1 < argc)
            {
                cfg->log_rate_seconds = atoi(argv[++i]);
                if (cfg->log_rate_seconds < 0)
                {
                    cfg->log_rate_seconds = 0;
                }
            }
            else
            {
                fprintf(stderr, "[warn] --log-rate-seconds requires a number\n");
            }
        }
        else if (strcmp(argv[i], "--whitelist") == 0)
        {
            if (i + 1 < argc)
            {
                cfg->whitelist_path = argv[++i];
            }
            else
            {
                fprintf(stderr, "[warn] --whitelist requires a file\n");
            }
        }
        else if (strcmp(argv[i], "--whitelist-percent") == 0)
        {
            if (i + 1 < argc)
            {
                cfg->whitelist_score_percent = atoi(argv[++i]);
                if (cfg->whitelist_score_percent < 0)
                {
                    cfg->whitelist_score_percent = 0;
                }
                if (cfg->whitelist_score_percent > 100)
                {
                    cfg->whitelist_score_percent = 100;
                }
            }
            else
            {
                fprintf(stderr, "[warn] --whitelist-percent requires a number\n");
            }
        }
        else if (strcmp(argv[i], "--plugin-dir") == 0)
        {
            if (i + 1 < argc)
            {
                cfg->plugin_dir = argv[++i];
            }
            else
            {
                fprintf(stderr, "[warn] --plugin-dir requires a directory\n");
            }
        }
        else if (strcmp(argv[i], "--module-config") == 0)
        {
            if (i + 1 < argc)
            {
                cfg->module_config_path = argv[++i];
            }
            else
            {
                fprintf(stderr, "[warn] --module-config requires a file\n");
            }
        }
        else
        {
            fprintf(stderr, "[warn] unknown option ignored: %s\n", argv[i]);
        }
    }
}

int main(int argc, char** argv)
{
    rw_config_t cfg = {
        .poll_seconds = 2,
        .enable_proc_events = 1,
        .enable_fanotify = 1,
        .enable_ebpf = 1,
        .stop_suspicious = 0,
        .verbose = 0,
        .log_network = 1,
        .log_raw = 1,
        .log_synscan = 0,
        .log_syscalls = 1,
        .use_syslog = 0,
        .case_threshold = 60,
        .injection_scan_seconds = 30,
        .log_dir = "logs",
        .log_max_bytes = 10L * 1024L * 1024L,
        .log_archives = 5,
        .log_rate_seconds = 10,
        .enable_whitelist = 1,
        .whitelist_path = "config/whitelist.conf",
        .whitelist_score_percent = 25,
        .enable_dynamic_plugins = 1,
        .plugin_dir = "plugins",
        .module_config_path = "config/modules.conf",
    };

    if (argc == 1 || argv[1][0] == '-')
    {
        parse_options(argc, argv, 1, &cfg);
        rw_monitor_all(&cfg);
        return 0;
    }

    if (strcmp(argv[1], "monitor") == 0)
    {
        int opt_start = 2;
        if (argc >= 3 && rw_is_numeric(argv[2]))
        {
            cfg.poll_seconds = atoi(argv[2]);
            if (cfg.poll_seconds <= 0)
            {
                cfg.poll_seconds = 2;
            }
            opt_start = 3;
        }
        parse_options(argc, argv, opt_start, &cfg);
        rw_monitor_all(&cfg);
        return 0;
    }

    if (strcmp(argv[1], "inspect") == 0)
    {
        if (argc < 3 || !rw_is_numeric(argv[2]))
        {
            fprintf(stderr, "Invalid or missing PID\n");
            return 1;
        }
        rw_inspect_process(atoi(argv[2]));
        return 0;
    }

    if (strcmp(argv[1], "scan-injection") == 0)
    {
        if (argc < 3 || !rw_is_numeric(argv[2]))
        {
            fprintf(stderr, "Invalid or missing PID\n");
            return 1;
        }
        rw_scan_injection_pid(atoi(argv[2]), 1, &cfg);
        return 0;
    }

    if (strcmp(argv[1], "scan-all-injection") == 0)
    {
        rw_scan_all_injection(&cfg);
        return 0;
    }

    if (strcmp(argv[1], "ebpf-status") == 0)
    {
        if (rw_log_init(cfg.log_dir, cfg.use_syslog) != 0)
        {
            fprintf(stderr, "[warn] logger init failed; continuing with console only\n");
        }
        if (rw_ebpf_init_backend() != 0)
        {
            fprintf(stderr, "[warn] eBPF backend unavailable: %s\n", strerror(errno));
            return 1;
        }
        rw_ebpf_print_status();
        rw_ebpf_poll(-1, &cfg);
        rw_ebpf_print_status();
        rw_ebpf_shutdown();
        return 0;
    }

    if (strcmp(argv[1], "ebpf-selftest") == 0)
    {
        rw_ebpf_selftest_hint();
        return 0;
    }

    rw_usage(argv[0]);
    return 1;
}
