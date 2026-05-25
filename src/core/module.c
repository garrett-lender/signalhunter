#define _GNU_SOURCE

#include "module.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int proc_enabled(const rw_config_t *cfg)
{
    return cfg && cfg->enable_proc_events;
}

static int fanotify_enabled(const rw_config_t *cfg)
{
    return cfg && cfg->enable_fanotify;
}

static int ebpf_enabled(const rw_config_t *cfg)
{
    return cfg && cfg->enable_ebpf;
}

static int proc_init(rw_module_t *module, const rw_config_t *cfg)
{
    (void)cfg;

    module->fd = rw_proc_events_init();

    if (module->fd < 0) {
        return -1;
    }

    return 0;
}

static void proc_poll(rw_module_t *module, const rw_config_t *cfg)
{
    if (module->fd >= 0) {
        rw_proc_events_poll(module->fd, cfg);
    }
}

static void proc_shutdown(rw_module_t *module)
{
    (void)module;
}

static int fanotify_init_mod(rw_module_t *module, const rw_config_t *cfg)
{
    (void)cfg;

    module->fd = rw_fanotify_init_backend();

    if (module->fd < 0) {
        return -1;
    }

    return 0;
}

static void fanotify_poll_mod(rw_module_t *module, const rw_config_t *cfg)
{
    if (module->fd >= 0) {
        rw_fanotify_poll(module->fd, cfg);
    }
}

static void fanotify_shutdown(rw_module_t *module)
{
    (void)module;
}

static int ebpf_init_mod(rw_module_t *module, const rw_config_t *cfg)
{
    (void)cfg;
    module->fd = -1;

    if (rw_ebpf_init_backend() != 0) {
        return -1;
    }

    return 0;
}

static void ebpf_poll_mod(rw_module_t *module, const rw_config_t *cfg)
{
    static time_t last_status = 0;
    time_t now = time(NULL);

    (void)module;

    rw_ebpf_poll(-1, cfg);

    if (now - last_status >= 15) {
        rw_ebpf_print_status();
        last_status = now;
    }
}

static void ebpf_shutdown_mod(rw_module_t *module)
{
    (void)module;
    rw_ebpf_shutdown();
}

static rw_module_t g_modules[] = {
    {
        .name = "proc_connector",
        .initialized = 0,
        .fd = -1,
        .enabled = proc_enabled,
        .init = proc_init,
        .poll = proc_poll,
        .shutdown = proc_shutdown,
    },
    {
        .name = "fanotify",
        .initialized = 0,
        .fd = -1,
        .enabled = fanotify_enabled,
        .init = fanotify_init_mod,
        .poll = fanotify_poll_mod,
        .shutdown = fanotify_shutdown,
    },
    {
        .name = "ebpf",
        .initialized = 0,
        .fd = -1,
        .enabled = ebpf_enabled,
        .init = ebpf_init_mod,
        .poll = ebpf_poll_mod,
        .shutdown = ebpf_shutdown_mod,
    },
};

static const size_t g_module_count = sizeof(g_modules) / sizeof(g_modules[0]);

int rw_modules_init_all(const rw_config_t *cfg)
{
    int enabled_count = 0;

    for (size_t i = 0; i < g_module_count; i++) {
        rw_module_t *m = &g_modules[i];

        if (m->enabled && !m->enabled(cfg)) {
            continue;
        }

        if (!m->init) {
            continue;
        }

        if (m->init(m, cfg) != 0) {
            fprintf(stderr, "[warn] module %s unavailable: %s\n", m->name, strerror(errno));
            rw_log_info("module %s unavailable: %s", m->name, strerror(errno));
            continue;
        }

        m->initialized = 1;
        enabled_count++;

        printf("[ok] module %s enabled\n", m->name);
        rw_log_info("module %s enabled", m->name);
    }

    return enabled_count;
}

void rw_modules_poll_all(const rw_config_t *cfg)
{
    for (size_t i = 0; i < g_module_count; i++) {
        rw_module_t *m = &g_modules[i];

        if (!m->initialized || !m->poll) {
            continue;
        }

        m->poll(m, cfg);
    }
}

void rw_modules_shutdown_all(void)
{
    for (size_t i = 0; i < g_module_count; i++) {
        rw_module_t *m = &g_modules[i];

        if (!m->initialized || !m->shutdown) {
            continue;
        }

        m->shutdown(m);
        m->initialized = 0;
    }
}

void rw_modules_print_active(void)
{
    int first = 1;

    for (size_t i = 0; i < g_module_count; i++) {
        rw_module_t *m = &g_modules[i];

        if (!m->initialized) {
            continue;
        }

        if (!first) {
            printf(", ");
        }

        printf("%s", m->name);
        first = 0;
    }

    if (first) {
        printf("none");
    }
}
