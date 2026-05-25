#define _GNU_SOURCE

#include "module.h"
#include "whitelist.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RW_MAX_DYNAMIC_MODULES 64
#define RW_MAX_MODULE_CONFIG_LINE 1024

static int proc_enabled(const rw_config_t* cfg)
{
    return cfg && cfg->enable_proc_events;
}

static int fanotify_enabled(const rw_config_t* cfg)
{
    return cfg && cfg->enable_fanotify;
}

static int ebpf_enabled(const rw_config_t* cfg)
{
    return cfg && cfg->enable_ebpf;
}

static int whitelist_enabled(const rw_config_t* cfg)
{
    return cfg && cfg->enable_whitelist;
}

static int proc_init(rw_module_t* module, const rw_config_t* cfg)
{
    (void)cfg;

    module->fd = rw_proc_events_init();

    if (module->fd < 0)
    {
        return -1;
    }

    return 0;
}

static void proc_poll(rw_module_t* module, const rw_config_t* cfg)
{
    if (module->fd >= 0)
    {
        rw_proc_events_poll(module->fd, cfg);
    }
}

static void proc_shutdown(rw_module_t* module)
{
    (void)module;
}

static int fanotify_init_mod(rw_module_t* module, const rw_config_t* cfg)
{
    (void)cfg;

    module->fd = rw_fanotify_init_backend();

    if (module->fd < 0)
    {
        return -1;
    }

    return 0;
}

static void fanotify_poll_mod(rw_module_t* module, const rw_config_t* cfg)
{
    if (module->fd >= 0)
    {
        rw_fanotify_poll(module->fd, cfg);
    }
}

static void fanotify_shutdown(rw_module_t* module)
{
    (void)module;
}

static int ebpf_init_mod(rw_module_t* module, const rw_config_t* cfg)
{
    (void)cfg;

    module->fd = -1;

    if (rw_ebpf_init_backend() != 0)
    {
        return -1;
    }

    return 0;
}

static void ebpf_poll_mod(rw_module_t* module, const rw_config_t* cfg)
{
    static time_t last_status = 0;
    time_t now = time(NULL);

    (void)module;

    rw_ebpf_poll(-1, cfg);

    if (now - last_status >= 15)
    {
        rw_ebpf_print_status();
        last_status = now;
    }
}

static void ebpf_shutdown_mod(rw_module_t* module)
{
    (void)module;
    rw_ebpf_shutdown();
}

static int whitelist_init_mod(rw_module_t* module, const rw_config_t* cfg)
{
    module->fd = -1;
    return rw_whitelist_init(cfg);
}

static void whitelist_poll_mod(rw_module_t* module, const rw_config_t* cfg)
{
    (void)module;
    rw_whitelist_poll(cfg);
}

static void whitelist_shutdown_mod(rw_module_t* module)
{
    (void)module;
    rw_whitelist_shutdown();
}

static rw_module_t g_modules[] = {
    {
        .name = "whitelist",
        .initialized = 0,
        .fd = -1,
        .enabled = whitelist_enabled,
        .init = whitelist_init_mod,
        .poll = whitelist_poll_mod,
        .shutdown = whitelist_shutdown_mod,
        .abi_version = RW_MODULE_ABI_VERSION,
    },
    {
        .name = "proc_connector",
        .initialized = 0,
        .fd = -1,
        .enabled = proc_enabled,
        .init = proc_init,
        .poll = proc_poll,
        .shutdown = proc_shutdown,
        .abi_version = RW_MODULE_ABI_VERSION,
    },
    {
        .name = "fanotify",
        .initialized = 0,
        .fd = -1,
        .enabled = fanotify_enabled,
        .init = fanotify_init_mod,
        .poll = fanotify_poll_mod,
        .shutdown = fanotify_shutdown,
        .abi_version = RW_MODULE_ABI_VERSION,
    },
    {
        .name = "ebpf",
        .initialized = 0,
        .fd = -1,
        .enabled = ebpf_enabled,
        .init = ebpf_init_mod,
        .poll = ebpf_poll_mod,
        .shutdown = ebpf_shutdown_mod,
        .abi_version = RW_MODULE_ABI_VERSION,
    },
};

static const size_t g_module_count = sizeof(g_modules) / sizeof(g_modules[0]);

typedef struct
{
    void* handle;
    rw_module_t* module;
    char path[512];
} rw_dynamic_module_slot_t;

static rw_dynamic_module_slot_t g_dynamic_modules[RW_MAX_DYNAMIC_MODULES];
static size_t g_dynamic_module_count = 0;

static char* trim(char* s)
{
    char* end = NULL;

    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
    {
        s++;
    }

    if (*s == '\0')
    {
        return s;
    }

    end = s + strlen(s) - 1;

    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
    {
        *end = '\0';
        end--;
    }

    return s;
}

static int str_bool_enabled(const char* s, int default_value)
{
    if (!s)
    {
        return default_value;
    }

    if (strcmp(s, "1") == 0 || strcmp(s, "on") == 0 || strcmp(s, "yes") == 0 ||
        strcmp(s, "true") == 0 || strcmp(s, "enabled") == 0)
    {
        return 1;
    }

    if (strcmp(s, "0") == 0 || strcmp(s, "off") == 0 || strcmp(s, "no") == 0 ||
        strcmp(s, "false") == 0 || strcmp(s, "disabled") == 0)
    {
        return 0;
    }

    return default_value;
}

static int builtin_config_enabled(const rw_config_t* cfg, const char* name, int default_value)
{
    FILE* fp = NULL;
    char line[RW_MAX_MODULE_CONFIG_LINE];
    int result = default_value;

    if (!cfg || !cfg->module_config_path)
    {
        return default_value;
    }

    fp = fopen(cfg->module_config_path, "r");

    if (!fp)
    {
        return default_value;
    }

    while (fgets(line, sizeof(line), fp))
    {
        char* p = trim(line);
        char* eq = NULL;

        if (*p == '\0' || *p == '#')
        {
            continue;
        }

        eq = strchr(p, '=');

        if (!eq)
        {
            continue;
        }

        *eq = '\0';

        char* key = trim(p);
        char* value = trim(eq + 1);
        char expected[256];

        snprintf(expected, sizeof(expected), "builtin.%s", name);

        if (strcmp(key, expected) == 0)
        {
            result = str_bool_enabled(value, default_value);
        }
    }

    fclose(fp);
    return result;
}

static int dynamic_module_already_loaded(const char* path)
{
    for (size_t i = 0; i < g_dynamic_module_count; i++)
    {
        if (strcmp(g_dynamic_modules[i].path, path) == 0)
        {
            return 1;
        }
    }

    return 0;
}

static int init_dynamic_module(void* handle, rw_module_t* module, const char* path,
                               const rw_config_t* cfg)
{
    if (!module || !module->name)
    {
        fprintf(stderr, "[warn] plugin %s returned invalid module\n", path);
        rw_log_info("plugin %s returned invalid module", path);
        return -1;
    }

    if (module->abi_version != 0 && module->abi_version != RW_MODULE_ABI_VERSION)
    {
        fprintf(stderr, "[warn] plugin %s ABI mismatch: module=%d host=%d\n", path,
                module->abi_version, RW_MODULE_ABI_VERSION);
        rw_log_info("plugin %s ABI mismatch", path);
        return -1;
    }

    if (module->enabled && !module->enabled(cfg))
    {
        return -1;
    }

    module->fd = -1;

    if (module->init && module->init(module, cfg) != 0)
    {
        fprintf(stderr, "[warn] plugin module %s init failed: %s\n", module->name, strerror(errno));
        rw_log_info("plugin module %s init failed: %s", module->name, strerror(errno));
        return -1;
    }

    module->initialized = 1;

    if (g_dynamic_module_count >= RW_MAX_DYNAMIC_MODULES)
    {
        fprintf(stderr, "[warn] dynamic module limit reached, skipping %s\n", path);
        rw_log_info("dynamic module limit reached, skipping %s", path);
        return -1;
    }

    g_dynamic_modules[g_dynamic_module_count].handle = handle;
    g_dynamic_modules[g_dynamic_module_count].module = module;
    snprintf(g_dynamic_modules[g_dynamic_module_count].path,
             sizeof(g_dynamic_modules[g_dynamic_module_count].path), "%s", path);
    g_dynamic_module_count++;

    printf("[ok] dynamic module %s enabled from %s\n", module->name, path);
    rw_log_info("dynamic module %s enabled from %s", module->name, path);
    return 0;
}

static int load_dynamic_module_file(const char* path, const rw_config_t* cfg)
{
    void* handle = NULL;
    rw_module_entry_fn entry = NULL;
    rw_module_t* module = NULL;

    if (!path || dynamic_module_already_loaded(path))
    {
        return 0;
    }

    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (!handle)
    {
        fprintf(stderr, "[warn] dlopen failed for %s: %s\n", path, dlerror());
        rw_log_info("dlopen failed for %s: %s", path, dlerror());
        return -1;
    }

    dlerror();
    entry = (rw_module_entry_fn)dlsym(handle, RW_MODULE_ENTRY_SYMBOL);

    if (!entry)
    {
        fprintf(stderr, "[warn] plugin %s missing %s\n", path, RW_MODULE_ENTRY_SYMBOL);
        rw_log_info("plugin %s missing %s", path, RW_MODULE_ENTRY_SYMBOL);
        dlclose(handle);
        return -1;
    }

    module = entry();

    if (init_dynamic_module(handle, module, path, cfg) != 0)
    {
        dlclose(handle);
        return -1;
    }

    return 0;
}

static int has_so_suffix(const char* name)
{
    size_t n = 0;

    if (!name)
    {
        return 0;
    }

    n = strlen(name);

    return n > 3 && strcmp(name + n - 3, ".so") == 0;
}

static int load_dynamic_module_dir(const char* dir_path, const rw_config_t* cfg)
{
    DIR* dir = NULL;
    struct dirent* de = NULL;
    int count = 0;

    if (!dir_path)
    {
        return 0;
    }

    dir = opendir(dir_path);

    if (!dir)
    {
        if (errno != ENOENT)
        {
            fprintf(stderr, "[warn] plugin dir %s unavailable: %s\n", dir_path, strerror(errno));
            rw_log_info("plugin dir %s unavailable: %s", dir_path, strerror(errno));
        }

        return 0;
    }

    while ((de = readdir(dir)) != NULL)
    {
        char path[1024];

        if (!has_so_suffix(de->d_name))
        {
            continue;
        }

        snprintf(path, sizeof(path), "%s/%s", dir_path, de->d_name);

        if (load_dynamic_module_file(path, cfg) == 0)
        {
            count++;
        }
    }

    closedir(dir);
    return count;
}

static int load_dynamic_modules_from_config(const rw_config_t* cfg)
{
    FILE* fp = NULL;
    char line[RW_MAX_MODULE_CONFIG_LINE];
    int count = 0;

    if (!cfg || !cfg->module_config_path)
    {
        return 0;
    }

    fp = fopen(cfg->module_config_path, "r");

    if (!fp)
    {
        return 0;
    }

    while (fgets(line, sizeof(line), fp))
    {
        char* p = trim(line);
        char* eq = NULL;

        if (*p == '\0' || *p == '#')
        {
            continue;
        }

        eq = strchr(p, '=');

        if (!eq)
        {
            continue;
        }

        *eq = '\0';

        char* key = trim(p);
        char* value = trim(eq + 1);

        if (strcmp(key, "plugin") == 0)
        {
            if (load_dynamic_module_file(value, cfg) == 0)
            {
                count++;
            }
        }
        else if (strcmp(key, "plugin_dir") == 0)
        {
            count += load_dynamic_module_dir(value, cfg);
        }
    }

    fclose(fp);
    return count;
}

int rw_modules_load_dynamic(const rw_config_t* cfg)
{
    int count = 0;

    if (!cfg || !cfg->enable_dynamic_plugins)
    {
        return 0;
    }

    count += load_dynamic_modules_from_config(cfg);
    count += load_dynamic_module_dir(cfg->plugin_dir, cfg);

    return count;
}

int rw_modules_init_all(const rw_config_t* cfg)
{
    int enabled_count = 0;

    for (size_t i = 0; i < g_module_count; i++)
    {
        rw_module_t* m = &g_modules[i];

        if (m->enabled && !m->enabled(cfg))
        {
            continue;
        }

        if (!builtin_config_enabled(cfg, m->name, 1))
        {
            rw_log_info("builtin module %s disabled by module config", m->name);
            continue;
        }

        if (!m->init)
        {
            continue;
        }

        if (m->init(m, cfg) != 0)
        {
            fprintf(stderr, "[warn] module %s unavailable: %s\n", m->name, strerror(errno));
            rw_log_info("module %s unavailable: %s", m->name, strerror(errno));
            continue;
        }

        m->initialized = 1;
        enabled_count++;

        printf("[ok] module %s enabled\n", m->name);
        rw_log_info("module %s enabled", m->name);
    }

    enabled_count += rw_modules_load_dynamic(cfg);

    return enabled_count;
}

void rw_modules_poll_all(const rw_config_t* cfg)
{
    for (size_t i = 0; i < g_module_count; i++)
    {
        rw_module_t* m = &g_modules[i];

        if (!m->initialized || !m->poll)
        {
            continue;
        }

        m->poll(m, cfg);
    }

    for (size_t i = 0; i < g_dynamic_module_count; i++)
    {
        rw_module_t* m = g_dynamic_modules[i].module;

        if (!m || !m->initialized || !m->poll)
        {
            continue;
        }

        m->poll(m, cfg);
    }
}

void rw_modules_shutdown_all(void)
{
    for (size_t i = 0; i < g_module_count; i++)
    {
        rw_module_t* m = &g_modules[i];

        if (!m->initialized || !m->shutdown)
        {
            continue;
        }

        m->shutdown(m);
        m->initialized = 0;
    }

    for (size_t i = 0; i < g_dynamic_module_count; i++)
    {
        rw_module_t* m = g_dynamic_modules[i].module;

        if (m && m->initialized && m->shutdown)
        {
            m->shutdown(m);
            m->initialized = 0;
        }

        if (g_dynamic_modules[i].handle)
        {
            dlclose(g_dynamic_modules[i].handle);
        }

        g_dynamic_modules[i].handle = NULL;
        g_dynamic_modules[i].module = NULL;
        g_dynamic_modules[i].path[0] = '\0';
    }

    g_dynamic_module_count = 0;
}

void rw_modules_print_active(void)
{
    int first = 1;

    for (size_t i = 0; i < g_module_count; i++)
    {
        rw_module_t* m = &g_modules[i];

        if (!m->initialized)
        {
            continue;
        }

        if (!first)
        {
            printf(", ");
        }

        printf("%s", m->name);
        first = 0;
    }

    for (size_t i = 0; i < g_dynamic_module_count; i++)
    {
        rw_module_t* m = g_dynamic_modules[i].module;

        if (!m || !m->initialized)
        {
            continue;
        }

        if (!first)
        {
            printf(", ");
        }

        printf("%s(dynamic)", m->name);
        first = 0;
    }

    if (first)
    {
        printf("none");
    }
}
