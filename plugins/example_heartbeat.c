#include "module.h"

#include <stdio.h>
#include <time.h>

static int heartbeat_init(rw_module_t *module, const rw_config_t *cfg)
{
    (void)cfg;

    module->fd = -1;
    module->state = NULL;
    rw_log_info("example heartbeat plugin initialized");
    return 0;
}

static void heartbeat_poll(rw_module_t *module, const rw_config_t *cfg)
{
    static time_t last = 0;
    time_t now = time(NULL);

    (void)module;
    (void)cfg;

    if (now - last >= 30)
    {
        rw_log_event("plugin=example_heartbeat status=alive time=%ld", (long)now);
        last = now;
    }
}

static void heartbeat_shutdown(rw_module_t *module)
{
    (void)module;
    rw_log_info("example heartbeat plugin shutdown");
}

static rw_module_t g_module = {
    .name = "example_heartbeat",
    .initialized = 0,
    .fd = -1,
    .state = NULL,
    .enabled = NULL,
    .init = heartbeat_init,
    .poll = heartbeat_poll,
    .shutdown = heartbeat_shutdown,
    .abi_version = RW_MODULE_ABI_VERSION,
};

rw_module_t *signalhunter_module(void)
{
    return &g_module;
}
