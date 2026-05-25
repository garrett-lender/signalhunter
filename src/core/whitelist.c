#define _GNU_SOURCE

#include "whitelist.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define RW_MAX_WHITELIST_RULES 256
#define RW_WHITELIST_VALUE_MAX 512

typedef enum
{
    RW_WL_COMM_EXACT = 0,
    RW_WL_COMM_CONTAINS,
    RW_WL_EXE_EXACT,
    RW_WL_EXE_PREFIX,
    RW_WL_EXE_CONTAINS,
    RW_WL_PID
} rw_whitelist_rule_type_t;

typedef struct
{
    rw_whitelist_rule_type_t type;
    char value[RW_WHITELIST_VALUE_MAX];
    int pid;
} rw_whitelist_rule_t;

static rw_whitelist_rule_t g_rules[RW_MAX_WHITELIST_RULES];
static size_t g_rule_count;
static char g_path[RW_MAX_PATH];
static time_t g_last_mtime;
static int g_loaded;

static int contains_ci(const char *haystack, const char *needle)
{
    size_t needle_len;

    if (!haystack || !needle)
    {
        return 0;
    }

    needle_len = strlen(needle);

    if (needle_len == 0)
    {
        return 1;
    }

    for (const char *p = haystack; *p; p++)
    {
        size_t i;

        for (i = 0; i < needle_len; i++)
        {
            unsigned char hc = (unsigned char)p[i];
            unsigned char nc = (unsigned char)needle[i];

            if (hc == 0)
            {
                return 0;
            }

            if (tolower(hc) != tolower(nc))
            {
                break;
            }
        }

        if (i == needle_len)
        {
            return 1;
        }
    }

    return 0;
}

static int starts_with(const char *s, const char *prefix)
{
    size_t n;

    if (!s || !prefix)
    {
        return 0;
    }

    n = strlen(prefix);

    return strncmp(s, prefix, n) == 0;
}

static void trim(char *s)
{
    char *end;
    char *start = s;

    if (!s)
    {
        return;
    }

    while (*start && isspace((unsigned char)*start))
    {
        start++;
    }

    if (start != s)
    {
        memmove(s, start, strlen(start) + 1);
    }

    end = s + strlen(s);

    while (end > s && isspace((unsigned char)end[-1]))
    {
        end--;
    }

    *end = '\0';
}

static void reset_rules(void)
{
    memset(g_rules, 0, sizeof(g_rules));
    g_rule_count = 0;
}

static int add_rule(rw_whitelist_rule_type_t type, const char *value)
{
    rw_whitelist_rule_t *r;

    if (g_rule_count >= RW_MAX_WHITELIST_RULES || !value || !*value)
    {
        return -1;
    }

    r = &g_rules[g_rule_count++];
    memset(r, 0, sizeof(*r));
    r->type = type;

    if (type == RW_WL_PID)
    {
        r->pid = atoi(value);
    }
    else
    {
        snprintf(r->value, sizeof(r->value), "%s", value);
    }

    return 0;
}

static void add_builtin_rules(void)
{
    /* Builtins reduce common JIT/browser noise but do not suppress evidence. */
    add_rule(RW_WL_COMM_CONTAINS, "firefox");
    add_rule(RW_WL_COMM_CONTAINS, "Web Content");
    add_rule(RW_WL_COMM_CONTAINS, "Isolated Web Co");
    add_rule(RW_WL_COMM_CONTAINS, "chrome");
    add_rule(RW_WL_COMM_CONTAINS, "chromium");
    add_rule(RW_WL_EXE_CONTAINS, "/firefox");
    add_rule(RW_WL_EXE_CONTAINS, "/chrome");
    add_rule(RW_WL_EXE_CONTAINS, "/chromium");
}

static int parse_rule_line(char *line)
{
    char *eq;
    char *key;
    char *value;

    trim(line);

    if (line[0] == '\0' || line[0] == '#')
    {
        return 0;
    }

    eq = strchr(line, '=');

    if (!eq)
    {
        return -1;
    }

    *eq = '\0';
    key = line;
    value = eq + 1;
    trim(key);
    trim(value);

    if (strcmp(key, "comm") == 0)
    {
        return add_rule(RW_WL_COMM_EXACT, value);
    }

    if (strcmp(key, "comm_contains") == 0)
    {
        return add_rule(RW_WL_COMM_CONTAINS, value);
    }

    if (strcmp(key, "exe") == 0)
    {
        return add_rule(RW_WL_EXE_EXACT, value);
    }

    if (strcmp(key, "exe_prefix") == 0)
    {
        return add_rule(RW_WL_EXE_PREFIX, value);
    }

    if (strcmp(key, "exe_contains") == 0)
    {
        return add_rule(RW_WL_EXE_CONTAINS, value);
    }

    if (strcmp(key, "pid") == 0)
    {
        return add_rule(RW_WL_PID, value);
    }

    return -1;
}

static int load_file(const char *path)
{
    FILE *fp;
    char line[1024];
    int loaded = 0;

    fp = fopen(path, "r");

    if (!fp)
    {
        return -1;
    }

    while (fgets(line, sizeof(line), fp))
    {
        if (parse_rule_line(line) == 0)
        {
            loaded++;
        }
    }

    fclose(fp);

    return loaded;
}

static int reload_rules(const rw_config_t *cfg, int force)
{
    struct stat st;
    const char *path;

    if (!cfg || !cfg->enable_whitelist)
    {
        reset_rules();
        return 0;
    }

    path = cfg->whitelist_path && *cfg->whitelist_path ? cfg->whitelist_path : "config/whitelist.conf";

    if (snprintf(g_path, sizeof(g_path), "%s", path) < 0)
    {
        return -1;
    }

    if (stat(path, &st) != 0)
    {
        if (!g_loaded || force)
        {
            reset_rules();
            add_builtin_rules();
            g_loaded = 1;
            rw_log_info("whitelist file unavailable, using builtin rules: %s", path);
        }

        return 0;
    }

    if (!force && g_loaded && st.st_mtime == g_last_mtime)
    {
        return 0;
    }

    reset_rules();
    add_builtin_rules();

    if (load_file(path) < 0)
    {
        rw_log_info("failed to load whitelist %s: %s", path, strerror(errno));
    }
    else
    {
        rw_log_info("whitelist loaded from %s rules=%zu", path, g_rule_count);
    }

    g_last_mtime = st.st_mtime;
    g_loaded = 1;

    return 0;
}

int rw_whitelist_init(const rw_config_t *cfg)
{
    g_loaded = 0;
    g_last_mtime = 0;
    g_path[0] = '\0';

    return reload_rules(cfg, 1);
}

void rw_whitelist_poll(const rw_config_t *cfg)
{
    static time_t last_check = 0;
    time_t now = time(NULL);

    if (now - last_check < 5)
    {
        return;
    }

    last_check = now;
    reload_rules(cfg, 0);
}

void rw_whitelist_shutdown(void)
{
    reset_rules();
    g_loaded = 0;
}

int rw_whitelist_match(int pid, const char *comm, const char *exe, char *why, size_t why_len)
{
    for (size_t i = 0; i < g_rule_count; i++)
    {
        rw_whitelist_rule_t *r = &g_rules[i];
        int matched = 0;

        switch (r->type)
        {
            case RW_WL_COMM_EXACT:
                matched = comm && strcmp(comm, r->value) == 0;
                break;
            case RW_WL_COMM_CONTAINS:
                matched = contains_ci(comm, r->value);
                break;
            case RW_WL_EXE_EXACT:
                matched = exe && strcmp(exe, r->value) == 0;
                break;
            case RW_WL_EXE_PREFIX:
                matched = starts_with(exe, r->value);
                break;
            case RW_WL_EXE_CONTAINS:
                matched = contains_ci(exe, r->value);
                break;
            case RW_WL_PID:
                matched = pid == r->pid;
                break;
            default:
                matched = 0;
                break;
        }

        if (matched)
        {
            if (why && why_len > 0)
            {
                snprintf(why, why_len, "rule_index=%zu type=%d value=%s", i, (int)r->type, r->type == RW_WL_PID ? "<pid>" : r->value);
            }

            return 1;
        }
    }

    return 0;
}
