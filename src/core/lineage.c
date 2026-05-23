#define _GNU_SOURCE

#include "lineage.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define RW_LINEAGE_MAX_NODES 8192
#define RW_LINEAGE_MAX_DEPTH 64

static rw_lineage_node_t g_nodes[RW_LINEAGE_MAX_NODES];
static size_t g_node_count;

static int is_numeric_name(const char* s)
{
    if (!s || !*s)
    {
        return 0;
    }

    for (; *s; s++)
    {
        if (!isdigit((unsigned char)*s))
        {
            return 0;
        }
    }

    return 1;
}

static rw_lineage_node_t* find_node(int pid)
{
    for (size_t i = 0; i < g_node_count; i++)
    {
        if (g_nodes[i].pid == pid)
        {
            return &g_nodes[i];
        }
    }

    return NULL;
}

static rw_lineage_node_t* create_node(int pid)
{
    if (pid <= 0 || g_node_count >= RW_LINEAGE_MAX_NODES)
    {
        return NULL;
    }

    rw_lineage_node_t* n = &g_nodes[g_node_count++];
    memset(n, 0, sizeof(*n));

    n->pid = pid;
    n->ppid = 0;
    n->first_seen = time(NULL);
    n->last_seen = n->first_seen;
    snprintf(n->comm, sizeof(n->comm), "%s", "<unknown>");
    snprintf(n->exe, sizeof(n->exe), "%s", "<unknown>");
    snprintf(n->cmdline, sizeof(n->cmdline), "%s", "<unknown>");

    return n;
}

static rw_lineage_node_t* get_or_create_node(int pid)
{
    rw_lineage_node_t* n = find_node(pid);
    if (n)
    {
        return n;
    }

    return create_node(pid);
}

static void add_child(int parent_pid, int child_pid)
{
    if (parent_pid <= 0 || child_pid <= 0 || parent_pid == child_pid)
    {
        return;
    }

    rw_lineage_node_t* parent = get_or_create_node(parent_pid);
    if (!parent)
    {
        return;
    }

    for (size_t i = 0; i < parent->child_count; i++)
    {
        if (parent->children[i] == child_pid)
        {
            return;
        }
    }

    if (parent->child_count < RW_LINEAGE_MAX_CHILDREN)
    {
        parent->children[parent->child_count++] = child_pid;
    }
}

static int read_proc_status(int pid, int* ppid, char* comm, size_t comm_len)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE* fp = fopen(path, "r");
    if (!fp)
    {
        return -1;
    }

    char line[512];
    int have_any = 0;

    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "Name:", 5) == 0)
        {
            char tmp[64] = {0};
            if (sscanf(line, "Name:%63s", tmp) == 1 && comm && comm_len > 0)
            {
                snprintf(comm, comm_len, "%s", tmp);
                have_any = 1;
            }
        }
        else if (strncmp(line, "PPid:", 5) == 0)
        {
            int tmp_ppid = 0;
            if (sscanf(line, "PPid:%d", &tmp_ppid) == 1 && ppid)
            {
                *ppid = tmp_ppid;
                have_any = 1;
            }
        }
    }

    fclose(fp);
    return have_any ? 0 : -1;
}

static void read_proc_cmdline(int pid, char* out, size_t out_len)
{
    if (!out || out_len == 0)
    {
        return;
    }

    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    FILE* fp = fopen(path, "rb");
    if (!fp)
    {
        snprintf(out, out_len, "%s", "<unavailable>");
        return;
    }

    size_t n = fread(out, 1, out_len - 1, fp);
    fclose(fp);

    if (n == 0)
    {
        snprintf(out, out_len, "%s", "<empty>");
        return;
    }

    out[n] = '\0';

    for (size_t i = 0; i < n; i++)
    {
        if (out[i] == '\0')
        {
            out[i] = ' ';
        }
    }
}

void rw_lineage_init(void)
{
    memset(g_nodes, 0, sizeof(g_nodes));
    g_node_count = 0;
}

void rw_lineage_observe_pid(int pid)
{
    if (pid <= 0)
    {
        return;
    }

    rw_lineage_node_t* n = get_or_create_node(pid);
    if (!n)
    {
        return;
    }

    int ppid = 0;
    char comm[64] = {0};
    char exe[RW_MAX_PATH] = {0};
    char cmdline[RW_LINEAGE_MAX_CMDLINE] = {0};

    if (read_proc_status(pid, &ppid, comm, sizeof(comm)) == 0)
    {
        if (comm[0])
        {
            snprintf(n->comm, sizeof(n->comm), "%s", comm);
        }

        if (ppid > 0)
        {
            n->ppid = ppid;
            add_child(ppid, pid);
        }
    }

    rw_read_exe_path(pid, exe, sizeof(exe));
    if (exe[0] && strcmp(exe, "<unknown>") != 0)
    {
        snprintf(n->exe, sizeof(n->exe), "%s", exe);
    }

    read_proc_cmdline(pid, cmdline, sizeof(cmdline));
    if (cmdline[0])
    {
        snprintf(n->cmdline, sizeof(n->cmdline), "%s", cmdline);
    }

    n->last_seen = time(NULL);
}

void rw_lineage_refresh_procfs(void)
{
    DIR* proc = opendir("/proc");
    if (!proc)
    {
        return;
    }

    struct dirent* de;
    while ((de = readdir(proc)) != NULL)
    {
        if (!is_numeric_name(de->d_name))
        {
            continue;
        }

        rw_lineage_observe_pid(atoi(de->d_name));
    }

    closedir(proc);
}

void rw_lineage_record_fork(int parent_pid, int child_pid)
{
    rw_lineage_node_t* child = get_or_create_node(child_pid);
    if (!child)
    {
        return;
    }

    child->ppid = parent_pid;
    child->last_seen = time(NULL);

    add_child(parent_pid, child_pid);
    rw_lineage_observe_pid(parent_pid);
    rw_lineage_observe_pid(child_pid);
}

void rw_lineage_record_exec(int pid)
{
    rw_lineage_node_t* n = get_or_create_node(pid);
    if (!n)
    {
        return;
    }

    n->exec_seen = time(NULL);
    rw_lineage_observe_pid(pid);
}

void rw_lineage_record_exit(int pid, int exit_code)
{
    rw_lineage_node_t* n = get_or_create_node(pid);
    if (!n)
    {
        return;
    }

    n->exited = 1;
    n->exit_code = exit_code;
    n->exit_seen = time(NULL);
    n->last_seen = n->exit_seen;
}

const rw_lineage_node_t* rw_lineage_get(int pid)
{
    return find_node(pid);
}

static void write_node_line(FILE* fp, const rw_lineage_node_t* n)
{
    if (!fp || !n)
    {
        return;
    }

    fprintf(fp, "%d\t%d\t%s\t%s\t%s\t%ld\t%ld\t%ld\t%d\t%d\n", n->pid, n->ppid, n->comm, n->exe,
            n->cmdline, (long)n->first_seen, (long)n->last_seen, (long)n->exec_seen, n->exited,
            n->exit_code);
}

static void write_ancestor_tree(FILE* fp, int pid, int depth)
{
    if (!fp || depth > RW_LINEAGE_MAX_DEPTH)
    {
        return;
    }

    const rw_lineage_node_t* n = rw_lineage_get(pid);
    if (!n)
    {
        for (int i = 0; i < depth; i++)
        {
            fprintf(fp, "    ");
        }
        fprintf(fp, "%d <unknown>\n", pid);
        return;
    }

    if (n->ppid > 0)
    {
        write_ancestor_tree(fp, n->ppid, depth + 1);
    }

    for (int i = 0; i < depth; i++)
    {
        fprintf(fp, "    ");
    }

    fprintf(fp, "pid=%d ppid=%d comm=%s exe=%s%s\n", n->pid, n->ppid, n->comm, n->exe,
            n->exited ? " [exited]" : "");
}

static int is_ancestor_of(int ancestor_pid, int pid)
{
    int guard = 0;
    const rw_lineage_node_t* cur = rw_lineage_get(pid);

    while (cur && guard++ < RW_LINEAGE_MAX_DEPTH)
    {
        if (cur->pid == ancestor_pid)
        {
            return 1;
        }

        if (cur->ppid <= 0)
        {
            break;
        }

        cur = rw_lineage_get(cur->ppid);
    }

    return 0;
}

static int case_root_for_pid(int pid)
{
    int root = pid;
    int guard = 0;
    const rw_lineage_node_t* cur = rw_lineage_get(pid);

    while (cur && guard++ < RW_LINEAGE_MAX_DEPTH)
    {
        if (cur->ppid <= 1)
        {
            break;
        }

        const rw_lineage_node_t* parent = rw_lineage_get(cur->ppid);

        if (!parent)
        {
            break;
        }

        root = parent->pid;
        cur = parent;
    }

    return root;
}

int rw_lineage_is_related(int case_pid, int pid)
{
    if (case_pid <= 0 || pid <= 0)
    {
        return 0;
    }

    if (case_pid == pid)
    {
        return 1;
    }

    int root = case_root_for_pid(case_pid);

    if (root == pid)
    {
        return 1;
    }

    if (is_ancestor_of(pid, case_pid))
    {
        return 1;
    }

    if (is_ancestor_of(root, pid))
    {
        return 1;
    }

    return 0;
}

static void write_manifest_header(FILE* fp)
{
    fprintf(fp,
            "pid\tppid\tcomm\texe\tcmdline\tfirst_seen\tlast_seen\texec_seen\texited\texit_code\n");
}

static void write_family_tree(FILE* fp, int pid, int depth)
{
    const rw_lineage_node_t* n = rw_lineage_get(pid);

    if (!fp || !n || depth > RW_LINEAGE_MAX_DEPTH)
    {
        return;
    }

    for (int i = 0; i < depth; i++)
    {
        fprintf(fp, "    ");
    }

    fprintf(fp, "%s pid=%d ppid=%d comm=%s exe=%s%s\n", depth == 0 ? "" : "└──", n->pid, n->ppid,
            n->comm, n->exe, n->exited ? " [exited]" : "");

    for (size_t i = 0; i < n->child_count; i++)
    {
        write_family_tree(fp, n->children[i], depth + 1);
    }
}

int rw_lineage_write_case(int pid, const char* case_dir)
{
    if (pid <= 0 || !case_dir || !*case_dir)
    {
        return -1;
    }

    rw_lineage_refresh_procfs();
    rw_lineage_observe_pid(pid);

    int root = case_root_for_pid(pid);

    char path[RW_MAX_PATH];
    int n = snprintf(path, sizeof(path), "%s/lineage.tsv", case_dir);

    if (n < 0 || (size_t)n >= sizeof(path))
    {
        return -1;
    }

    FILE* tsv = fopen(path, "w");

    if (tsv)
    {
        write_manifest_header(tsv);

        for (size_t i = 0; i < g_node_count; i++)
        {
            if (rw_lineage_is_related(pid, g_nodes[i].pid))
            {
                write_node_line(tsv, &g_nodes[i]);
            }
        }

        fclose(tsv);
    }

    n = snprintf(path, sizeof(path), "%s/tree_manifest.tsv", case_dir);

    if (n < 0 || (size_t)n >= sizeof(path))
    {
        return -1;
    }

    FILE* manifest = fopen(path, "w");

    if (manifest)
    {
        write_manifest_header(manifest);

        for (size_t i = 0; i < g_node_count; i++)
        {
            if (rw_lineage_is_related(pid, g_nodes[i].pid))
            {
                write_node_line(manifest, &g_nodes[i]);
            }
        }

        fclose(manifest);
    }

    n = snprintf(path, sizeof(path), "%s/process_tree.txt", case_dir);

    if (n < 0 || (size_t)n >= sizeof(path))
    {
        return -1;
    }

    FILE* tree = fopen(path, "w");

    if (tree)
    {
        fprintf(tree, "Process tree for case pid %d\n", pid);
        fprintf(tree, "=============================\n\n");
        fprintf(tree, "Case root pid: %d\n", root);
        fprintf(tree, "Suspicious pid: %d\n\n", pid);
        fprintf(tree, "Family tree observed by SignalHunter:\n");
        write_family_tree(tree, root, 0);
        fprintf(tree, "\nAncestor chain for suspicious pid:\n");
        write_ancestor_tree(tree, pid, 0);
        fclose(tree);
    }

    return 0;
}
