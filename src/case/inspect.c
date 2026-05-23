#define _GNU_SOURCE
#include "signalhunter.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static void print_proc_file_text(int pid, const char* name, int nul_to_space)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);

    FILE* fp = fopen(path, "rb");
    if (!fp)
    {
        printf("%s: <unavailable>\n", name);
        return;
    }

    printf("%s: ", name);
    int c;
    while ((c = fgetc(fp)) != EOF)
    {
        if (nul_to_space && c == '\0')
        {
            c = ' ';
        }
        putchar(c);
    }
    putchar('\n');
    fclose(fp);
}

void rw_dump_process_exe(int pid)
{
    char src[128];
    char dump_name[128];

    snprintf(src, sizeof(src), "/proc/%d/exe", pid);
    snprintf(dump_name, sizeof(dump_name), "pid_%d_exe.dump", pid);

    if (rw_copy_file(src, dump_name) == 0)
    {
        printf("\nDumped executable: %s\n", dump_name);
        rw_log_event("dumped executable pid=%d path=%s", pid, dump_name);
        char hash[65];
        if (rw_sha256_file(dump_name, hash) == 0)
        {
            printf("SHA256: %s\n", hash);
            rw_log_event("dumped executable hash pid=%d sha256=%s", pid, hash);
        }
    }
    else
    {
        printf("\nDumped executable: failed: %s\n", strerror(errno));
        rw_log_event("dump executable failed pid=%d error=%s", pid, strerror(errno));
    }
}

static void inspect_fds(int pid)
{
    char fd_dir[128];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);

    DIR* dir = opendir(fd_dir);
    if (!dir)
    {
        printf("\nFDs: <unavailable>\n");
        return;
    }

    printf("\nFDs:\n");
    struct dirent* de;
    while ((de = readdir(dir)) != NULL)
    {
        if (de->d_name[0] == '.')
        {
            continue;
        }
        char fd_path[RW_MAX_PATH];
        char target[RW_MAX_PATH];
        snprintf(fd_path, sizeof(fd_path), "%s/%s", fd_dir, de->d_name);
        if (rw_read_link_path(fd_path, target, sizeof(target)) == 0)
        {
            printf("  %-4s -> %s\n", de->d_name, target);
        }
    }
    closedir(dir);
}

static void inspect_maps(int pid)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE* fp = fopen(path, "r");
    if (!fp)
    {
        printf("\nMaps: <unavailable>\n");
        return;
    }

    printf("\nMemory maps:\n");
    char line[1024];
    int count = 0;
    while (fgets(line, sizeof(line), fp))
    {
        printf("  %s", line);
        if (++count >= 80)
        {
            printf("  ... truncated ...\n");
            break;
        }
    }
    fclose(fp);
}

void rw_inspect_process(int pid)
{
    char path[128];
    char exe[RW_MAX_PATH];
    char cwd[RW_MAX_PATH];
    char root[RW_MAX_PATH];

    printf("\nSignalHunter process inspection\n");
    printf("=============================\n");
    printf("PID: %d\n", pid);

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    if (rw_read_link_path(path, exe, sizeof(exe)) == 0)
    {
        printf("exe: %s\n", exe);
    }
    else
    {
        printf("exe: <unavailable>\n");
    }

    snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
    printf("cwd: %s\n", rw_read_link_path(path, cwd, sizeof(cwd)) == 0 ? cwd : "<unavailable>");

    snprintf(path, sizeof(path), "/proc/%d/root", pid);
    printf("root: %s\n", rw_read_link_path(path, root, sizeof(root)) == 0 ? root : "<unavailable>");

    print_proc_file_text(pid, "cmdline", 1);
    print_proc_file_text(pid, "status", 0);

    rw_dump_process_exe(pid);
    inspect_fds(pid);
    inspect_maps(pid);

    printf("\nInjection scan:\n");
    rw_scan_injection_pid(pid, 1, NULL);
}
