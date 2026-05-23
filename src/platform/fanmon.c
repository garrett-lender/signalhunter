#define _GNU_SOURCE
#include "signalhunter.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/fanotify.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/fanotify.h>
#include <unistd.h>

int rw_fanotify_init_backend(void)
{
    int fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
    if (fd < 0)
    {
        return -1;
    }

    uint64_t mask = FAN_OPEN_EXEC | FAN_OPEN | FAN_CLOSE_WRITE;
    if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, "/") < 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

static void fd_to_path(int fd, char* out, size_t out_len)
{
    char proc_path[128];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    if (rw_read_link_path(proc_path, out, out_len) != 0)
    {
        snprintf(out, out_len, "<unknown>");
    }
}

void rw_fanotify_poll(int fd, const rw_config_t* cfg)
{
    char buf[8192];

    while (1)
    {
        ssize_t len = read(fd, buf, sizeof(buf));
        if (len < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return;
            }
            perror("fanotify read");
            return;
        }
        if (len == 0)
        {
            return;
        }

        struct fanotify_event_metadata* md;
        for (md = (struct fanotify_event_metadata*)buf; FAN_EVENT_OK(md, len);
             md = FAN_EVENT_NEXT(md, len))
        {

            if (md->vers != FANOTIFY_METADATA_VERSION)
            {
                fprintf(stderr, "fanotify metadata version mismatch\n");
                return;
            }
            if (md->fd < 0)
            {
                continue;
            }

            char path[RW_MAX_PATH];
            fd_to_path(md->fd, path, sizeof(path));

            if ((md->mask & FAN_OPEN_EXEC) || rw_suspicious_path(path))
            {
                printf("\n[FILE] pid=%d mask=0x%llx path=%s\n", md->pid,
                       (unsigned long long)md->mask, path);
                rw_log_event("file pid=%d mask=0x%llx path=%s", md->pid,
                             (unsigned long long)md->mask, path);
                if (rw_suspicious_path(path))
                {
                    printf("  Reason: suspicious file path touched\n");
                    rw_log_alert("suspicious file path touched pid=%d path=%s mask=0x%llx", md->pid,
                                 path, (unsigned long long)md->mask);
                    rw_score_add(md->pid, NULL, NULL, cfg, "FILE", "suspicious file path touched",
                                 65);
                    if (rw_case_has(md->pid))
                        rw_case_event(md->pid, 65, cfg, "FILE_DETAIL", "path=%s mask=0x%llx", path,
                                      (unsigned long long)md->mask);
                    rw_scan_injection_pid(md->pid, 0, cfg);
                }
            }
            else if (cfg->verbose)
            {
                printf("\n[FILE] pid=%d mask=0x%llx path=%s\n", md->pid,
                       (unsigned long long)md->mask, path);
                rw_log_event("file pid=%d mask=0x%llx path=%s", md->pid,
                             (unsigned long long)md->mask, path);
            }

            close(md->fd);
        }
    }
}
