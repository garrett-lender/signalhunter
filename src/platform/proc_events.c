#define _GNU_SOURCE
#include "signalhunter.h"

#include <errno.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int rw_proc_events_init(void)
{
  int fd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK, NETLINK_CONNECTOR);
  if (fd < 0)
  {
    return -1;
  }

  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_groups = CN_IDX_PROC;
  sa.nl_pid = (unsigned int)getpid();

  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
  {
    close(fd);
    return -1;
  }

  struct
  {
    struct nlmsghdr nl;
    struct cn_msg cn;
    enum proc_cn_mcast_op op;
  } msg;
  memset(&msg, 0, sizeof(msg));

  msg.nl.nlmsg_len = sizeof(msg);
  msg.nl.nlmsg_type = NLMSG_DONE;
  msg.nl.nlmsg_flags = 0;
  msg.nl.nlmsg_seq = 0;
  msg.nl.nlmsg_pid = (unsigned int)getpid();
  msg.cn.id.idx = CN_IDX_PROC;
  msg.cn.id.val = CN_VAL_PROC;
  msg.cn.len = sizeof(enum proc_cn_mcast_op);
  msg.op = PROC_CN_MCAST_LISTEN;

  if (send(fd, &msg, sizeof(msg), 0) < 0)
  {
    close(fd);
    return -1;
  }

  return fd;
}

void rw_proc_events_poll(int fd, const rw_config_t *cfg)
{
  (void)cfg;
  char buf[4096];

  while (1)
  {
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        return;
      }
      perror("proc connector recv");
      return;
    }
    if (n == 0)
    {
      return;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    for (; NLMSG_OK(nlh, (unsigned int)n); nlh = NLMSG_NEXT(nlh, n))
    {
      struct cn_msg *cn = NLMSG_DATA(nlh);
      struct proc_event *ev = (struct proc_event *)cn->data;

      switch (ev->what)
      {
      case PROC_EVENT_EXEC:
        rw_lineage_record_exec(ev->event_data.exec.process_pid);
        rw_event_addf(ev->event_data.exec.process_pid, "proc", "exec pid=%d tgid=%d",
                      ev->event_data.exec.process_pid,
                      ev->event_data.exec.process_tgid);
        printf("\n[PROC] exec pid=%d tgid=%d\n",
               ev->event_data.exec.process_pid,
               ev->event_data.exec.process_tgid);
        rw_log_event("proc exec pid=%d tgid=%d",
                     ev->event_data.exec.process_pid,
                     ev->event_data.exec.process_tgid);
        rw_scan_injection_pid(ev->event_data.exec.process_pid, 0, cfg);
        break;
      case PROC_EVENT_FORK:
        rw_lineage_record_fork(ev->event_data.fork.parent_pid,
                               ev->event_data.fork.child_pid);
        rw_event_addf(ev->event_data.fork.child_pid, "proc", "fork parent=%d child=%d",
                      ev->event_data.fork.parent_pid,
                      ev->event_data.fork.child_pid);
        if (cfg->verbose)
        {
          printf("\n[PROC] fork parent=%d child=%d\n",
                 ev->event_data.fork.parent_pid, ev->event_data.fork.child_pid);
          rw_log_event("proc fork parent=%d child=%d",
                       ev->event_data.fork.parent_pid,
                       ev->event_data.fork.child_pid);
        }
        break;
      case PROC_EVENT_EXIT:
        rw_lineage_record_exit(ev->event_data.exit.process_pid,
                               (int)ev->event_data.exit.exit_code);
        rw_event_addf(ev->event_data.exit.process_pid, "proc", "exit pid=%d code=%u",
                      ev->event_data.exit.process_pid,
                      ev->event_data.exit.exit_code);
        if (cfg->verbose)
        {
          printf("\n[PROC] exit pid=%d code=%u\n",
                 ev->event_data.exit.process_pid,
                 ev->event_data.exit.exit_code);
          rw_log_event("proc exit pid=%d code=%u",
                       ev->event_data.exit.process_pid,
                       ev->event_data.exit.exit_code);
        }
        break;
      case PROC_EVENT_UID:
        printf("\n[PROC] uid change pid=%d uid=%u euid=%u\n",
               ev->event_data.id.process_pid, ev->event_data.id.r.ruid,
               ev->event_data.id.e.euid);
        rw_log_event("proc uid-change pid=%d uid=%u euid=%u",
                     ev->event_data.id.process_pid, ev->event_data.id.r.ruid,
                     ev->event_data.id.e.euid);
        break;
      case PROC_EVENT_GID:
        printf("\n[PROC] gid change pid=%d gid=%u egid=%u\n",
               ev->event_data.id.process_pid, ev->event_data.id.r.rgid,
               ev->event_data.id.e.egid);
        rw_log_event("proc gid-change pid=%d gid=%u egid=%u",
                     ev->event_data.id.process_pid, ev->event_data.id.r.rgid,
                     ev->event_data.id.e.egid);
        break;
      default:
        break;
      }
    }
  }
}
