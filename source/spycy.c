#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdnoreturn.h>
#include <stdbool.h>
#include <assert.h>

#include <sqlite3.h>

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

volatile sig_atomic_t quit = 0;

#define FAIL(reason)                            \
  do {                                          \
    perror("ERROR: " reason);                   \
    goto exit;                                  \
  } while (0)

typedef struct {
  uint64_t start_time_ns;
  char executable_path[PATH_MAX];
} process_info_t;

typedef struct {
  pid_t key;
  process_info_t value;
} item_t;

item_t*  pids = NULL;

int pid_to_executable_path(pid_t pid, char executable_path[PATH_MAX]) {
  static char symlink_path[PATH_MAX];
  snprintf(symlink_path, PATH_MAX, "/proc/%d/exe", pid);

  int executable_path_len = readlink(symlink_path, executable_path, PATH_MAX);
  if (executable_path_len != -1) {
    executable_path[executable_path_len] = 0;
  }
  return executable_path_len;
}

void handle_exec_event(struct proc_event *event) {
  (void) event;
  assert(event->what == PROC_EVENT_EXEC);

  pid_t pid = event->event_data.exec.process_pid;

  pid_t index = -1;
  if ((index = hmgeti(pids, pid)) >= 0) {
    hmdel(pids, pid);
  }

  static process_info_t new_process_info = {};
  new_process_info.start_time_ns = event->timestamp_ns;
  if (pid_to_executable_path(pid, new_process_info.executable_path) == -1) {
    fprintf(stderr, "ERROR: failed to readlink on /proc/%d/exe: %s\n", pid, strerror(errno));
    return;
  }

  hmput(pids, pid, new_process_info);
}

void handle_exit_event(struct proc_event *event) {
  (void) event;
  assert(event->what == PROC_EVENT_EXIT);

  pid_t pid = event->event_data.exec.process_pid;

  item_t* item = hmgetp_null(pids, pid);
  if (item == NULL) {
    return;
  }

  uint64_t execution_time_ns = event->timestamp_ns - item->value.start_time_ns;
  printf("%d %s %.3fs\n", pid, item->value.executable_path, execution_time_ns / 1e9);
  assert(hmdel(pids, pid) == 1);
}

void handle_message(struct cn_msg *message) {
  (void) message;
  struct proc_event *event = (struct proc_event *)message->data;

  if (event->what == PROC_EVENT_EXEC) {
    handle_exec_event(event);
  } else if (event->what == PROC_EVENT_EXIT) {
    handle_exit_event(event);
  }
}

int main(int argc, char** argv) {
  (void) argc;
  (void) argv;

  int code = 0;

  int connection = -1;
  if ((connection = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR)) == -1) {
    FAIL("socket");
  }

  struct sockaddr_nl my = {
    .nl_family = AF_NETLINK,
    .nl_groups = CN_IDX_PROC,
    .nl_pid = getpid(),
  };

  struct sockaddr_nl kernel = {
    .nl_family = AF_NETLINK,
    .nl_groups = CN_IDX_PROC,
    .nl_pid = 1,
  };

  if (bind(connection, (struct sockaddr *)&my, sizeof(my)) == -1) {
    FAIL("bind");
  }

  static uint8_t buffer[1024] = {};
  memset(buffer, 0, sizeof(buffer));

  struct nlmsghdr *netlink_header = (struct nlmsghdr *) buffer;
  struct cn_msg *message_header = (struct cn_msg *) NLMSG_DATA(netlink_header);

  enum proc_cn_mcast_op *message_operation = (enum proc_cn_mcast_op *) &message_header->data[0];
  *message_operation = PROC_CN_MCAST_LISTEN;

  netlink_header->nlmsg_len = NLMSG_LENGTH(sizeof(*message_header) + sizeof(*message_operation));
  netlink_header->nlmsg_type = NLMSG_DONE;
  netlink_header->nlmsg_flags = 0;
  netlink_header->nlmsg_seq = 0;
  netlink_header->nlmsg_pid = getpid();

  message_header->id.idx = CN_IDX_PROC;
  message_header->id.val = CN_VAL_PROC;
	message_header->seq = 0;
	message_header->ack = 0;
	message_header->len = sizeof(*message_operation);

  if (send(connection, netlink_header, netlink_header->nlmsg_len, 0) != netlink_header->nlmsg_len) {
    FAIL("send");
  }

  if (*message_operation == PROC_CN_MCAST_IGNORE) {
    goto exit;
  }

  while (!quit) {
    struct cn_msg* message = (struct cn_msg *) (buffer + sizeof(struct nlmsghdr));
    struct proc_event* event = (struct proc_event *) (buffer + sizeof(struct nlmsghdr) + sizeof(struct cn_msg));
    struct nlmsghdr* header = (struct nlmsghdr *) buffer;

    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_nl from = kernel;
    socklen_t from_len = sizeof (from);
    size_t received_len = recvfrom(connection, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_len);
    if (from.nl_pid != 0 || received_len < 1) {
      continue;
    }

    if (event->what == PROC_EVENT_NONE) {
      continue;
    }

    static uint32_t seqs[4096] = {};
    if (seqs[event->cpu] && message->seq != seqs[event->cpu] + 1) {
      fprintf(stderr, "ERROR: out of order message on cpu %d\n", event->cpu);
    }
    seqs[event->cpu] = message->seq;

    while (NLMSG_OK(header, received_len)) {
      if (header->nlmsg_type == NLMSG_NOOP) {
        continue;
      }

      if (header->nlmsg_type == NLMSG_ERROR ||
          header->nlmsg_type == NLMSG_OVERRUN) {
        break;
      }

      handle_message(NLMSG_DATA(header));

      if (header->nlmsg_type == NLMSG_DONE) {
        break;
      }
      header = NLMSG_NEXT(header, received_len);
    }
  }

 exit:
  if (connection != -1) close(connection);
  return code;
}
