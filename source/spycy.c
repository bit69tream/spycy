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
    code = 1;                                   \
    destruct();                                 \
  } while (0)

#define SQLITE3_FAIL(...)                       \
  do {                                          \
    fprintf(stderr, __VA_ARGS__);               \
    code = 1;                                   \
    destruct();                                 \
  } while (0)

typedef struct {
  uint64_t start_time_ns;
  char executable_path[PATH_MAX];
  uid_t uid;
} process_info_t;

typedef struct {
  pid_t key;
  process_info_t value;
} item_t;

typedef struct {
  char* key;
  uint64_t value;
} counter_map_t;

item_t* pids = NULL;
counter_map_t* pid_counts = NULL;

sqlite3* db = NULL;
int connection = -1;

int code = 0;

bool should_close = false;

uint64_t last_timestamp_ns = 0;

void destruct();

int get_executable_path(pid_t pid, char executable_path[PATH_MAX]) {
  static char symlink_path[PATH_MAX];
  snprintf(symlink_path, PATH_MAX, "/proc/%d/exe", pid);

  int executable_path_len = readlink(symlink_path, executable_path, PATH_MAX);
  if (executable_path_len != -1) {
    executable_path[executable_path_len] = 0;
  }
  return executable_path_len;
}

uid_t uid_by_pid(pid_t pid) {
  struct stat info = {};

  static char proc_path[128] = {};
  snprintf(proc_path, 128, "/proc/%d", pid);

  if (stat(proc_path, &info) == -1) {
    FAIL("stat");
  }

  return info.st_uid;
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
  if (get_executable_path(pid, new_process_info.executable_path) == -1) {
    fprintf(stderr, "WARNING: failed to readlink on /proc/%d/exe: %s\n", pid, strerror(errno));
    return;
  }
  new_process_info.uid = uid_by_pid(pid);

  hmput(pids, pid, new_process_info);

  item_t* new_item = hmgetp_null(pids, pid);
  assert(new_item != NULL);

  counter_map_t* counter = shgetp_null(pid_counts, new_item->value.executable_path);
  if (counter != NULL) {
    counter->value++;
  } else {
    shput(pid_counts, new_item->value.executable_path, 1);
  }
}

bool exists_in_db(char* executable_path, char* username) {
  assert(db != NULL);

  sqlite3_stmt* select_statement = NULL;
  int rc = sqlite3_prepare(db,
                           "select exists "
                           "(select 1 from spycy_data "
                           " where executable_path = ? and "
                           "       username = ?)",
                           -1, &select_statement, NULL);
  if (rc != SQLITE_OK) {
    SQLITE3_FAIL("ERROR: failed to prepare select statement: %s\n", sqlite3_errmsg(db));
  }

  if (((rc = sqlite3_bind_text(select_statement, 1, executable_path, -1, SQLITE_STATIC)) != SQLITE_OK) ||
      ((rc = sqlite3_bind_text(select_statement, 2, username, -1, SQLITE_STATIC)) != SQLITE_OK)) {
    SQLITE3_FAIL("ERROR: failed to bind select statement: %s\n", sqlite3_errstr(rc));
  }

  int step = sqlite3_step(select_statement);
  bool result = false;
  if (step == SQLITE_ROW) {
    result = sqlite3_column_int(select_statement, 0);
  }

  sqlite3_finalize(select_statement);
  return result;
}

void update_executable(uint64_t execution_time_ns, char* executable_path, char* username) {
  assert(db != NULL);

  sqlite3_stmt* update_statement = NULL;
  int rc = sqlite3_prepare_v2(db,
                              "update spycy_data "
                              "set nanoseconds_spent = nanoseconds_spent + ? "
                              "where executable_path = ? and username = ?;",
                              -1, &update_statement, NULL);
  if (rc != SQLITE_OK) {
    SQLITE3_FAIL("ERROR: failed to prepare update statement: %s\n", sqlite3_errmsg(db));
  }

  if (((rc = sqlite3_bind_int64(update_statement, 1, execution_time_ns)) != SQLITE_OK) ||
      ((rc = sqlite3_bind_text(update_statement, 2, executable_path, -1, SQLITE_STATIC)) != SQLITE_OK) ||
      ((rc = sqlite3_bind_text(update_statement, 3, username, -1, SQLITE_STATIC)) != SQLITE_OK)) {
    SQLITE3_FAIL("ERROR: failed to bind update statement: %s\n", sqlite3_errstr(rc));
  }

  while (sqlite3_step(update_statement) != SQLITE_DONE) ;
  sqlite3_finalize(update_statement);
}

void insert_executable(uint64_t execution_time_ns, char* executable_path, char* username) {
  assert(db != NULL);

  sqlite3_stmt* insert_statement = NULL;

  int rc = sqlite3_prepare_v2(db,
                              "insert into spycy_data (executable_path, nanoseconds_spent, username) "
                              "values (?, ?, ?)",
                              -1, &insert_statement, NULL);
  if (rc != SQLITE_OK) {
    SQLITE3_FAIL("ERROR: failed to prepare insert statement: %s\n", sqlite3_errmsg(db));
  }


  if (((rc = sqlite3_bind_text(insert_statement, 1, executable_path, -1, SQLITE_STATIC)) != SQLITE_OK) ||
      ((rc = sqlite3_bind_int64(insert_statement, 2, execution_time_ns)) != SQLITE_OK) ||
      ((rc = sqlite3_bind_text(insert_statement, 3, username, -1, SQLITE_STATIC)) != SQLITE_OK)) {
    SQLITE3_FAIL("ERROR: failed to bind insert statement: %s\n", sqlite3_errstr(rc));
  }

  while (sqlite3_step(insert_statement) != SQLITE_DONE) ;
  sqlite3_finalize(insert_statement);
}

void save_to_db(uint64_t execution_time_ns, char* executable_path, uid_t uid) {
  assert(db != NULL);

  struct passwd* passwd = getpwuid(uid);
  assert(passwd != NULL);

  if (exists_in_db(executable_path, passwd->pw_name)) {
    update_executable(execution_time_ns, executable_path, passwd->pw_name);
  } else {
    insert_executable(execution_time_ns, executable_path, passwd->pw_name);
  }

  if (should_close) {
    destruct();
  }
}

void destruct() {
  if (sqlite3_is_interrupted(db)) {
    should_close = true;

    if (connection != -1) {
      close(connection);
    }

    return;
  }

  if (connection != -1) {
    close(connection);
  }

  for (size_t i = 0; i < hmlenu(pids); i++) {
    uint64_t execution_time_ns = last_timestamp_ns - pids[i].value.start_time_ns;
    save_to_db(execution_time_ns, pids[i].value.executable_path, pids[i].value.uid);
  }

  hmfree(pids);
  shfree(pid_counts);

  if (sqlite3_close(db) != SQLITE_OK) {
    should_close = true;
    return;
  }

  exit(code);
}

void handle_exit_event(struct proc_event *event) {
  (void) event;
  assert(event->what == PROC_EVENT_EXIT);

  pid_t pid = event->event_data.exec.process_pid;

  item_t* item = hmgetp_null(pids, pid);
  if (item == NULL) {
    return;
  }

  counter_map_t* counter = shgetp_null(pid_counts, item->value.executable_path);
  assert(counter != NULL);

  counter->value--;
  if (counter->value == 0) {
    uint64_t execution_time_ns = event->timestamp_ns - item->value.start_time_ns;
    save_to_db(execution_time_ns, item->value.executable_path, item->value.uid);
  }

  assert(hmdel(pids, pid) == 1);
}

void handle_message(struct cn_msg *message) {
  (void) message;
  struct proc_event *event = (struct proc_event *)message->data;

  last_timestamp_ns = event->timestamp_ns;

  if (event->what == PROC_EVENT_EXEC) {
    handle_exec_event(event);
  } else if (event->what == PROC_EVENT_EXIT) {
    handle_exit_event(event);
  }
}

char* default_data_home() {
  struct passwd *passwd = getpwuid(getuid());
  if (passwd == NULL) {
    FAIL("getpwuid");
  }

  static char data_home_path[PATH_MAX] = {};
  snprintf(data_home_path, PATH_MAX, "%s/.local/share/", passwd->pw_dir);
  return data_home_path;
}

void recursive_mkdir(char* path) {
  char* separator = strrchr(path, '/');

  if (separator == path) {
    separator = strrchr(path + 1, '/');
  }

  if (separator != NULL) {
    *separator = 0;
    recursive_mkdir(path);
    *separator = '/';
  }

  if (mkdir(path, 0777) && errno != EEXIST) {
    FAIL("mkdir");
  }
}

char* default_db_path() {
  char* xdg_data_home = getenv("XDG_DATA_HOME");
  if (xdg_data_home == NULL) {
    xdg_data_home = default_data_home();
  }

  assert(xdg_data_home != NULL);

  static char db_path[PATH_MAX] = {};
  snprintf(db_path, PATH_MAX, "%s/spycy/", xdg_data_home);

  recursive_mkdir(db_path);

  snprintf(db_path, PATH_MAX, "%s/spycy/spycy.db", xdg_data_home);

  return db_path;
}

void signal_handler(int asdf) {
  (void) asdf;
  destruct();
}

void prepare_db() {
  assert(db != NULL);

  char* error_message = NULL;
  sqlite3_exec(db,
               "create table if not exists spycy_data ("
               " executable_path text not null unique,"
               " nanoseconds_spent integer not null,"
               " username text not null,"
               " primary key(executable_path)"
               ");",
               NULL, NULL, &error_message);

  if (error_message != NULL) {
    fprintf(stderr, "ERROR: failed to prepare database: %s\n", error_message);
    sqlite3_free(error_message);
    code = 1;
    destruct();
  }
}

int main(int argc, char** argv) {
  char* db_path = NULL;

  if (argc > 2) {
    fprintf(stderr, "USAGE: %s <path to database file>\n", argv[0]);
  } else if (argc == 2) {
    db_path = argv[1];
  } else {
    db_path = default_db_path();
  }

  if (sqlite3_open(db_path, &db)) {
    SQLITE3_FAIL("ERROR: failed to open database: %s\n", sqlite3_errmsg(db));
  }

  printf("LOG: using database %s\n.", db_path);

  prepare_db();

  if ((connection = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR)) == -1) {
    FAIL("socket");
  }

  if (signal(SIGINT, signal_handler) == SIG_ERR || signal(SIGTERM, signal_handler) == SIG_ERR) {
    FAIL("signal");
  }

  struct sockaddr_nl my = {
    .nl_family = AF_NETLINK,
    .nl_groups = CN_IDX_PROC,
    .nl_pid = getpid(),
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
    code = 2;
    destruct();
  }

  while (!quit) {
    if (should_close) {
      break;
    }

    struct cn_msg* message = (struct cn_msg *) (buffer + sizeof(struct nlmsghdr));
    struct proc_event* event = (struct proc_event *) (buffer + sizeof(struct nlmsghdr) + sizeof(struct cn_msg));
    struct nlmsghdr* header = (struct nlmsghdr *) buffer;

    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_nl from = {
      .nl_family = AF_NETLINK,
      .nl_groups = CN_IDX_PROC,
      .nl_pid = 1,
    };

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

  destruct();
}
