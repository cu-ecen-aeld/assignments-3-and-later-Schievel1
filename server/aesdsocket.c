#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "queue.h"
#include <pthread.h>
#include <stdbool.h>

#define BUFFER_SIZE 100
#define USE_AESD_CHAR_DEVICE 1
#if USE_AESD_CHAR_DEVICE==1
#define DATA_PATH "/dev/aesdchar"
#else
#define DATA_PATH "/var/tmp/aesdsocketdata"
#endif
#define MAX_ACCEPT 10

int32_t socket_fd;

typedef TAILQ_HEAD(head_s, node_s) head_t;

typedef enum { accept_t, join_t, recv_t, send_t } thread_type_t;
typedef struct node_s {
  pthread_t thread_id;
  bool thread_completed;
  thread_type_t thread_type;
  int fd;
  char ip_addr[INET6_ADDRSTRLEN];
  TAILQ_ENTRY(node_s) nodes;
} node_t;
typedef struct {
  bool trigger;
  bool free_address_info;
  bool disarm_alarm;
  struct addrinfo *host_addr_info;
  int serverfd;
  bool free_serverfd;
  pthread_mutex_t mutex;
  int connection_count;
  timer_t timer;
  struct itimerspec itime;
} s_data_t;
typedef struct {
  char time[100];
} time_str_s;
typedef struct {
  bool q_empty;
  bool q_full;
  uint32_t tail;
  uint32_t head;
  time_str_s t_str[MAX_ACCEPT];
} queue_s;
static uint32_t nextPtr(uint32_t ptr) { return ((ptr + 1) & (MAX_ACCEPT - 1)); }
queue_s q;
static int dequeue(char *buf) {
  if (q.q_empty) {
    return -1;
  }
  strncpy(buf, q.t_str[q.head].time, 80);
  q.head = nextPtr(q.head);
  q.q_full = false;
  if (q.tail == q.head) {
    q.q_empty = true;
  }
  return 0;
}

s_data_t s_data;
#define BUFFER_STD_SIZE 256
static int write_data(int fd, char *string, int write_len) {
  ssize_t ret;
  while (write_len != 0) {
    ret = write(fd, string, write_len);
    if (ret == 0) {
      break;
    }
    if (ret == -1) {
      if (errno == EINTR) {
        continue;
      }
      syslog(LOG_ERR, "write error %m\n");
      return -1;
    }
    write_len -= ret;
    string += ret;
  }
  return 0;
}
static int echo_file_socket(int fd, int acceptfd) {
  ssize_t ret;
  char write_str[BUFFER_STD_SIZE];
  while (1) {
    memset(write_str, 0, sizeof(write_str));
    ret = read(fd, write_str, sizeof(write_str));
    if (ret == 0) {
      break;
    }
    if (ret == -1) {
      if (errno == EINTR) {
        continue;
      }
      syslog(LOG_ERR, "read error %m\n");
      return -1;
    }
    int num_bytes_to_send = ret;
    int num_bytes_sent = 0;
    int str_index = 0;
    while (num_bytes_to_send > 0) {
      num_bytes_sent =
          send(acceptfd, &write_str[str_index], num_bytes_to_send, 0);
      if (num_bytes_sent == -1) {
        syslog(LOG_ERR, "send error %m\n");
        return -1;
      }
      num_bytes_to_send -= num_bytes_sent;
      str_index += num_bytes_sent;
    }
  }
  return 0;
}
static void *threadfn(void *thread_param) {
  char *buffer;
  int file_fd;
  int recv_bytes = 0, start_ptr = 0, read_bytes = 0;
  int buffer_length = 0, buffer_capacity = 0;
  int status = 0;
  node_t *thread_params = (node_t *)thread_param;
  while (1) {
    switch (thread_params->thread_type) {
    case recv_t:
      if (buffer_capacity == buffer_length) {
        if (buffer_capacity == 0) {
          buffer = malloc(BUFFER_STD_SIZE);
          if (buffer == NULL) {
            goto free_socket_fd;
          }
        } else {
          int new_len = buffer_capacity + BUFFER_STD_SIZE;
          char *new_buffer;
          new_buffer = realloc(buffer, new_len);
          if (!new_buffer) {
            free(buffer);
            goto free_mem;
          }
          buffer = new_buffer;
        }
        buffer_capacity += BUFFER_STD_SIZE;
      }
      recv_bytes = 0;
      recv_bytes = recv(thread_params->fd, (buffer + buffer_length),
                        (buffer_capacity - buffer_length), 0);
      if (recv_bytes == -1) {
        syslog(LOG_ERR, "Recv: %m");
        goto free_mem;
      } else if (recv_bytes > 0) {
        thread_params->thread_type = send_t;
      } else if (recv_bytes == 0) {
        goto free_mem;
      }
      break;
    case send_t:
      read_bytes = ((buffer_length - start_ptr) + recv_bytes);
      int temp_read_var = read_bytes;
      char *ptr;
      for (ptr = &buffer[start_ptr]; temp_read_var > 0;
           ptr++, temp_read_var--) {
        if (*ptr == '\n') {
          temp_read_var--;
          status = pthread_mutex_lock(&s_data.mutex);
          if (status != 0) {
            syslog(LOG_ERR, "Mutex Lock: %m");
            goto free_mem;
          }
          file_fd = open(DATA_PATH, O_RDWR | O_CREAT | O_APPEND,
                         0777);
          if (file_fd == -1) {
            syslog(LOG_ERR, "Open: %m");
            goto unlock_mutex;
          }

          int newline_data = (read_bytes - temp_read_var);
          if (write_data(file_fd, &buffer[start_ptr], newline_data) == -1) {
            goto close_filefd;
          }
          lseek(file_fd, 0, SEEK_SET);

          if (echo_file_socket(file_fd, thread_params->fd) == -1) {
            goto close_filefd;
          }
          char time_str[80];

          if (dequeue(time_str) == 0) {
            if (write_data(file_fd, time_str, strlen(time_str)) != -1) {
              newline_data += strlen(time_str);
            }
          }
          start_ptr = newline_data;
          close(file_fd);
          status = pthread_mutex_unlock(&s_data.mutex);
          if (status != 0) {
            syslog(LOG_ERR, "Mutex Unlock %m");
            goto unlock_mutex;
          }
          break;
        }
      }
      buffer_length += recv_bytes;
      thread_params->thread_type = recv_t;
      break;

    case accept_t:
      break;
    case join_t:
      break;
    }
  }
close_filefd:
  close(file_fd);
unlock_mutex:
  pthread_mutex_unlock(&s_data.mutex);
free_mem:
  free(buffer);
free_socket_fd:
  close(thread_params->fd);
  thread_params->thread_completed = true;
  syslog(LOG_DEBUG, "Closed connection from %s", thread_params->ip_addr);
  return 0;
}

static void signal_handler(int signal_number) { s_data.trigger = true; }

#if USE_AESD_CHAR_DEVICE==0
static void alarm_handler() {
  time_t rawtime;
  struct tm *info;
  char time_val[40];
  char buffer[80];
  time(&rawtime);

  info = localtime(&rawtime);

  strftime(time_val, 40, "%Y/%m/%d - %H:%M:%S", info);
  sprintf(buffer, "timestamp: %s \n", time_val);
  if (q.q_full) {
    exit(-1);
  }
  strncpy(q.t_str[q.tail].time, buffer, 80);
  q.tail = nextPtr(q.tail);
  q.q_empty = false;
  if (q.tail == q.head) {
    q.q_full = true;
  }
}
#endif // USE_AESD_CHAR_DEVICE==0
static void shutdown_function() {
  syslog(LOG_INFO, "Caught signal, exiting");
  remove(DATA_PATH);
  shutdown(socket_fd, SHUT_RDWR);
  exit(1);
}

static void queue_init() {
  q.q_full = false;
  q.q_empty = true;
  q.tail = 0;
  q.head = 0;
}
static void socket_init() {
  s_data.free_address_info = false;
  s_data.free_serverfd = false;
  s_data.trigger = false;
  s_data.disarm_alarm = false;
  s_data.host_addr_info = NULL;
  pthread_mutex_init(&s_data.mutex, NULL);
  s_data.connection_count = 0;
}

int main(int argc, char *argv[]) {
  int32_t opt = 0;
  int32_t sockflgs = 1;
  int32_t ret;
  thread_type_t thread_type;
  queue_init();
  socket_init();
  struct addrinfo myaddrinfoin = {.ai_flags = AI_PASSIVE,
                                  .ai_family = PF_INET,
                                  .ai_socktype = SOCK_STREAM,
                                  .ai_protocol = 0,
                                  .ai_addrlen = 0,
                                  .ai_addr = NULL,
                                  .ai_canonname = NULL,
                                  .ai_next = NULL};
  struct addrinfo *myaddrinfo;

  openlog(NULL, 0, LOG_USER);

  struct sigaction saction;
  memset(&saction, 0, sizeof(saction));
  saction.sa_handler = signal_handler;
  if (sigaction(SIGTERM, &saction, NULL) != 0) {
    syslog(LOG_ERR, "Error registering SIGTERM: %m");
  }
  if (sigaction(SIGINT, &saction, NULL) != 0) {
    syslog(LOG_ERR, "Error registering SIGINT: %m");
  }
#if USE_AESD_CHAR_DEVICE==0
  saction.sa_handler = alarm_handler;
  if (sigaction(SIGALRM, &saction, NULL) != 0) {
    syslog(LOG_ERR, "Error registering SIGALRM: %m");
  }
#endif//  USE_AESD_CHAR_DEVICE==0

  socket_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    printf("Socket could not be created: %m\n");
    exit(-1);
  }
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &sockflgs,
                 sizeof(sockflgs))) {
    printf("Could not set socket options: %m\n");
    goto fail;
  }
  if (getaddrinfo(NULL, "9000", &myaddrinfoin, &myaddrinfo)) {
    printf("gettaddrinfo failed: %m\n");
    freeaddrinfo(myaddrinfo);
    goto fail;
  }
  if (bind(socket_fd, myaddrinfo->ai_addr, sizeof(struct sockaddr)) < 0) {
    printf("bind failed: %m\n");
    goto fail;
  }
  freeaddrinfo(myaddrinfo);
  if (listen(socket_fd, 10)) {
    printf("listen failed: %m\n");
    goto fail;
  }

  // doing this so late because we want to be sure first that
  // port 9000 is free
  while ((opt = getopt(argc, argv, "dh")) != -1)
    switch (opt) {
    case 'd':
      syslog(LOG_INFO, "Daemonizing...");
      daemon(0, 0);
      break;
    case '?':
    case 'h':
      printf("Usage: %s [-d]\n-d Run as daemon\n", argv[0]);
      exit(0);
      break;
    default:
      break;
    }


#if USE_AESD_CHAR_DEVICE==0
  ret = timer_create(CLOCK_REALTIME, NULL, &s_data.timer);
  if (ret == -1) {
    syslog(LOG_ERR, "timer create error %m\n");
    return -1;
  }
  s_data.itime.it_interval.tv_sec = 10;
  s_data.itime.it_interval.tv_nsec = 0;
  s_data.itime.it_value.tv_sec = 10;
  s_data.itime.it_value.tv_nsec = 0;
  ret = timer_settime(s_data.timer, 0, &s_data.itime, NULL);
  if (ret == -1) {
    syslog(LOG_ERR, "timer_settime error %m\n");
    return -1;
  }
#endif // USE_AESD_CHAR_DEVICE==0

  s_data.disarm_alarm = true;
  head_t head;
  TAILQ_INIT(&head);

  if (s_data.trigger) {
    thread_type = join_t;
  } else {
    thread_type = accept_t;
  }

  struct sockaddr_in addr;
  socklen_t addr_len;
  int client_fd;

  while (1) {
    switch (thread_type) {
    case accept_t:
      addr_len = sizeof(addr);
      client_fd = accept(socket_fd, (struct sockaddr *)&addr, &addr_len);
      if (client_fd < 0) {
        syslog(LOG_INFO, "accept failed: %m\n");
        thread_type = join_t;
        break;
      }
      char client_addr[INET_ADDRSTRLEN] = "";
      inet_ntop(AF_INET, &(addr.sin_addr), client_addr, INET_ADDRSTRLEN);
      syslog(LOG_INFO, "Accepted connection from %s", client_addr);

      node_t *node = NULL;
      node = malloc(sizeof(node_t));
      if (node == NULL) {
        syslog(LOG_ERR, "malloc error %m\n");
        thread_type = join_t;
        break;
      }
      node->thread_completed = false;
      node->thread_type = recv_t;
      node->fd = client_fd;
      strcpy(node->ip_addr, client_addr);
      ret = pthread_create(&node->thread_id, (void *)0, threadfn, node);
      if (ret != 0) {
        free(node);
        syslog(LOG_ERR, "malloc error %m\n");
        thread_type = join_t;
        break;
      }
      TAILQ_INSERT_TAIL(&head, node, nodes);
      s_data.connection_count++;
      node = NULL;
      thread_type = join_t;
      break;

    case join_t:
      if (s_data.connection_count > 0) {
        node_t *var = NULL;
        node_t *tvar = NULL;
        TAILQ_FOREACH_SAFE(var, &head, nodes, tvar) {
          if (var->thread_completed) {
            TAILQ_REMOVE(&head, var, nodes);
            pthread_join(var->thread_id, NULL);
            free(var);
            var = NULL;
            s_data.connection_count--;
          }
        }
      }
      if (s_data.connection_count == 0) {
        char time_val_buf[80];
        if (dequeue(time_val_buf) == 0) {
          ret = pthread_mutex_trylock(&s_data.mutex);
          if (ret == 0) {
            int fd = open(DATA_PATH, O_WRONLY | O_CREAT | O_APPEND,
                          0777);
            if (fd != -1) {
              printf("File desc %d\n", fd);
              write_data(fd, time_val_buf, strlen(time_val_buf));
              close(fd);
            }
            pthread_mutex_unlock(&s_data.mutex);
          }
        }
      }
      if (s_data.trigger) {
        if (s_data.connection_count == 0) {
          shutdown_function();
        } else {
          break;
        }
      }
      thread_type = accept_t;
      break;
    case send_t:
      break;
    case recv_t:
      break;
    }
  }

fail:
  remove(DATA_PATH);
  close(socket_fd);
  exit(-1);
}
