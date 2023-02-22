#include <arpa/inet.h>
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

#define BUFFER_SIZE 100
#define DATA_PATH "/var/tmp/aesdsocketdata"

int32_t socket_fd;

static void signal_handler(int signal_number) {
  syslog(LOG_INFO, "Caught signal, exiting");
  remove(DATA_PATH);
  shutdown(socket_fd, SHUT_RDWR);
}

int main(int argc, char *argv[]) {
  int32_t opt = 0;
  int32_t sockflgs = 1;
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
  if (listen(socket_fd, 5)) {
    printf("listen failed: %m\n");
    goto fail;
  }

  // doing this so late because we want to be sure first that
  // port 9000 is free
  while ((opt = getopt(argc, argv, "dh")) != -1)
    switch (opt) {
    case 'd':
      syslog(LOG_INFO, "Daemonizing...");
	  daemon(0,0);
      break;
    case '?':
    case 'h':
      printf("Usage: %s [-d]\n-d Run as daemon\n", argv[0]);
	  exit(0);
      break;
    default:
      break;
    }

  FILE *data_fd = fopen(DATA_PATH, "a+");
  if (data_fd == NULL) {
    printf("Could not open data file: %m\n");
    goto fail;
  }
  while (1) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd = accept(socket_fd, (struct sockaddr *)&addr, &addr_len);
    if (client_fd < 0) {
      printf("accept failed: %m\n");
      goto fail;
    }
    char client_addr[INET_ADDRSTRLEN] = "";
    inet_ntop(AF_INET, &(addr.sin_addr), client_addr, INET_ADDRSTRLEN);
    syslog(LOG_INFO, "Accepted connection from %s", client_addr);

    char *msgbuf = malloc(sizeof(char));
    *msgbuf = '\0';
    int buf_size = 1;
    while (1) {
      char recv_buf[BUFFER_SIZE + 1];
      int recvd = recv(client_fd, recv_buf, BUFFER_SIZE, 0);
      if (recvd == -1) {
        syslog(LOG_ERR, "Error receiving: %m");
        close(client_fd);
        goto fail;
      } else if (!recvd) {
        syslog(LOG_INFO, "Closed connection from %s", client_addr);
        break;
      }
      recv_buf[recvd] = '\0';
      char *str = recv_buf;
      char *token = strsep(&str, "\n");
      if (str == NULL) {
        // haven't found the \n yet, there is more dta to come
        buf_size += recvd;
        msgbuf = realloc(msgbuf, buf_size * sizeof(char));
        strncat(msgbuf, token, recvd);
      } else {
        buf_size += strlen(token);
        msgbuf = realloc(msgbuf, buf_size * sizeof(char));
        strcat(msgbuf, token);
        syslog(LOG_INFO, "Received packet: %s", msgbuf);

        // write packetbuffer to file
        if (fprintf(data_fd, "%s\n", msgbuf) < 0) {
          syslog(LOG_ERR, "Error writing to file: %m");
          goto fail1;
        }
        // go to start of file
        if (fseek(data_fd, 0, SEEK_SET) != 0) {
          syslog(LOG_ERR, "Error seeking file: %m");
          goto fail1;
        }

        char *line = NULL;
        size_t line_len = 0;
        ssize_t num_read;

        // send to client
        while ((num_read = getline(&line, &line_len, data_fd)) != -1) {
          if (send(client_fd, line, num_read, MSG_NOSIGNAL) == -1) {
            syslog(LOG_ERR, "Error sending: %m");
            goto fail1;
          }
        }
        free(line);

        // write the data from to next packet at beginning of msgbuf
        buf_size = strlen(str) + 1;
        msgbuf = realloc(msgbuf, buf_size * sizeof(char));
        strcpy(msgbuf, str);
      }
    }
  }

fail1:
  fclose(data_fd);
  remove(DATA_PATH);
fail:
  close(socket_fd);
  exit(-1);
}
