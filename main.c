#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "log.h"

#define TCP_PORT_DEFAULT 80
#define BUF_LEN_DEFAULT 256

static struct socket_fd {
    int fd;
    pthread_t thread_id;
    struct socket_fd *next;
} gfd = { -1, 0, NULL };

static int add_global_fd(int fd, pthread_t thread_id) {
    struct socket_fd *sfd = &gfd;
    struct socket_fd *new_sfd = malloc(sizeof(gfd));
    if (!new_sfd)
        return -1;

    new_sfd->fd = fd;
    new_sfd->thread_id = thread_id;
    new_sfd->next = NULL;

    while (sfd->next)
        sfd = sfd->next;

    sfd->next = new_sfd;

    return 0;
}

/*static int remove_global_fd(int fd) {
    struct socket_fd *sfd = &gfd;
    struct socket_fd *prev_sfd = sfd;

    while(sfd->next) {
        sfd = sfd->next;
        if (sfd->fd == fd)
        {
            prev_sfd->next = sfd->next;
            free(sfd);
            return 0;
        }

        prev_sfd = sfd;
   }

   return -1;
}*/

static void print_usage(void) {
    fprintf(stdout, "Chat commands:\n");
    fprintf(stdout, "    1 <x.x.x.x> - connect to another client with ip x.x.x.x\n");
    fprintf(stdout, "    2 <message text> - write a broadcasting message\n");
    fprintf(stdout, "    3 - see connections list\n");
    fprintf(stdout, "    0 - exit input mode\n");
}

static void *receiving_thread (void *vargp) {
    char buf[BUF_LEN_DEFAULT] = { 0, };
    int socket_fd = *(int*)vargp;

    while(1)
        if(read(socket_fd, buf, sizeof(buf)) > 0)
            fprintf(stdout, "Received message: %s\n", buf);

    return NULL;
}

static int tcp_connect(int fd, struct sockaddr* addr) {
    pthread_t thread_id;

    if (connect(fd, addr, sizeof(struct sockaddr_in))) {
        LOGE("Failed to connect, err = %s", strerror(errno));
        return -1;
    }

    if (pthread_create(&thread_id, NULL, receiving_thread, &fd)) {
        LOGE("Failed to create a thread.");
        close(fd);
        return -1;
    }

    if (add_global_fd(fd, thread_id)) {
        LOGE("Failed to add tcp connection FD.");
        close(fd);
        return -1;
    }

    return 0;
}

/*
 * Establish tcp connection and returns 0 on success, or -1 onerror
 */
static int init_tcp_connection(char *ip, int port) {
    struct sockaddr_in sockaddrin;
    struct hostent *host;
    if (ip[0] == ' ')
        ip++;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        LOGE("Socket Error %s", strerror(errno));
        return -1;
    }

    host = gethostbyname(ip);
    if (host == NULL) {
        LOGE("|%s| - unknown host.", ip);
        return -1;
    }

    sockaddrin.sin_family = AF_INET;
    sockaddrin.sin_port = htons(port);
    memcpy(&sockaddrin.sin_addr, host->h_addr, host->h_length);

    if (tcp_connect(fd, (struct sockaddr*) &sockaddrin)) {
        LOGE("Failed to tcp connect");
        close(fd);
        return -1;
    }

    LOGI("Connection established with %s on socket %d", ip, fd);

    return 0;
}

/*
 * Starts listener and return listener fd of -1 on error
 */
static int listener_start(int port) {
    int fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOGE("socket error = %s", strerror(errno));
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOGE("bind error = %s", strerror(errno));
        goto err;
    }

    if (listen(fd, 10)) {
        LOGE("listen err = %s", strerror(errno));
        goto err;
    }

    return fd;

err:
    close (fd);
    return -1;
}

static void fill_buf_from_stdin(char *buf, size_t size) {
    fgets(buf, (int)size, stdin);

    /* replace endline for 0 if present */
    buf[strlen(buf) - 1] = 0;
}

static void handle_output_connection_request(void) {
    char ip_buf[64] = { 0, };

    fill_buf_from_stdin(ip_buf, sizeof(ip_buf));

    if (init_tcp_connection(ip_buf, TCP_PORT_DEFAULT) < 0)
        LOGE("Failed to connect to %s", ip_buf);
}

static int handle_input_connection(int fd) {
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, receiving_thread, &fd)) {
        LOGE("Failed to create a thread.");
        close(fd);
        return -1;
    }

    if (add_global_fd(fd, thread_id)) {
        LOGE("Can not add connection fd. Connection limit reached");
        return -1;
    }

    return 0;
}

static void *main_listener_thread (void *vargp) {
    int listening_fd = *(int*)vargp;
    struct sockaddr_in addr;
    socklen_t addrlen;
    while (1) {
        LOGD("accepting on %d...", listening_fd);
        int session_fd = accept(listening_fd, (struct sockaddr*)&addr, &addrlen);
        LOGI("Accepted connection. Fd = %d", session_fd);
        if (handle_input_connection(session_fd))
            close(session_fd);
    }
    return NULL;
}

static void write_broadcasting_message(char *buf, size_t len) {
    struct socket_fd *sfd = &gfd;

    while (sfd->next) {
        sfd = sfd->next;

        if(len != (size_t)write(sfd->fd, buf, len))
            LOGE("Something went wrong while sending message...");
    }
}

static void handle_broadcasting_message() {
    char message[BUF_LEN_DEFAULT] = { 0, };
    fill_buf_from_stdin(message, sizeof(message));
    write_broadcasting_message(message, strlen(message));
}

static void list_connections(void) {
    struct socket_fd *sfd = &gfd;

    while (sfd->next) {
        sfd = sfd->next;
        fprintf(stdout, "Connsction for socket %d\n", sfd->fd);
    }
}

static int input_loop(void) {
    fprintf(stdout, "You have started input mode.\n");
    print_usage();
    while (1) {
        int cmd = -1;
        fprintf(stdout, "enter the command:\n");
        scanf("%d", &cmd);
        switch (cmd) {
            case 1: {
                handle_output_connection_request();
                break;
            }

            case 2: {
                handle_broadcasting_message();
                break;
            }

            case 3: {
                list_connections();
                break;
            }

            case 0:
                goto out;

            default:
                LOGE("Wrong command");
                print_usage();
                break;
        }
    }
out:
    fprintf(stdout, "You have finished input mode.\n");
    return 0;
}

static int main_loop(void)
{
    fprintf(stdout, " You are in a read-only mode.\n");
    fprintf(stdout, " Commands: i - input mode; e - exit. You choice:\n");
    while (1) {
        char input = getchar();
        if (input=='i')
        {
            input_loop();
            fprintf(stdout, " You are back in readonly mode.\n");
            fprintf(stdout, " Commands: i - input mode; e - exit. You choice:\n");
        }
        else if (input == 'e')
            break;
    }
    return 0;
}

int main(void) {

    pthread_t m_listen_thread_id;
    int listener_fd = listener_start(TCP_PORT_DEFAULT);
    LOGD("Start listening on fd %d", listener_fd);
    pthread_create(&m_listen_thread_id, NULL, main_listener_thread, &listener_fd);
    main_loop();

    pthread_join(m_listen_thread_id, NULL);

    return 0;
}
