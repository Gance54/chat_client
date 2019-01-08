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
#include <arpa/inet.h>
#include <signal.h>

#include "log.h"

#define TCP_PORT_DEFAULT 8080
#define BUF_LEN_DEFAULT 256

static pthread_mutex_t g_sock_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct socket_fd {
    int fd;
    pthread_t thread_id;
    struct socket_fd *next;
} gfd = { -1, 0, NULL };

void get_client_ip(int fd, char *buf, size_t len) {
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(fd, (struct sockaddr *)&addr, &addr_size);
    inet_ntop(AF_INET, &addr.sin_addr, buf, (unsigned int)len);
}

static void release_sfd(struct socket_fd *sfd) {
    //TODO:
    //Add thread termination sfd->thread_id;
    close(sfd->fd);
    memset(sfd, 0xff, sizeof(struct socket_fd));
    free(sfd);
}

static void free_global_resources(void) {
    pthread_mutex_lock(&g_sock_mutex);
    while(gfd.next) {
        struct socket_fd *sfd = gfd.next;
        gfd.next = sfd->next;
        release_sfd(sfd);
    }
    pthread_mutex_unlock(&g_sock_mutex);
}

static int remove_global_fd(int fd) {
    struct socket_fd *sfd = &gfd;
    struct socket_fd *prev_sfd = sfd;

    while(sfd->next) {
        sfd = sfd->next;
        if (sfd->fd == fd)
        {
            pthread_mutex_lock(&g_sock_mutex);
            prev_sfd->next = sfd->next;
            release_sfd(sfd);
            pthread_mutex_unlock(&g_sock_mutex);
            return 0;
        }

        prev_sfd = sfd;
   }

   return -1;
}

/*
 * Decrypt function
 * */
static int decrypt(char *in, size_t in_len, char **out, size_t *out_len) {
    char *ptr;
    size_t len;
    len = in_len + 1;
    ptr = malloc(len);
    if(!ptr)
        return -1;

    memcpy(ptr, in, in_len);
    ptr[in_len] = '\0';

    *out = ptr;
    *out_len = len;

    return 0;
}

/*
 * Encrypt function
 * */
static int encrypt(char *in, size_t in_len, char **out, size_t *out_len) {
    char *ptr;
    size_t len;
    len = in_len + 1;
    ptr = malloc(len);
    if(!ptr)
        return -1;

    memcpy(ptr, in, in_len);
    ptr[in_len] = '\0';

    *out = ptr;
    *out_len = len;

    return 0;
}

static int accept_message(int socket_fd, char **buf, size_t *len) {
    char b[BUF_LEN_DEFAULT] = { 0, };
    ssize_t l = read(socket_fd, b, sizeof(b));
    if (l <= 0) {
        if(l)
            LOGE("Failed to read from socket %d", socket_fd);
        else
            LOGI("Connection from socket %d was closed by peer",
                socket_fd);
        return -1;
    }

    return decrypt(b, (size_t)l, buf, len);
}

static void *receiving_thread (void *vargp) {
    int socket_fd = *(int *)vargp;
    char *buf;
    size_t len;
    while (1) {
        if (accept_message(socket_fd, &buf, &len) == 0) {
            fprintf(stdout, ">>%s\n", buf);
            free(buf);
        }
        else {
            LOGI("Closing cosket %d", socket_fd);
            remove_global_fd(socket_fd);
            break;
        }
    }

    return NULL;
}

static int add_global_fd(int fd) {
    char ip_buf[64] = { 0, };
    struct socket_fd *sfd = &gfd;
    struct socket_fd *new_sfd = malloc(sizeof(gfd));
    if (!new_sfd)
        return -1;

    new_sfd->next = NULL;
    new_sfd->fd = fd;

    if (pthread_create(&new_sfd->thread_id, NULL,
                       receiving_thread, &new_sfd->fd)) {
        LOGE("Failed to create a thread.");
        close(fd);
        free(new_sfd);
        return -1;
    }

    while (sfd->next)
        sfd = sfd->next;

    pthread_mutex_lock(&g_sock_mutex);
    sfd->next = new_sfd;
    pthread_mutex_unlock(&g_sock_mutex);

    get_client_ip(new_sfd->fd, ip_buf, sizeof(ip_buf));

    LOGI("Connection established: socket -> %d, ip -> %s",
         new_sfd->fd, ip_buf);

    return 0;
}

static int tcp_connect(int fd, struct sockaddr* addr) {
    if (connect(fd, addr, sizeof(struct sockaddr_in))) {
        LOGE("Failed to connect, err = %s", strerror(errno));
        return -1;
    }

    if (add_global_fd(fd)) {
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
    if (add_global_fd(fd)) {
        LOGE("Can not add connection fd. Connection limit reached");
        return -1;
    }

    return 0;
}

static void *main_listener_thread (void *vargp) {
    int listening_fd = *(int*)vargp;

    while (1) {
        int session_fd = accept(listening_fd, NULL, NULL);
        if (session_fd <= 0) {
            LOGE("Failed to accept. something went wrong...");
            pthread_exit(NULL);
        }

        if (handle_input_connection(session_fd))
            close(session_fd);
    }
    return NULL;
}

static void write_broadcasting_message(char *buf, size_t len) {
    struct socket_fd *sfd = &gfd;

    // TODO:
    // better to create a working list
    // of sockfds under mutex, and then unlock it
    pthread_mutex_lock(&g_sock_mutex);
    while (sfd->next) {
        sfd = sfd->next;

        if(len != (size_t)write(sfd->fd, buf, len))
            LOGE("Something went wrong while sending message...");
    }
    pthread_mutex_unlock(&g_sock_mutex);
}

static void handle_broadcasting_mode(void) {
    fprintf(stdout, "You are in chat mode. Enter '-exit' to exit"
                    " the mode.\n");
    while (1) {
        char *buf;
        size_t len;
        char message[BUF_LEN_DEFAULT] = { 0, };
        fill_buf_from_stdin(message, sizeof(message));

        if (strstr(message, "-exit"))
            return;

        if (encrypt(message, strlen(message), &buf, &len)) {
            LOGE("Failed to encrypt message");
            continue;
        }

        write_broadcasting_message(message, strlen(message));
        free(buf);
    }
}

static void list_connections(void) {
    struct socket_fd *sfd = &gfd;
    int i = 0;
    // TODO:
    // better to create a working list
    // of sockfds under mutex, and then unlock it
    pthread_mutex_lock(&g_sock_mutex);
    while (sfd->next) {
        i++;
        char ip_buf[64] = { 0, };
        sfd = sfd->next;
        get_client_ip(sfd->fd, ip_buf, sizeof(ip_buf));
        fprintf(stdout, "Conection %d: socket -> %d, ip -> %s\n", i, sfd->fd, ip_buf);
    }
    pthread_mutex_unlock(&g_sock_mutex);
}

static void print_usage(void) {
    fprintf(stdout, "Chat commands:\n");
    fprintf(stdout, "    1 <x.x.x.x> - connect to another client "
                    "with ip x.x.x.x\n");
    fprintf(stdout, "    2 - switch to chat mode\n");
    fprintf(stdout, "    3 - see connections list\n");
    fprintf(stdout, "    0 - exit \n");
}

static int main_loop(void) {
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
                handle_broadcasting_mode();
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
                return 0;
        }
    }

out:
    return 0;
}

int main(void) {
    pthread_t m_listen_thread_id;
    int listener_fd = listener_start(TCP_PORT_DEFAULT);
    pthread_create(&m_listen_thread_id, NULL,
                   main_listener_thread, &listener_fd);

    main_loop();
    free_global_resources();
    close(listener_fd);

    return 0;
}
