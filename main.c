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
#include "crypto_helper.h"
#include "log.h"

#define TCP_PORT_DEFAULT 8080
#define BUF_LEN_DEFAULT 256
#define KEY_FILE_NAME_DEFAULT "/data/local/tmp/encrypted_key.dat"

/*static void dump_blob (char *buf, size_t len) {
    size_t i;
    LOGI("Dumping blob ----------------------");
    for (i = 0; i < len; i++) {
        fprintf(stdout, "%02x", buf[i]);
        if(i%8 == 7)
            fprintf(stdout, "\n");
    }
    LOGI("Blob dumped ------------------------");
}*/

static char gkey[32] = "01234567890123456789012345678901";

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
        if (sfd->fd == fd)  {
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
 * TODO: rewrite with a structure
 * TODO: refactor -> move closer to sending moment
 * */
static int decrypt(char *in, size_t in_len, char **out, size_t *out_len, char *key) {
    char *ptr;
    size_t len;
    char iv[AES_GCM_256_IV_LEN];
    char tag[AES_GCM_256_TAG_LEN];

    if (in_len < sizeof(iv) + sizeof(tag)) {
        LOGE("Too short message came. It can not be decrypted");
        return -1;
    }

    len = in_len - sizeof(tag) - sizeof(iv) + 1;
    ptr = *out ? *out : (char*)malloc(len);
    if(!ptr)
        return -1;

    memcpy(tag, in + in_len - sizeof(tag), sizeof(tag));
    in_len -= sizeof(tag);
    memcpy(iv, in + in_len - sizeof(iv), sizeof(iv));
    in_len -= sizeof(iv);

    if (EncryptDecrypt(MODE_DECRYPT, in, in_len, (char*)key, iv, tag, ptr, &len)) {
        LOGE("Failed to decrypt message");
        free(ptr);
        return -1;
    }

    ptr[len] = '\0';
    *out = ptr;
    *out_len = len + 1;

    return 0;
}

/*
 * Encrypt function
 * TODO: rewrite with a structure
 * TODO: refactor -> move closer to sending moment
 * */
static int encrypt(char *in, size_t in_len, char **out, size_t *out_len, char *key) {
    char *ptr;
    size_t len;
    char iv[AES_GCM_256_IV_LEN];
    char tag[AES_GCM_256_TAG_LEN];
    RAND_bytes((unsigned char*)iv, (int)sizeof(iv));
    len = in_len + AES_GCM_256_IV_LEN + AES_GCM_256_TAG_LEN;
    ptr = *out ? *out : (char*)malloc(len);
    if(!ptr)
        return -1;

    if (EncryptDecrypt(MODE_ENCRYPT, in, in_len, (char*)key, iv, tag, ptr, &len)) {
        LOGE("Failed to encrypt message");
        free(ptr);
        return -1;
    }

    memcpy(ptr + len, iv, sizeof(iv));
    len += sizeof(iv);
    memcpy(ptr + len, tag, sizeof(tag));
    len += sizeof(tag);

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
        return -2;
    }

    return decrypt(b, (size_t)l, buf, len, (char*)gkey);
}

static void *receiving_thread (void *vargp) {
    int socket_fd = *(int *)vargp;
    size_t len;
    int ret;
    while (1) {
        char *buf = NULL;
        ret = accept_message(socket_fd, &buf, &len);
        if ( ret == 0) {
            fprintf(stdout, ">>%s\n", buf);
            free(buf);
        }
        else if (ret == -1) {
            continue;
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
    char ip_buf[BUF_LEN_DEFAULT] = { 0, };
    struct socket_fd *sfd = &gfd;
    struct socket_fd *new_sfd = (struct socket_fd*)malloc(sizeof(gfd));
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
    char ip_buf[BUF_LEN_DEFAULT] = { 0, };

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
        char *buf = NULL;
        size_t len;
        char message[BUF_LEN_DEFAULT] = { 0, };
        fill_buf_from_stdin(message, sizeof(message));

        if (strstr(message, "-exit"))
            return;

        if (encrypt(message, strlen(message), &buf, &len, (char*)gkey)) {
            LOGE("Failed to encrypt message");
            continue;
        }

        write_broadcasting_message(buf, len);
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
        char ip_buf[BUF_LEN_DEFAULT] = { 0, };
        sfd = sfd->next;
        get_client_ip(sfd->fd, ip_buf, sizeof(ip_buf));
        fprintf(stdout, "Conection %d: socket -> %d, ip -> %s\n", i, sfd->fd, ip_buf);
    }
    pthread_mutex_unlock(&g_sock_mutex);
}

static void print_usage(void) {
    fprintf(stdout, "Chat commands:\n");
    fprintf(stdout, "    1 - connect to another client\n");
    fprintf(stdout, "    2 - switch to chat mode\n");
    fprintf(stdout, "    3 - see connections list\n");
    fprintf(stdout, "    4 - encrypt key and write to a file\n");
    fprintf(stdout, "    5 - decrypt key from file\n");
    fprintf(stdout, "    6 - set key manually\n");
    fprintf(stdout, "    10 - exit \n");
}

static int encrypt_and_write_key(char *key_data) {
    int ret = -1;
    FILE *pFile = NULL;
    char phrase[BUF_LEN_DEFAULT] = { 0, };
    char kek[SHA256_DEFAULT_SIZE] = { 0, };
    char *encrypted_key;
    size_t encrypted_key_len;
    size_t bytes_written;
    fprintf(stdout, "Please, write a passphrase for key encryption: ");
    fgets(phrase, sizeof(phrase), stdin);
    if(!SHA256((const uint8_t*)phrase, strlen(phrase), (uint8_t*)kek)) {
        LOGE("Failed to calculate hash for passphrase");
        return -1;
    }

    if (encrypt(key_data, AES_GCM_256_KEY_LEN, &encrypted_key, &encrypted_key_len, kek)) {
        LOGE("Failed to encrypt key");
        return -1;
    }

    pFile = fopen(KEY_FILE_NAME_DEFAULT, "wb");
    if (!pFile) {
        LOGE("Can not open file, error = %s", strerror(errno));
        goto out;
    }

    bytes_written = fwrite(encrypted_key, 1, encrypted_key_len, pFile);

    if (bytes_written != encrypted_key_len) {
        LOGE("Could not write key to a file. Wrote %zu, expected %zu. Error = %s",
             bytes_written, encrypted_key_len, strerror(errno));
        goto out;
    }

    ret = 0;

out:
    free(encrypted_key);
    if(pFile)
        fclose(pFile);

    return ret;
}

static int read_and_decrypt_key(char *key_data) {
    int ret = -1;
    FILE *pFile = NULL;
    char phrase[BUF_LEN_DEFAULT] = { 0, };
    char kek[SHA256_DEFAULT_SIZE] = { 0, };
    char encrypted_key[AES_GCM_256_KEY_LEN * 2];
    size_t encrypted_key_len;
    size_t decrypted_key_len;
    fprintf(stdout, "Please, write a passphrase for key encryption: ");
    fgets(phrase, sizeof(phrase), stdin);
    if(!SHA256((const uint8_t *)phrase, strlen(phrase), (uint8_t*)kek)) {
        LOGE("Failed to calculate hash for passphrase");
        return -1;
    }

    pFile = fopen(KEY_FILE_NAME_DEFAULT, "rb");
    if (!pFile) {
        LOGE("Can not open file, error = %s", strerror(errno));
        goto out;
    }

    fseek(pFile , 0 , SEEK_END);
    encrypted_key_len = (size_t)ftell(pFile);
    rewind (pFile);
    size_t bytes_read = fread(encrypted_key, 1, sizeof(encrypted_key), pFile);

    if (bytes_read != encrypted_key_len) {
        LOGE("Could not read key from file. Read %zu, expected = %zu Error = %s",
             bytes_read, encrypted_key_len, strerror(errno));
        goto out;
    }

    if (decrypt(encrypted_key, encrypted_key_len, &key_data, &decrypted_key_len, kek)) {
        LOGE("Failed to decrypt key");
        goto out;
    }

    ret = 0;
out:
    free(encrypted_key);
    if(pFile)
        fclose(pFile);

    return ret;
}

static void set_key_by_user(void) {
    char key_buf[AES_GCM_256_KEY_LEN] = { 0, };
    fprintf(stdout, "Enter the key:\n");
    fgets(key_buf, sizeof(key_buf), stdin);
    memcpy(gkey, key_buf, sizeof(gkey));
}

static int main_loop(void) {
    print_usage();
    while (1) {
        char buf[10] = { 0, };
        int cmd = -1;
        char *end;
        fprintf(stdout, "enter the command:\n");
        fgets(buf, sizeof(buf), stdin);
        cmd = (int)strtol(buf, &end, 10);
        switch (cmd) {
            case 1: {
                fprintf(stdout, "Enter IP: x.x.x.x\n");
                handle_output_connection_request();
                print_usage();
                break;
            }

            case 2: {
                handle_broadcasting_mode();
                break;
            }

            case 3: {
                list_connections();
                print_usage();
                break;
            }

            case 4: {
                if(encrypt_and_write_key(gkey)) {
                    LOGE("Failed to encrypt key and write to a file");
                }
                break;
            }

            case 5: {
                if (read_and_decrypt_key(gkey)) {
                    LOGE("Failed to decrypt read and decrypt key");
                }
                break;
            }

            case 6: {
                set_key_by_user();
                break;
             }

            case 10:
                goto out;

            case 0:
                continue;

            default:
                LOGE("Wrong command");
                print_usage();
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
