// OUTDATED

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define TEST_SOCKET_PATH "/tmp/wrist-hello-auth-test.sock"

const char SERVER_RESPONSE_VERIFIED[10] = {0x02, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0x00};
const char SERVER_RESPONSE_UNVERIFIED[10] = {0x01, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00};

extern int auth_via_socket(char* socket_path);

static const char* g_response = SERVER_RESPONSE_VERIFIED;
static int g_server_fd = -1;

void stop_server(void) {
    if (g_server_fd == -1) return;

    shutdown(g_server_fd, SHUT_RDWR);
    close(g_server_fd);
    g_server_fd = -1;
}

void* server_thread(void* arg) {
    g_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TEST_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    unlink(TEST_SOCKET_PATH);
    int is_success = bind(g_server_fd, (struct sockaddr*)&addr, sizeof(addr));
    if (is_success == -1) {
        printf("bind() failed\n");
        stop_server();
        return NULL;
    }
    listen(g_server_fd, 1);

    *(int*)arg = 1;

    while (1) {
        int client_fd = accept(g_server_fd, NULL, NULL);
        if (client_fd == -1) break;

        write(client_fd, g_response, 10);
        close(client_fd);
    }

    unlink(TEST_SOCKET_PATH);
    return NULL;
}

int main(void) {
    int ready = 0;
    pthread_t th;
    pthread_create(&th, NULL, server_thread, &ready);
    while (!ready) sleep(1);

    g_response = SERVER_RESPONSE_VERIFIED;
    if (auth_via_socket(TEST_SOCKET_PATH) == 0) {
        printf("[PASS]: VERIFIED -> auth_via_socket() returns 0\n");
    } else {
        printf("[FAIL]: VERIFIED -> auth_via_socket() returns non-zero\n");
    }

    g_response = SERVER_RESPONSE_UNVERIFIED;
    if (auth_via_socket(TEST_SOCKET_PATH) != 0) {
        printf("[PASS]: UNVERIFIED -> auth_via_socket() returns non-zero\n");
    } else {
        printf("[FAIL]: UNVERIFIED -> auth_via_socket() returns 0\n");
    }

    stop_server();
    pthread_join(th, NULL);
    return 0;
}
