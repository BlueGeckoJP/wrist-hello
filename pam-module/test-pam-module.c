#include <pthread.h>
#include <security/pam_modules.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common.h"

#define TEST_SOCKET_PATH "/tmp/wrist-hello-auth-test.sock"

const char SERVER_RESPONSE_VERIFIED[10] = {0x02, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0x00};
const char SERVER_RESPONSE_UNVERIFIED[10] = {0x01, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00};

extern int auth_via_socket(pam_handle_t* pamh, char* socket_path);

static const char* g_response = SERVER_RESPONSE_VERIFIED;
static int g_server_fd = -1;
static bool g_verify_after_challenge = false;

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

        bool challenged = false;
        uint8_t cmd;
        while (read(client_fd, &cmd, 1) == 1) {
            if (cmd == CMD_CHECK_STATUS) {
                const char* response = (g_verify_after_challenge && challenged)
                                           ? SERVER_RESPONSE_VERIFIED
                                           : g_response;
                write(client_fd, response, SOCKET_PAYLOAD_SIZE);
            } else if (cmd == CMD_TRIGGER_CHALLENGE) {
                challenged = true;
            }
        }
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

    printf("\n[TEST]: VERIFIED: CMD_CHECK_STATUS returns VERIFIED on first attempt\n");
    g_response = SERVER_RESPONSE_VERIFIED;
    if (auth_via_socket(NULL, TEST_SOCKET_PATH) == 0) {
        printf("[PASS]: VERIFIED -> auth_via_socket() returns 0\n");
    } else {
        printf("[FAIL]: VERIFIED -> auth_via_socket() returns non-zero\n");
    }

    printf(
        "\n[TEST]: UNVERIFIED: CMD_CHECK_STATUS always returns UNVERIFIED even after "
        "CMD_TRIGGER_CHALLENGE\n");
    g_response = SERVER_RESPONSE_UNVERIFIED;
    if (auth_via_socket(NULL, TEST_SOCKET_PATH) != 0) {
        printf("[PASS]: UNVERIFIED -> auth_via_socket() returns non-zero\n");
    } else {
        printf("[FAIL]: UNVERIFIED -> auth_via_socket() returns 0\n");
    }

    printf(
        "\n[TEST]: CHALLENGE_SUCCESS: CMD_CHECK_STATUS returns UNVERIFIED initially, then VERIFIED "
        "after CMD_TRIGGER_CHALLENGE\n");
    g_response = SERVER_RESPONSE_UNVERIFIED;
    g_verify_after_challenge = true;
    if (auth_via_socket(NULL, TEST_SOCKET_PATH) == 0) {
        printf("[PASS]: CHALLENGE_SUCCESS -> auth_via_socket() returns 0\n");
    } else {
        printf("[FAIL]: CHALLENGE_SUCCESS -> auth_via_socket() returns non-zero\n");
    }
    g_verify_after_challenge = false;

    stop_server();
    pthread_join(th, NULL);
    return 0;
}
