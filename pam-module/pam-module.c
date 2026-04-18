#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <security/_pam_types.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include "common.h"

#define SOCKET_PATH "/run/wrist-hello/auth.sock"
#define BUF_SIZE 256

// Result: 0=Success, 1=Should retry, -1=Fatal error
int check_status(pam_handle_t* pamh, int fd) {
    SocketCommand cmd = CMD_CHECK_STATUS;
    ssize_t n = write(fd, &cmd, sizeof(cmd));
    if (n < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to write command to UNIX socket server");
        return -1;
    }

    char buf[BUF_SIZE] = {0};
    n = recv(fd, buf, sizeof(SocketPayload), MSG_WAITALL);
    if (n == 0) {
        return 1;  // Socket disconnected
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }
        return -1;
    }

    uint8_t* payload = (uint8_t*)buf;
    SocketPayload sp = {0};
    if (!socket_payload_deserialize(payload, (size_t)n, &sp) || sp.status != STATUS_VERIFIED) {
        return 1;
    }

    return 0;
}

int check_status_with_ttl(pam_handle_t* pamh, int fd, int ttl) {
    while (ttl-- > 0) {
        sleep(1);
        int status = check_status(pamh, fd);
        if (status == 0) return 0;    // If success
        if (status == -1) return -1;  // If fatal errors occurred
    }

    return -1;
}

int auth_via_socket(pam_handle_t* pamh, char* socket_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    int result = check_status(pamh, fd);
    if (result == 0) {
        close(fd);
        return 0;
    }

    SocketCommand cmd = CMD_TRIGGER_CHALLENGE;
    ssize_t n = write(fd, &cmd, sizeof(cmd));
    if (n < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to write command to UNIX socket server");
        close(fd);
        return -1;
    }

    result = check_status_with_ttl(pamh, fd, 5);
    close(fd);

    return (result == 0) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    (void)flags;
    (void)argc;
    (void)argv;

    const char* user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return PAM_USER_UNKNOWN;
    }

    if (auth_via_socket(pamh, SOCKET_PATH) != 0) {
        pam_syslog(pamh, LOG_WARNING, "Authentication failed: user=%s", user);
        return PAM_AUTH_ERR;
    }

    pam_syslog(pamh, LOG_INFO, "Authentication succeeded: user=%s", user);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;

    return PAM_SUCCESS;
}
