#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pwd.h>
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
#define AUTH_TIMEOUT_SECONDS 30

typedef enum {
    WRIST_AUTH_SUCCESS,
    WRIST_AUTH_FAILURE,
    WRIST_OPEN_SOCKET_ERROR,
    WRIST_WRITE_SOCKET_ERROR,
    WRIST_SOCKET_CLOSED_ERROR,
    WRIST_READ_SOCKET_ERROR,
} WristResultCode;

// success=0, failure=1
int get_auth_identity(pam_handle_t* pamh, AuthIdentity* identity) {
    const char* user = NULL;
    const char* tty = NULL;
    const char* service = NULL;

    if (pam_get_item(pamh, PAM_USER, (const void**)&user) != PAM_SUCCESS || !user) {
        return 1;
    }

    pam_get_item(pamh, PAM_TTY, (const void**)&tty);

    pam_get_item(pamh, PAM_SERVICE, (const void**)&service);

    struct passwd* pw = getpwnam(user);
    if (!pw) {
        return 1;
    }
    identity->uid = pw->pw_uid;

    if (tty) {
        strncpy(identity->tty, tty, sizeof(identity->tty) - 1);
        identity->tty[sizeof(identity->tty) - 1] = '\0';
    } else {
        identity->tty[0] = '\0';
    }

    if (service) {
        strncpy(identity->service, service, sizeof(identity->service) - 1);
        identity->service[sizeof(identity->service) - 1] = '\0';
    } else {
        identity->service[0] = '\0';
    }

    return 0;
}

int open_socket(const char* socket_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = AUTH_TIMEOUT_SECONDS;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

WristResultCode handle_authentication(AuthIdentity* identity) {
    int fd = open_socket(SOCKET_PATH);
    if (fd < 0) return WRIST_OPEN_SOCKET_ERROR;

    // Use a `while` loop with a `remaining` counter so the send operation can recover even if a
    // short write occurs
    const uint8_t* p = (const uint8_t*)&identity;
    size_t remaining = sizeof(AuthIdentity);
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);

        if (n < 0) {
            if (errno == EINTR) continue;

            close(fd);
            return WRIST_WRITE_SOCKET_ERROR;
        }

        if (n == 0) {
            close(fd);
            return WRIST_SOCKET_CLOSED_ERROR;
        }

        p += n;
        remaining -= (size_t)n;
    }

    uint8_t response = 0;
    ssize_t n = recv(fd, &response, sizeof(response), MSG_WAITALL);
    if (n != (ssize_t)sizeof(response)) {
        close(fd);
        return WRIST_READ_SOCKET_ERROR;
    }

    close(fd);
    return response == 0 ? WRIST_AUTH_SUCCESS : WRIST_AUTH_FAILURE;
}

void print_wrist_result(pam_handle_t* pamh, const char* user, WristResultCode code) {
    switch (code) {
        case WRIST_AUTH_SUCCESS:
            pam_syslog(pamh, LOG_INFO, "Authentication succeeded: user=%s", user);
            break;
        case WRIST_AUTH_FAILURE:
            pam_syslog(pamh, LOG_ERR, "Authentication failed: user=%s", user);
            break;
        case WRIST_OPEN_SOCKET_ERROR:
            pam_syslog(pamh, LOG_ERR, "Failed to open socket: user=%s", user);
            break;
        case WRIST_WRITE_SOCKET_ERROR:
            pam_syslog(pamh, LOG_ERR, "Failed to write to socket: user=%s", user);
            break;
        case WRIST_SOCKET_CLOSED_ERROR:
            pam_syslog(pamh, LOG_ERR, "Socket closed unexpectedly: user=%s", user);
            break;
        case WRIST_READ_SOCKET_ERROR:
            pam_syslog(pamh, LOG_ERR, "Failed to read from socket: user=%s", user);
            break;
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    (void)flags;
    (void)argc;
    (void)argv;

    const char* user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) {
        return PAM_USER_UNKNOWN;
    }

    AuthIdentity identity = {0};
    if (get_auth_identity(pamh, &identity) != 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to get user identity: user=%s", user);
        return PAM_USER_UNKNOWN;
    }

    int result = handle_authentication(&identity);
    print_wrist_result(pamh, user, result);
    if (result != PAM_SUCCESS) return result;

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;

    return PAM_SUCCESS;
}
