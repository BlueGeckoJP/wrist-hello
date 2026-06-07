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

int get_auth_identity(pam_handle_t* pamh, AuthIdentity* identity) {
    const char* user = NULL;
    const char* tty = NULL;
    const char* service = NULL;

    if (pam_get_item(pamh, PAM_USER, (const void**)&user) != PAM_SUCCESS || !user) {
        return PAM_AUTH_ERR;
    }

    pam_get_item(pamh, PAM_TTY, (const void**)&tty);

    pam_get_item(pamh, PAM_SERVICE, (const void**)&service);

    struct passwd* pw = getpwnam(user);
    if (!pw) {
        return PAM_USER_UNKNOWN;
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

    return PAM_SUCCESS;
}

int open_socket(const char* socket_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = 5;
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

int handle_authentication(pam_handle_t* pamh) {
    AuthIdentity identity = {0};
    int identity_result = get_auth_identity(pamh, &identity);
    if (identity_result != PAM_SUCCESS) return identity_result;

    int fd = open_socket(SOCKET_PATH);
    if (fd < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to connect to UNIX socket server");
        return PAM_AUTH_ERR;
    }

    // Use a `while` loop with a `remaining` counter so the send operation can recover even if a
    // short write occurs
    const uint8_t* p = (const uint8_t*)&identity;
    size_t remaining = sizeof(identity);
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);

        if (n < 0) {
            if (errno == EINTR) continue;

            pam_syslog(pamh, LOG_ERR, "Failed to write auth identity to UNIX socket server: %s",
                       strerror(errno));
            close(fd);
            return PAM_AUTH_ERR;
        }

        if (n == 0) {
            pam_syslog(pamh, LOG_ERR, "UNIX socket server closed connection unexpectedly");
            close(fd);
            return PAM_AUTH_ERR;
        }

        p += n;
        remaining -= (size_t)n;
    }

    uint8_t response = 0;
    ssize_t n = recv(fd, &response, sizeof(response), MSG_WAITALL);
    if (n != (ssize_t)sizeof(response)) {
        close(fd);
        pam_syslog(pamh, LOG_ERR, "Failed to receive response from UNIX socket server");
        return PAM_AUTH_ERR;
    }

    close(fd);
    return response == 0 ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    (void)flags;
    (void)argc;
    (void)argv;

    const char* user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) {
        return PAM_USER_UNKNOWN;
    }

    int result = handle_authentication(pamh);
    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Authentication failed: user=%s, error_code=%d", user, result);
        return result;
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
