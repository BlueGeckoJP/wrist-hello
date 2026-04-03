#define _POSIX_C_SOURCE 200809L

#include <security/_pam_types.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include "common.h"

#define SOCKET_PATH "/run/wrist-hello/auth.sock"
#define BUF_SIZE 256

static int auth_via_socket(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    char res[BUF_SIZE] = {0};
    ssize_t n = read(fd, res, sizeof(res) - 1);
    close(fd);
    if (n <= 0) return -1;

    uint8_t* payload = (uint8_t*)res;
    SocketPayload sp = {0};
    if (!socket_payload_deserialize(payload, (size_t)n, &sp) || sp.status != STATUS_VERIFIED) {
        return -1;
    }

    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    (void)flags;
    (void)argc;
    (void)argv;

    const char* user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return PAM_USER_UNKNOWN;
    }

    if (auth_via_socket() != 0) {
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
