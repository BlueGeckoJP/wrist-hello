#define _POSIX_C_SOURCE 200809L

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
#include <time.h>
#include <unistd.h>

#include "common.h"

#define SOCKET_PATH "/run/wrist-hello/auth.sock"
#define BUF_SIZE 256
#define AUTH_CACHE_TTL 60

int get_auth_cache(pam_handle_t* pamh, AuthCache* cache) {
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
    cache->uid = pw->pw_uid;

    if (tty) {
        strncpy(cache->tty, tty, sizeof(cache->tty) - 1);
        cache->tty[sizeof(cache->tty) - 1] = '\0';
    } else {
        cache->tty[0] = '\0';
    }

    if (service) {
        strncpy(cache->service, service, sizeof(cache->service) - 1);
        cache->service[sizeof(cache->service) - 1] = '\0';
    } else {
        cache->service[0] = '\0';
    }

    time_t now = time(NULL);
    cache->expires_at = now + AUTH_CACHE_TTL;

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
    AuthCache cache = {0};
    int cache_result = get_auth_cache(pamh, &cache);
    if (cache_result != PAM_SUCCESS) return cache_result;

    int fd = open_socket(SOCKET_PATH);
    if (fd < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to connect to UNIX socket server");
        return PAM_AUTH_ERR;
    }

    ssize_t n = write(fd, &cache, sizeof(cache));
    if (n < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to write auth cache to UNIX socket server");
        close(fd);
        return PAM_AUTH_ERR;
    }

    char buf[64] = {0};
    n = recv(fd, buf, sizeof(bool), MSG_WAITALL);
    if (n <= 0) {
        close(fd);
        pam_syslog(pamh, LOG_ERR, "Failed to receive response from UNIX socket server");
        return PAM_AUTH_ERR;
    }

    return buf[0] == 0 ? PAM_SUCCESS : PAM_AUTH_ERR;
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

/*

int get_auth_cache(pam_handle_t* pamh, AuthCache* item) {
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
    item->uid = pw->pw_uid;

    if (tty) {
        strncpy(item->tty, tty, sizeof(item->tty) - 1);
        item->tty[sizeof(item->tty) - 1] = '\0';
    } else {
        item->tty[0] = '\0';
    }

    if (service) {
        strncpy(item->service, service, sizeof(item->service) - 1);
        item->service[sizeof(item->service) - 1] = '\0';
    } else {
        item->service[0] = '\0';
    }

    time_t now = time(NULL);
    item->expires_at = now + AUTH_CACHE_TTL;

    return PAM_SUCCESS;
}

int add_auth_cache(pam_handle_t* pamh, int fd, const AuthCache* cache) {
    SocketCommand cmd = CMD_ADD_AUTH_CACHE;
    ssize_t n = write(fd, &cmd, sizeof(cmd));
    if (n < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to write command to UNIX socket server");
        return -1;
    }

    n = write(fd, cache, sizeof(AuthCache));
    if (n < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to write command to UNIX socket server");
        return -1;
    }

    return 0;
}

bool has_valid_cache(pam_handle_t* pamh, int fd, const AuthCache* item) {
    SocketCommand cmd = CMD_HAS_VALID_CACHE;
    ssize_t n = write(fd, &cmd, sizeof(cmd));
    if (n < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to write command to UNIX socket server");
        return -1;
    }

    n = write(fd, item, sizeof(AuthCache));
    if (n < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to write command to UNIX socket server");
        return -1;
    }

    char buf[BUF_SIZE] = {0};
    n = recv(fd, buf, sizeof(bool), MSG_WAITALL);
    if (n == 0) {
        return 1;  // Socket disconnected
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }
        return -1;
    }

    return buf[0] == '1';
}

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
*/