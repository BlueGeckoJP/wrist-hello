#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <security/_pam_types.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdatomic.h>
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
#define SOCKET_POLL_INTERVAL_MILLIS 100

typedef enum {
    WRIST_AUTH_SUCCESS,
    WRIST_AUTH_FAILURE,
    WRIST_AUTH_CANCELLED,
    WRIST_OPEN_SOCKET_ERROR,
    WRIST_WRITE_SOCKET_ERROR,
    WRIST_SOCKET_CLOSED_ERROR,
    WRIST_READ_SOCKET_ERROR,
} WristResultCode;

typedef enum { WRIST_RUNNING, WRIST_SUCCESS, WRIST_FAILED } WristState;

typedef struct {
    AuthIdentity identity;
    atomic_int state;
    atomic_int result_code;
    int cancel_fd;
} WristContext;

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

WristResultCode handle_wrist_authentication(AuthIdentity* identity, int cancel_fd) {
    int fd = open_socket(SOCKET_PATH);
    if (fd < 0) return WRIST_OPEN_SOCKET_ERROR;

    // Use a `while` loop with a `remaining` counter so the send operation can recover even if a
    // short write occurs
    const uint8_t* p = (const uint8_t*)identity;
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

    while (true) {
        struct pollfd fds[2] = {
            {.fd = fd, .events = POLLIN},
            {.fd = cancel_fd, .events = POLLIN},
        };

        int poll_result = poll(fds, 2, SOCKET_POLL_INTERVAL_MILLIS);
        if (poll_result == 0) {
            continue;
        }

        if (poll_result < 0) {
            if (errno == EINTR) continue;

            close(fd);
            return WRIST_READ_SOCKET_ERROR;
        }

        if (fds[1].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) {
            close(fd);
            return WRIST_AUTH_CANCELLED;
        }

        if (fds[0].revents & POLLIN) {
            uint8_t response = 0;
            ssize_t n = read(fd, &response, sizeof(response));

            close(fd);

            if (n != (ssize_t)sizeof(response)) {
                return WRIST_READ_SOCKET_ERROR;
            }

            return response == 0 ? WRIST_AUTH_SUCCESS : WRIST_AUTH_FAILURE;
        }

        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            close(fd);
            return WRIST_READ_SOCKET_ERROR;
        }
    }
}

static void print_wrist_result(pam_handle_t* pamh, const char* user, WristResultCode code) {
    switch (code) {
        case WRIST_AUTH_SUCCESS:
            pam_syslog(pamh, LOG_INFO, "Authentication succeeded: user=%s", user);
            break;
        case WRIST_AUTH_FAILURE:
            pam_syslog(pamh, LOG_ERR, "Authentication failed: user=%s", user);
            break;
        case WRIST_AUTH_CANCELLED:
            pam_syslog(pamh, LOG_ERR, "Authentication cancelled: user=%s", user);
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

static void* wrist_auth_thread(void* arg) {
    WristContext* ctx = (WristContext*)arg;

    WristResultCode result = handle_wrist_authentication(&ctx->identity, ctx->cancel_fd);
    atomic_store(&ctx->result_code, result);
    if (result == WRIST_AUTH_SUCCESS) {
        atomic_store(&ctx->state, WRIST_SUCCESS);
    } else {
        atomic_store(&ctx->state, WRIST_FAILED);
    }

    return NULL;
}

static bool ends_with_enter(const char* buf, ssize_t len) {
    if (len <= 0) return false;

    for (ssize_t i = len - 1; i >= 0; i--) {
        if (buf[i] == '\n' || buf[i] == '\r') return true;
        if (buf[i] != '\0') return false;
    }

    return false;
}

static bool write_cancel_signal(pam_handle_t* pamh, int fd, const char* user) {
    uint8_t cancel = 1;

    while (true) {
        ssize_t n = write(fd, &cancel, sizeof(cancel));

        if (n == (ssize_t)sizeof(cancel)) return true;
        if (n < 0 && errno == EINTR) continue;

        pam_syslog(pamh, LOG_ERR, "Failed to write cancel signal: user=%s, error=%s", user,
                   n < 0 ? strerror(errno) : "short write");
        return false;
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

    WristContext ctx = {0};
    if (get_auth_identity(pamh, &ctx.identity) != 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to get user information: user=%s", user);
        return PAM_AUTH_ERR;
    }
    atomic_init(&ctx.state, WRIST_RUNNING);
    atomic_init(&ctx.result_code, WRIST_AUTH_FAILURE);
    int cancel_pipe[2] = {-1, -1};
    if (pipe2(cancel_pipe, O_CLOEXEC) != 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to create cancellation pipe: user=%s", user);
        return PAM_AUTH_ERR;
    }
    ctx.cancel_fd = cancel_pipe[0];

    pthread_t wrist_thread;
    if (pthread_create(&wrist_thread, NULL, wrist_auth_thread, &ctx) != 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to create authentication thread: user=%s", user);
        close(cancel_pipe[0]);
        close(cancel_pipe[1]);
        return PAM_AUTH_ERR;
    }

    pam_info(pamh,
             "Approve on watch, or press Enter to continue with the next authentication method.");

    int tty_fd = open("/dev/tty", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (tty_fd < 0) {
        pam_syslog(pamh, LOG_WARNING, "Failed to open /dev/tty for fallback input: %s",
                   strerror(errno));
    }

    int result = PAM_IGNORE;

    while (true) {
        int wrist_state = atomic_load(&ctx.state);

        if (wrist_state == WRIST_SUCCESS) {
            pam_syslog(pamh, LOG_INFO, "Wrist authentication succeeded: user=%s", user);
            result = PAM_SUCCESS;
            break;
        }

        if (wrist_state == WRIST_FAILED) {
            pam_syslog(pamh, LOG_ERR, "Wrist authentication failed: user=%s", user);
            print_wrist_result(pamh, user, atomic_load(&ctx.result_code));
            result = PAM_AUTH_ERR;
            break;
        }

        if (tty_fd < 0) {
            usleep(50 * 1000);
            continue;
        }

        struct pollfd pfd = {
            .fd = tty_fd,
            .events = POLLIN,
        };

        int poll_result = poll(&pfd, 1, 50);
        if (poll_result > 0 && (pfd.revents & POLLIN)) {
            char buf[256];
            ssize_t n = read(tty_fd, buf, sizeof(buf));

            // TODO: Propagate Enter fallback cancellation from the PAM module to the daemon.
            // The current cancel pipe only stops the PAM-side waiting thread. If an
            // AuthRequest is already queued in AuthProcessor, it can still be processed
            // later and trigger a watch challenge even though PAM has already returned
            // PAM_IGNORE. Add a daemon-visible cancel signal over the auth socket and remove
            // the matching queued/in-progress request when it is received.
            if (ends_with_enter(buf, n)) {
                write_cancel_signal(pamh, cancel_pipe[1], user);

                pam_syslog(pamh, LOG_INFO,
                           "Wrist authentication skipped by Enter fallback: user=%s", user);
                result = PAM_IGNORE;
                break;
            }
        }
    }

    if (tty_fd >= 0) {
        close(tty_fd);
    }

    close(cancel_pipe[1]);
    pthread_join(wrist_thread, NULL);
    close(cancel_pipe[0]);

    return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;

    return PAM_SUCCESS;
}
