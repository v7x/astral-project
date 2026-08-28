#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define MAX_ARGUMENTS 64
#define MAX_LINE (16U * 1024U)
#define ENTRY "/usr/libexec/astral-project/aspr-sandbox-entry"
#define HOST_RX "/usr/libexec/astral-project/aspr-host-rx"
#define SESSION_SOCKET "/run/astral-project/session.sock"

static void fail(const char *message) {
    fprintf(stderr, "ASPR_SANDBOX_ENTRY: %s\n", message);
    exit(70);
}

#include "aspr-hardening.h"

static void write_all(int fd, const char *data, size_t length) {
    while (length > 0) {
        ssize_t count = write(fd, data, length);
        if (count <= 0) fail("sandbox session relay write failed");
        data += count;
        length -= (size_t)count;
    }
}

static size_t read_line(int fd, char *buffer, size_t capacity) {
    size_t length = 0;
    while (length + 1 < capacity) {
        char value;
        ssize_t count = read(fd, &value, 1);
        if (count <= 0) return 0;
        buffer[length++] = value;
        if (value == '\n') {
            buffer[length] = '\0';
            return length;
        }
    }
    fail("sandbox session relay frame is too large");
    return 0;
}

static void session_relay(int relay_fd) {
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) fail("sandbox session socket could not be created");
    unlink(SESSION_SOCKET);
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(SESSION_SOCKET) >= sizeof(address.sun_path)) fail("sandbox session socket path is too long");
    memcpy(address.sun_path, SESSION_SOCKET, strlen(SESSION_SOCKET) + 1);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(SESSION_SOCKET, 0666) != 0 || listen(listener, 4) != 0) {
        close(listener);
        fail("sandbox session socket could not be bound");
    }
    for (;;) {
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) break;
        char request[MAX_LINE];
        char response[MAX_LINE];
        size_t request_length = read_line(client, request, sizeof(request));
        if (request_length == 0) {
            close(client);
            continue;
        }
        write_all(relay_fd, request, request_length);
        size_t response_length = read_line(relay_fd, response, sizeof(response));
        if (response_length == 0) {
            close(client);
            break;
        }
        write_all(client, response, response_length);
        close(client);
    }
    close(listener);
    _exit(70);
}

int main(int argc, char **argv) {
    if (argc < 2 || argv[0] == NULL || strcmp(argv[0], ENTRY) != 0) {
        fail("fixed sandbox entrypoint invocation is invalid");
    }
    if (argc < 5 || strcmp(argv[1], "--aspr-hardening") != 0) {
        fail("sandbox entrypoint is not running under the fixed setup profile");
    }
    const char *read_roots[64];
    const char *write_roots[64];
    size_t read_count = 0;
    size_t write_count = 0;
    int payload_index = 0;
    for (int index = 2; index < argc; index += 2) {
        if (strcmp(argv[index], "--") == 0) {
            payload_index = index + 1;
            break;
        }
        if (index + 1 >= argc || argv[index + 1][0] != '/') {
            fail("sandbox hardening root is invalid");
        }
        if (strcmp(argv[index], "--aspr-read-root") == 0) {
            if (read_count >= 64) fail("sandbox hardening roots exceed limit");
            read_roots[read_count++] = argv[index + 1];
        } else if (strcmp(argv[index], "--aspr-write-root") == 0) {
            if (write_count >= 64) fail("sandbox hardening roots exceed limit");
            write_roots[write_count++] = argv[index + 1];
        } else {
            fail("sandbox hardening root marker is invalid");
        }
    }
    if (payload_index == 0 || payload_index >= argc || argv[payload_index][0] != '/') {
        fail("sandbox payload is missing");
    }
    char profile[256] = {0};
    int profile_fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    ssize_t profile_size = profile_fd < 0 ? -1 : read(profile_fd, profile, sizeof(profile) - 1);
    if (profile_fd >= 0) close(profile_fd);
    if (profile_size <= 0 || strstr(profile, "aspr-bwrap-setup") == NULL) {
        fail("sandbox entrypoint is not running under the fixed setup profile");
    }
    if (argc - payload_index > MAX_ARGUMENTS) {
        fail("payload command is not an absolute bounded executable");
    }
    if (strcmp(argv[payload_index], HOST_RX) == 0 &&
        (payload_index + 1 >= argc || strncmp(argv[payload_index + 1], "/home/sandbox/", 14) != 0)) {
        fail("host-rx payload invocation is invalid");
    }
    aspr_harden_payload(read_roots, read_count, write_roots, write_count);
    const char *relay_text = getenv("ASPR_SESSION_RELAY_FD");
    if (relay_text != NULL) {
        if (strcmp(relay_text, "3") != 0) fail("sandbox session relay descriptor is invalid");
        pid_t relay = fork();
        if (relay < 0) fail("sandbox session relay could not start");
        if (relay == 0) session_relay(3);
        close(3);
        unsetenv("ASPR_SESSION_RELAY_FD");
    }
    execv(argv[payload_index], &argv[payload_index]);
    fail("payload executable could not start");
    return 70;
}
