#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_ARGUMENTS 64
#define ENTRY "/usr/libexec/astral-project/aspr-sandbox-entry"

static void fail(const char *message) {
    fprintf(stderr, "ASPR_SANDBOX_ENTRY: %s\n", message);
    exit(70);
}

int main(int argc, char **argv) {
    if (argc < 2 || argv[0] == NULL || strcmp(argv[0], ENTRY) != 0) {
        fail("fixed sandbox entrypoint invocation is invalid");
    }
    char profile[256] = {0};
    int profile_fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    ssize_t profile_size = profile_fd < 0 ? -1 : read(profile_fd, profile, sizeof(profile) - 1);
    if (profile_fd >= 0) close(profile_fd);
    if (profile_size <= 0 || strstr(profile, "aspr-bwrap-setup") == NULL) {
        fail("sandbox entrypoint is not running under the fixed setup profile");
    }
    if (argc - 1 > MAX_ARGUMENTS || argv[1][0] != '/') {
        fail("payload command is not an absolute bounded executable");
    }
    execv(argv[1], &argv[1]);
    fail("payload executable could not start");
    return 70;
}
