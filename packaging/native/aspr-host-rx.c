#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ENTRY "/usr/libexec/astral-project/aspr-host-rx"
#define MANIFEST "/tmp/aspr-host-rx.allow"
#define HOME_PREFIX "/home/sandbox/"
#define MAX_ARGUMENTS 64
#define MAX_PATH 4096
#define MAX_EXECUTABLE (64U * 1024U * 1024U)

extern char **environ;

static void fail(const char *message) {
    fprintf(stderr, "ASPR_HOST_RX: %s\n", message);
    exit(70);
}

static void fail_errno(const char *message) {
    fprintf(stderr, "ASPR_HOST_RX: %s: %s\n", message, strerror(errno));
    exit(70);
}

static int create_staging_file(void) {
    return open("/tmp/aspr-host-rx.exec", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0700);
}

static void copy_all(int source, int destination, size_t remaining) {
    unsigned char buffer[65536];
    while (remaining != 0) {
        size_t wanted = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        ssize_t read_count = read(source, buffer, wanted);
        if (read_count <= 0) fail("approved executable changed while being copied");
        unsigned char *cursor = buffer;
        size_t unwritten = (size_t)read_count;
        while (unwritten != 0) {
            ssize_t written = write(destination, cursor, unwritten);
            if (written <= 0) fail("sealed executable copy failed");
            cursor += written;
            unwritten -= (size_t)written;
        }
        remaining -= (size_t)read_count;
    }
    unsigned char extra;
    if (read(source, &extra, 1) != 0) fail("approved executable changed while being copied");
}

static void require_manifest_path(const char *target) {
    struct stat visible;
    if (stat(MANIFEST, &visible) != 0) fail_errno("host-rx manifest stat failed");
    int descriptor = open(MANIFEST, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) fail_errno("host-rx manifest is unavailable");
    struct stat details;
    if (fstat(descriptor, &details) != 0 || !S_ISREG(details.st_mode) ||
        details.st_uid != getuid() || (details.st_mode & 022) != 0 || details.st_size == 0 ||
        details.st_size > MAX_PATH) {
        close(descriptor);
        fail("host-rx manifest is unsafe");
    }
    char allowed[MAX_PATH + 1];
    ssize_t length = read(descriptor, allowed, sizeof(allowed) - 1);
    close(descriptor);
    if (length <= 1 || allowed[length - 1] != '\n') fail("host-rx manifest is invalid");
    allowed[length - 1] = '\0';
    if (strcmp(allowed, target) != 0) fail("command is not the approved host-rx path");
}

int main(int argc, char **argv) {
    if (argc < 2 || argc - 1 > MAX_ARGUMENTS || argv[0] == NULL || strcmp(argv[0], ENTRY) != 0) {
        fail("fixed host-rx invocation is invalid");
    }
    const char *target = argv[1];
    if (target[0] != '/' || strncmp(target, HOME_PREFIX, strlen(HOME_PREFIX)) != 0 ||
        strlen(target) >= MAX_PATH || strstr(target, "//") != NULL || strstr(target, "/./") != NULL ||
        strstr(target, "/../") != NULL || strstr(target, "/..") == target + strlen(target) - 3) {
        fail("host-rx command path is invalid");
    }
    require_manifest_path(target);
    int source = open(target, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source < 0) fail_errno("approved host-rx executable is unavailable");
    struct stat details;
    if (fstat(source, &details) != 0 || !S_ISREG(details.st_mode) || details.st_size <= 0 ||
        (unsigned long long)details.st_size > MAX_EXECUTABLE || (details.st_mode & 0111) == 0) {
        close(source);
        fail("approved host-rx node is not an executable regular file");
    }
    int sealed = create_staging_file();
    if (sealed < 0) {
        close(source);
        fail("sealed executable staging is unavailable");
    }
    copy_all(source, sealed, (size_t)details.st_size);
    close(source);
    if (lseek(sealed, 0, SEEK_SET) < 0) fail("sealed executable rewind failed");
    if (fchmod(sealed, 0500) != 0) fail_errno("sealed executable mode could not be fixed");
    close(sealed);
    execve("/tmp/aspr-host-rx.exec", &argv[1], environ);
    fail_errno("sealed host-rx executable could not start");
    return 70;
}
