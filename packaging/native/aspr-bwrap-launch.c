#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#define MAX_PLAN (64U * 1024U)
#define MAX_COMMAND 64U
#define MAX_REMOTES 32U
#define MAX_STRING 4096U
#define BWRAP "/usr/bin/bwrap"
#define ENTRY "/usr/libexec/astral-project/aspr-sandbox-entry"
#define MAGIC "ASPRSB01"

typedef struct { char *value; } String;
typedef struct { uint8_t mode; String mount_id; String source; String target; } Remote;

typedef struct {
    uint8_t network;
    uint32_t command_count;
    String *command;
    uint32_t remote_count;
    Remote *remote;
    String socket;
    int has_socket;
} Plan;

static void fail(const char *message) {
    fprintf(stderr, "ASPR_SANDBOX_LAUNCH: %s\n", message);
    exit(70);
}

static size_t bytes_read;

static void read_exact(void *buffer, size_t length) {
    if (length > MAX_PLAN - bytes_read) fail("sandbox plan exceeds fixed size limit");
    unsigned char *cursor = buffer;
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(STDIN_FILENO, cursor + offset, length - offset);
        if (count <= 0) fail("sandbox plan ended before declared length");
        offset += (size_t)count;
        bytes_read += (size_t)count;
    }
}

static uint8_t read_u8(void) {
    uint8_t value;
    read_exact(&value, sizeof(value));
    return value;
}

static uint32_t read_u32(void) {
    unsigned char bytes[4];
    read_exact(bytes, sizeof(bytes));
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static String read_string(void) {
    uint32_t length = read_u32();
    if (length == 0 || length > MAX_STRING) {
        fail("sandbox plan string is empty or too long");
    }
    char *value = calloc((size_t)length + 1, 1);
    if (value == NULL) fail("sandbox plan allocation failed");
    read_exact(value, length);
    if (memchr(value, '\0', length) != NULL) fail("sandbox plan string contains NUL");
    return (String){value};
}

static int suffix(const char *value, const char *ending) {
    size_t value_length = strlen(value);
    size_t ending_length = strlen(ending);
    return value_length >= ending_length &&
           strcmp(value + value_length - ending_length, ending) == 0;
}

static int path_is_or_below(const char *path, const char *root) {
    size_t root_length = strlen(root);
    return strcmp(path, root) == 0 ||
           (strncmp(path, root, root_length) == 0 && path[root_length] == '/');
}

static void absolute_normalized(const char *value, int root_allowed) {
    size_t length = strlen(value);
    if (length == 0 || length > MAX_STRING || value[0] != '/') fail("sandbox plan path is not absolute");
    if ((!root_allowed && strcmp(value, "/") == 0) ||
        (length > 1 && suffix(value, "/")) || strstr(value, "//") != NULL ||
        strstr(value, "/./") != NULL || strstr(value, "/../") != NULL ||
        suffix(value, "/.") || suffix(value, "/..")) {
        fail("sandbox plan path is not normalized");
    }
}

static void require_authority_marker(const char *source, const char *mount_id) {
    char source_copy[MAX_STRING + 1];
    int source_length = snprintf(source_copy, sizeof(source_copy), "%s", source);
    if (source_length < 0 || (size_t)source_length >= sizeof(source_copy)) {
        fail("sandbox mount source path is invalid");
    }
    char marker_path[MAX_STRING + 32];
    int marker_length = snprintf(
        marker_path, sizeof(marker_path), "%s/.aspr-mount-%s", dirname(source_copy), mount_id
    );
    if (marker_length < 0 || (size_t)marker_length >= sizeof(marker_path)) {
        fail("sandbox mount authority marker path is invalid");
    }
    int descriptor = open(marker_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) fail("sandbox mount lacks daemon authority marker");
    struct stat details;
    char marker_value[33] = {0};
    unsigned char trailing;
    ssize_t length = read(descriptor, marker_value, 32);
    ssize_t extra = read(descriptor, &trailing, 1);
    int valid = fstat(descriptor, &details) == 0 && S_ISREG(details.st_mode) &&
                details.st_uid == getuid() && length == 32 && extra == 0 &&
                memcmp(marker_value, mount_id, 32) == 0;
    close(descriptor);
    if (!valid) fail("sandbox mount authority marker is invalid");
}

static void parse_plan(Plan *plan) {
    char magic[sizeof(MAGIC) - 1];
    read_exact(magic, sizeof(magic));
    if (memcmp(magic, MAGIC, sizeof(magic)) != 0) fail("sandbox plan magic or version is invalid");
    plan->network = read_u8();
    if (plan->network > 1) fail("sandbox network mode is invalid");
    plan->command_count = read_u32();
    if (plan->command_count == 0 || plan->command_count > MAX_COMMAND) fail("sandbox command count is invalid");
    plan->command = calloc(plan->command_count, sizeof(*plan->command));
    if (plan->command == NULL) fail("sandbox plan allocation failed");
    for (uint32_t index = 0; index < plan->command_count; ++index) {
        plan->command[index] = read_string();
    }
    absolute_normalized(plan->command[0].value, 0);
    plan->remote_count = read_u32();
    if (plan->remote_count > MAX_REMOTES) fail("sandbox remote count is invalid");
    if (plan->remote_count != 0) {
        plan->remote = calloc(plan->remote_count, sizeof(*plan->remote));
        if (plan->remote == NULL) fail("sandbox plan allocation failed");
    }
    for (uint32_t index = 0; index < plan->remote_count; ++index) {
        plan->remote[index].mode = read_u8();
        if (plan->remote[index].mode > 1) fail("sandbox remote mode is invalid");
        plan->remote[index].mount_id = read_string();
        plan->remote[index].source = read_string();
        plan->remote[index].target = read_string();
        if (strchr(plan->remote[index].mount_id.value, '/') != NULL ||
            strlen(plan->remote[index].mount_id.value) != 32) {
            fail("sandbox mount identity is invalid");
        }
        absolute_normalized(plan->remote[index].source.value, 1);
        absolute_normalized(plan->remote[index].target.value, 0);
    }
    static const char *const reserved[] = {
        "/bin", "/dev", "/home", "/lib", "/lib64", "/proc", "/run", "/sbin", "/sys", "/tmp", "/usr"
    };
    for (uint32_t left = 0; left < plan->remote_count; ++left) {
        for (size_t reserved_index = 0; reserved_index < sizeof(reserved) / sizeof(reserved[0]); ++reserved_index) {
            if (path_is_or_below(plan->remote[left].target.value, reserved[reserved_index])) {
                fail("sandbox remote target overlaps a fixed sandbox path");
            }
        }
        for (uint32_t right = left + 1; right < plan->remote_count; ++right) {
            if (path_is_or_below(plan->remote[left].target.value, plan->remote[right].target.value) ||
                path_is_or_below(plan->remote[right].target.value, plan->remote[left].target.value)) {
                fail("sandbox remote targets collide or overlap");
            }
        }
    }
    for (uint32_t index = 0; index < plan->remote_count; ++index) {
        require_authority_marker(
            plan->remote[index].source.value, plan->remote[index].mount_id.value
        );
        struct stat details;
        struct statfs filesystem;
        if (stat(plan->remote[index].source.value, &details) != 0 || !S_ISDIR(details.st_mode) ||
            statfs(plan->remote[index].source.value, &filesystem) != 0 ||
            (unsigned long)filesystem.f_type != 0x65735546UL) {
            fail("sandbox remote source is not a daemon FUSE mount");
        }
    }
    plan->has_socket = read_u8();
    if (plan->has_socket > 1) fail("sandbox session socket flag is invalid");
    if (plan->has_socket) {
        plan->socket = read_string();
        absolute_normalized(plan->socket.value, 0);
        struct stat details;
        if (stat(plan->socket.value, &details) != 0 || !S_ISSOCK(details.st_mode) ||
            details.st_uid != getuid()) {
            fail("sandbox session socket is not an owned session socket");
        }
    }
    unsigned char extra;
    if (read(STDIN_FILENO, &extra, 1) != 0) fail("sandbox plan has trailing bytes");
}

static void add(char **argv, size_t *count, size_t capacity, const char *value) {
    if (*count + 1 >= capacity) fail("sandbox launcher argv exceeds fixed bound");
    argv[(*count)++] = (char *)value;
}

static void execute_plan(const Plan *plan) {
    size_t capacity = 128 + (size_t)plan->command_count + (size_t)plan->remote_count * 3;
    char **argv = calloc(capacity, sizeof(*argv));
    if (argv == NULL) fail("sandbox launcher argv allocation failed");
    size_t count = 0;
    add(argv, &count, capacity, BWRAP);
    add(argv, &count, capacity, "--die-with-parent");
    add(argv, &count, capacity, "--new-session");
    add(argv, &count, capacity, "--unshare-pid");
    add(argv, &count, capacity, "--unshare-ipc");
    add(argv, &count, capacity, "--unshare-uts");
    add(argv, &count, capacity, "--ro-bind"); add(argv, &count, capacity, "/usr"); add(argv, &count, capacity, "/usr");
    add(argv, &count, capacity, "--symlink"); add(argv, &count, capacity, "/usr/bin"); add(argv, &count, capacity, "/bin");
    add(argv, &count, capacity, "--symlink"); add(argv, &count, capacity, "/usr/sbin"); add(argv, &count, capacity, "/sbin");
    add(argv, &count, capacity, "--symlink"); add(argv, &count, capacity, "/usr/lib"); add(argv, &count, capacity, "/lib");
    add(argv, &count, capacity, "--symlink"); add(argv, &count, capacity, "/usr/lib64"); add(argv, &count, capacity, "/lib64");
    add(argv, &count, capacity, "--dev"); add(argv, &count, capacity, "/dev");
    add(argv, &count, capacity, "--proc"); add(argv, &count, capacity, "/proc");
    add(argv, &count, capacity, "--tmpfs"); add(argv, &count, capacity, "/tmp");
    add(argv, &count, capacity, "--tmpfs"); add(argv, &count, capacity, "/home");
    add(argv, &count, capacity, "--dir"); add(argv, &count, capacity, "/home/sandbox");
    add(argv, &count, capacity, "--clearenv");
    add(argv, &count, capacity, "--setenv"); add(argv, &count, capacity, "HOME"); add(argv, &count, capacity, "/home/sandbox");
    add(argv, &count, capacity, "--setenv"); add(argv, &count, capacity, "PATH"); add(argv, &count, capacity, "/usr/local/bin:/usr/bin:/bin");
    add(argv, &count, capacity, "--cap-drop"); add(argv, &count, capacity, "ALL");
    if (plan->network == 1) add(argv, &count, capacity, "--unshare-net");
    for (uint32_t index = 0; index < plan->remote_count; ++index) {
        add(argv, &count, capacity, plan->remote[index].mode == 1 ? "--bind" : "--ro-bind");
        add(argv, &count, capacity, plan->remote[index].source.value);
        add(argv, &count, capacity, plan->remote[index].target.value);
    }
    if (plan->has_socket) {
        add(argv, &count, capacity, "--dir"); add(argv, &count, capacity, "/run");
        add(argv, &count, capacity, "--dir"); add(argv, &count, capacity, "/run/astral-project");
        add(argv, &count, capacity, "--ro-bind"); add(argv, &count, capacity, plan->socket.value);
        add(argv, &count, capacity, "/run/astral-project/session.sock");
    }
    add(argv, &count, capacity, "--");
    add(argv, &count, capacity, ENTRY);
    for (uint32_t index = 0; index < plan->command_count; ++index) add(argv, &count, capacity, plan->command[index].value);
    argv[count] = NULL;
    execv(BWRAP, argv);
    fail("fixed /usr/bin/bwrap could not execute");
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) fail("fixed launcher accepts no command-line arguments");
    Plan plan = {0};
    parse_plan(&plan);
    execute_plan(&plan);
    return 70;
}
