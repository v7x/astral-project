#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <termios.h>
#include <sys/vfs.h>
#include <unistd.h>

#define MAX_PLAN (64U * 1024U)
#define MAX_COMMAND 64U
#define MAX_REMOTES 32U
#define MAX_SOCKETS 16U
#define MAX_ENVIRONMENT 64U
#define MAX_STRING 4096U
#define BWRAP "/usr/bin/bwrap"
#define ENTRY "/usr/libexec/astral-project/aspr-sandbox-entry"
#define HOST_RX "/usr/libexec/astral-project/aspr-host-rx"
#define MAGIC "ASPRSB01"

typedef struct { char *value; } String;
typedef struct { uint8_t mode; String mount_id; String source; String target; } Remote;
typedef struct { String path; } SocketBinding;

static struct termios saved_terminal;
static int terminal_saved;

static void restore_terminal(void) {
    if (terminal_saved) {
        (void)tcsetattr(STDIN_FILENO, TCSADRAIN, &saved_terminal);
        terminal_saved = 0;
    }
}

typedef struct {
    uint8_t network;
    uint32_t command_count;
    String *command;
    uint32_t remote_count;
    Remote *remote;
    uint32_t socket_count;
    SocketBinding *socket_binding;
    String socket;
    int has_socket;
    String session_id;
    int has_session_id;
    String projected_home;
    int has_projected_home;
    int projected_home_writable;
    String host_rx_manifest;
    int has_host_rx_manifest;
} Plan;

static void fail(const char *message) {
    restore_terminal();
    fprintf(stderr, "ASPR_SANDBOX_LAUNCH: %s\n", message);
    exit(70);
}

static size_t bytes_read;
static unsigned char transport_prefix[sizeof(MAGIC) - 1];
static size_t transport_prefix_offset;
static unsigned char decoded_plan[MAX_PLAN];
static size_t decoded_plan_length;
static size_t decoded_plan_offset;
static int transport_is_decoded;

static void read_fd_exact(void *buffer, size_t length) {
    unsigned char *cursor = buffer;
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(STDIN_FILENO, cursor + offset, length - offset);
        if (count <= 0) fail("sandbox plan ended before declared length");
        offset += (size_t)count;
    }
}

static void read_exact(void *buffer, size_t length) {
    if (length > MAX_PLAN - bytes_read) fail("sandbox plan exceeds fixed size limit");
    unsigned char *cursor = buffer;
    size_t offset = 0;
    while (offset < length && transport_is_decoded) {
        if (decoded_plan_offset >= decoded_plan_length) {
            fail("sandbox encoded plan ended before declared length");
        }
        size_t available = decoded_plan_length - decoded_plan_offset;
        size_t count = length - offset < available ? length - offset : available;
        memcpy(cursor + offset, decoded_plan + decoded_plan_offset, count);
        decoded_plan_offset += count;
        offset += count;
    }
    while (!transport_is_decoded && offset < length && transport_prefix_offset < sizeof(transport_prefix)) {
        cursor[offset++] = transport_prefix[transport_prefix_offset++];
    }
    if (offset < length) read_fd_exact(cursor + offset, length - offset);
    bytes_read += length;
}

static int base64_value(unsigned char value) {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}

static void prepare_transport(void) {
    unsigned char prefix[sizeof(MAGIC) - 1];
    read_fd_exact(prefix, sizeof(prefix));
    if (memcmp(prefix, "ASPRB64\n", sizeof(prefix)) != 0) {
        memcpy(transport_prefix, prefix, sizeof(prefix));
        transport_prefix_offset = 0;
        return;
    }
    unsigned char encoded[MAX_PLAN * 2];
    size_t encoded_length = 0;
    for (;;) {
        unsigned char value;
        read_fd_exact(&value, 1);
        if (value == '\n') break;
        if (encoded_length >= sizeof(encoded)) fail("sandbox encoded plan is too large");
        encoded[encoded_length++] = value;
    }
    if (encoded_length == 0 || encoded_length % 4 != 0) {
        fail("sandbox encoded plan is invalid");
    }
    for (size_t index = 0; index < encoded_length; index += 4) {
        int a = base64_value(encoded[index]);
        int b = base64_value(encoded[index + 1]);
        unsigned char third = encoded[index + 2];
        unsigned char fourth = encoded[index + 3];
        int c = third == '=' ? 0 : base64_value(third);
        int d = fourth == '=' ? 0 : base64_value(fourth);
        if (a < 0 || b < 0 || c < 0 || d < 0 ||
            (third == '=' && fourth != '=') ||
            (third == '=' && index + 4 != encoded_length) ||
            (fourth == '=' && index + 4 != encoded_length)) {
            fail("sandbox encoded plan is invalid");
        }
        if (decoded_plan_length >= sizeof(decoded_plan)) fail("sandbox plan exceeds fixed size limit");
        decoded_plan[decoded_plan_length++] = (unsigned char)((a << 2) | (b >> 4));
        if (third != '=') {
            if (decoded_plan_length >= sizeof(decoded_plan)) fail("sandbox plan exceeds fixed size limit");
            decoded_plan[decoded_plan_length++] = (unsigned char)((b << 4) | (c >> 2));
        }
        if (fourth != '=') {
            if (decoded_plan_length >= sizeof(decoded_plan)) fail("sandbox plan exceeds fixed size limit");
            decoded_plan[decoded_plan_length++] = (unsigned char)((c << 6) | d);
        }
    }
    transport_is_decoded = 1;
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
    plan->socket_count = read_u32();
    if (plan->socket_count > MAX_SOCKETS) fail("sandbox socket count is invalid");
    if (plan->socket_count != 0) {
        plan->socket_binding = calloc(plan->socket_count, sizeof(*plan->socket_binding));
        if (plan->socket_binding == NULL) fail("sandbox plan allocation failed");
    }
    for (uint32_t index = 0; index < plan->socket_count; ++index) {
        plan->socket_binding[index].path = read_string();
        absolute_normalized(plan->socket_binding[index].path.value, 0);
        struct stat details;
        if (lstat(plan->socket_binding[index].path.value, &details) != 0 || !S_ISSOCK(details.st_mode)) {
            fail("sandbox approved socket is unavailable or not a pathname socket");
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
    plan->has_session_id = read_u8();
    if (plan->has_session_id > 1 || (plan->has_session_id && !plan->has_socket) ||
        (plan->has_socket && !plan->has_session_id)) {
        fail("sandbox session identity flag is invalid");
    }
    if (plan->has_session_id) plan->session_id = read_string();
    plan->has_projected_home = read_u8();
    if (plan->has_projected_home > 1) fail("sandbox projected home flag is invalid");
    if (plan->has_projected_home) {
        plan->projected_home = read_string();
        absolute_normalized(plan->projected_home.value, 0);
        plan->projected_home_writable = read_u8();
        if (plan->projected_home_writable > 1) fail("sandbox projected home mutability flag is invalid");
        struct stat details;
        struct statfs filesystem;
        if (stat(plan->projected_home.value, &details) != 0 || !S_ISDIR(details.st_mode) ||
            details.st_uid != getuid() || statfs(plan->projected_home.value, &filesystem) != 0 ||
            (unsigned long)filesystem.f_type != 0x65735546UL) {
            fail("sandbox projected home is not an owned FUSE mount");
        }
    }
    plan->has_host_rx_manifest = read_u8();
    if (plan->has_host_rx_manifest > 1) fail("sandbox host-rx manifest flag is invalid");
    if (plan->has_host_rx_manifest) {
        plan->host_rx_manifest = read_string();
        absolute_normalized(plan->host_rx_manifest.value, 0);
        struct stat details;
        if (lstat(plan->host_rx_manifest.value, &details) != 0 || !S_ISREG(details.st_mode) ||
            details.st_uid != getuid() || (details.st_mode & 022) != 0) {
            fail("sandbox host-rx manifest is unsafe");
        }
        if (!plan->has_projected_home || strncmp(plan->command[0].value, "/home/sandbox/", 14) != 0) {
            fail("sandbox host-rx command is invalid");
        }
    }
    if (transport_is_decoded) {
        if (decoded_plan_offset != decoded_plan_length) fail("sandbox plan has trailing bytes");
    } else {
        unsigned char extra;
        if (read(STDIN_FILENO, &extra, 1) != 0) fail("sandbox plan has trailing bytes");
    }
}

static size_t read_line_fd(int fd, char *buffer, size_t capacity) {
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

static int connect_session_socket(const char *path) {
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) return -1;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path)) {
        close(descriptor);
        return -1;
    }
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static void relay_session(int relay_fd, const Plan *plan, pid_t child) {
    char request[MAX_PLAN / 4];
    char response[MAX_PLAN / 4];
    for (;;) {
        int status;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) break;
        if (waited < 0) fail("sandbox child wait failed");
        struct pollfd descriptor = {.fd = relay_fd, .events = POLLIN};
        int ready = poll(&descriptor, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) fail("sandbox session relay poll failed");
        if (ready == 0) continue;
        size_t request_length = read_line_fd(relay_fd, request, sizeof(request));
        if (request_length == 0) break;
        int session = connect_session_socket(plan->socket.value);
        if (session < 0) fail("sandbox session socket could not be reached");
        if (write(session, request, request_length) != (ssize_t)request_length) {
            close(session);
            fail("sandbox session request relay failed");
        }
        size_t response_length = read_line_fd(session, response, sizeof(response));
        close(session);
        if (response_length == 0) fail("sandbox session response relay failed");
        if (write(relay_fd, response, response_length) != (ssize_t)response_length) {
            fail("sandbox session response forwarding failed");
        }
    }
    close(relay_fd);
    int status;
    if (waitpid(child, &status, 0) < 0) fail("sandbox child wait failed");
    if (WIFEXITED(status)) exit(WEXITSTATUS(status));
    exit(70);
}

static void close_unlisted_fds(int preserve_fd) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) fail("sandbox descriptor inventory is unavailable");
    int directory_fd = dirfd(directory);
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long value = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || value < 3 || value == preserve_fd || value == directory_fd) continue;
        close((int)value);
    }
    closedir(directory);
}

extern char **environ;

static void add(char **argv, size_t *count, size_t capacity, const char *value);

static size_t environment_count(void) {
    size_t count = 0;
    for (char **entry = environ; entry != NULL && *entry != NULL; ++entry) {
        const char *separator = strchr(*entry, '=');
        if (separator == NULL || separator == *entry || (size_t)(separator - *entry) > 255U ||
            strlen(separator + 1) > MAX_STRING) {
            fail("sanitized environment entry is invalid");
        }
        size_t name_length = (size_t)(separator - *entry);
        if ((name_length == 4U && strncmp(*entry, "HOME", 4U) == 0) ||
            (name_length == 4U && strncmp(*entry, "PATH", 4U) == 0)) {
            continue;
        }
        if (++count > MAX_ENVIRONMENT) fail("sanitized environment has too many entries");
    }
    return count;
}

static void add_environment(char **argv, size_t *count, size_t capacity) {
    for (char **entry = environ; entry != NULL && *entry != NULL; ++entry) {
        const char *separator = strchr(*entry, '=');
        size_t name_length = (size_t)(separator - *entry);
        if ((name_length == 4U && strncmp(*entry, "HOME", 4U) == 0) ||
            (name_length == 4U && strncmp(*entry, "PATH", 4U) == 0)) {
            continue;
        }
        char *name = calloc(name_length + 1U, 1U);
        if (name == NULL) fail("sandbox environment allocation failed");
        memcpy(name, *entry, name_length);
        add(argv, count, capacity, "--setenv");
        add(argv, count, capacity, name);
        add(argv, count, capacity, separator + 1);
    }
}

static void add(char **argv, size_t *count, size_t capacity, const char *value) {
    if (*count + 1 >= capacity) fail("sandbox launcher argv exceeds fixed bound");
    argv[(*count)++] = (char *)value;
}

static void execute_plan(const Plan *plan) {
    size_t environment_entries = environment_count();
    size_t capacity = 136 + (size_t)plan->command_count +
                      (size_t)(plan->remote_count + plan->socket_count) * 3 +
                      environment_entries * 3;
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
    const char *path = getenv("PATH");
    if (path == NULL) path = "/usr/local/bin:/usr/bin:/bin";
    if (strlen(path) > MAX_STRING) fail("sanitized PATH is invalid");
    add(argv, &count, capacity, "--setenv"); add(argv, &count, capacity, "PATH"); add(argv, &count, capacity, path);
    add_environment(argv, &count, capacity);
    add(argv, &count, capacity, "--cap-drop"); add(argv, &count, capacity, "ALL");
    if (plan->network == 1) add(argv, &count, capacity, "--unshare-net");
    for (uint32_t index = 0; index < plan->remote_count; ++index) {
        add(argv, &count, capacity, plan->remote[index].mode == 1 ? "--bind" : "--ro-bind");
        add(argv, &count, capacity, plan->remote[index].source.value);
        add(argv, &count, capacity, plan->remote[index].target.value);
    }
    for (uint32_t index = 0; index < plan->socket_count; ++index) {
        add(argv, &count, capacity, "--ro-bind");
        add(argv, &count, capacity, plan->socket_binding[index].path.value);
        add(argv, &count, capacity, plan->socket_binding[index].path.value);
    }
    if (plan->has_projected_home) {
        add(argv, &count, capacity, plan->projected_home_writable ? "--bind" : "--ro-bind");
        add(argv, &count, capacity, plan->projected_home.value);
        add(argv, &count, capacity, "/home/sandbox");
    }
    if (plan->has_host_rx_manifest) {
        add(argv, &count, capacity, "--ro-bind"); add(argv, &count, capacity, plan->host_rx_manifest.value);
        add(argv, &count, capacity, "/tmp/aspr-host-rx.allow");
    }
    if (plan->has_socket) {
        if (!plan->has_host_rx_manifest) {
            add(argv, &count, capacity, "--dir"); add(argv, &count, capacity, "/run");
            add(argv, &count, capacity, "--dir"); add(argv, &count, capacity, "/run/astral-project");
        }
        add(argv, &count, capacity, "--dir"); add(argv, &count, capacity, "/run/astral-project");
        add(argv, &count, capacity, "--setenv"); add(argv, &count, capacity, "ASPR_SESSION_SOCKET");
        add(argv, &count, capacity, "/run/astral-project/session.sock");
        add(argv, &count, capacity, "--setenv"); add(argv, &count, capacity, "ASPR_SESSION_ID");
        add(argv, &count, capacity, plan->session_id.value);
        add(argv, &count, capacity, "--setenv"); add(argv, &count, capacity, "ASPR_SESSION_RELAY_FD");
        add(argv, &count, capacity, "3");
    }
    add(argv, &count, capacity, "--");
    add(argv, &count, capacity, ENTRY);
    add(argv, &count, capacity, "--aspr-hardening");
    if (plan->has_socket) {
        add(argv, &count, capacity, "--aspr-socket-root");
        add(argv, &count, capacity, "/run/astral-project");
    }
    for (uint32_t index = 0; index < plan->remote_count; ++index) {
        add(argv, &count, capacity, plan->remote[index].mode == 1 ? "--aspr-write-root" : "--aspr-read-root");
        add(argv, &count, capacity, plan->remote[index].target.value);
    }
    if (plan->has_projected_home) {
        add(argv, &count, capacity, plan->projected_home_writable ? "--aspr-write-root" : "--aspr-read-root");
        add(argv, &count, capacity, "/home/sandbox");
    }
    add(argv, &count, capacity, "--");
    if (plan->has_host_rx_manifest) add(argv, &count, capacity, HOST_RX);
    for (uint32_t index = 0; index < plan->command_count; ++index) add(argv, &count, capacity, plan->command[index].value);
    argv[count] = NULL;
    if (!plan->has_socket) {
        close_unlisted_fds(-1);
        execv(BWRAP, argv);
        fail("fixed /usr/bin/bwrap could not execute");
    }
    int relay[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, relay) != 0) {
        fail("sandbox session relay could not be created");
    }
    pid_t child = fork();
    if (child < 0) fail("sandbox launcher could not fork");
    if (child == 0) {
        close(relay[0]);
        if (dup2(relay[1], 3) < 0) fail("sandbox session relay descriptor could not be installed");
        close(relay[1]);
        close_unlisted_fds(3);
        if (setenv("ASPR_SESSION_RELAY_FD", "3", 1) != 0) {
            fail("sandbox session relay environment could not be set");
        }
        execv(BWRAP, argv);
        fail("fixed /usr/bin/bwrap could not execute");
    }
    close(relay[1]);
    relay_session(relay[0], plan, child);
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) fail("fixed launcher accepts no command-line arguments");
    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &saved_terminal) == 0) {
        struct termios raw = saved_terminal;
        cfmakeraw(&raw);
        if (tcsetattr(STDIN_FILENO, TCSADRAIN, &raw) == 0) terminal_saved = 1;
    }
    Plan plan = {0};
    prepare_transport();
    parse_plan(&plan);
    restore_terminal();
    execute_plan(&plan);
    return 70;
}
