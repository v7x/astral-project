#ifndef ASPR_HARDENING_H
#define ASPR_HARDENING_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ASPR_LANDLOCK_CREATE_RULESET 444
#define ASPR_LANDLOCK_ADD_RULE 445
#define ASPR_LANDLOCK_RESTRICT_SELF 446
#define ASPR_LANDLOCK_CREATE_RULESET_VERSION 1
#define ASPR_LANDLOCK_RULE_TYPE_PATH_BENEATH 1
#define ASPR_LANDLOCK_MINIMUM_ABI 3
#define ASPR_LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define ASPR_LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define ASPR_LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define ASPR_LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define ASPR_LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define ASPR_LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define ASPR_LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#define ASPR_LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#define ASPR_LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define ASPR_LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#define ASPR_LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#define ASPR_LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define ASPR_LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#define ASPR_LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#define ASPR_LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#define ASPR_PR_SET_NO_NEW_PRIVS 38
#define ASPR_PR_CAPBSET_DROP 24

struct aspr_landlock_ruleset_attr {
    uint64_t handled_access_fs;
};

struct aspr_landlock_path_beneath_attr {
    uint64_t allowed_access;
    int parent_fd;
};

static void aspr_hardening_fail(const char *message) {
    fail(message);
}

static void aspr_hardening_require_abi(void) {
    long abi = syscall(ASPR_LANDLOCK_CREATE_RULESET, NULL, 0,
                       ASPR_LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < ASPR_LANDLOCK_MINIMUM_ABI) {
        aspr_hardening_fail(abi < 0 ? "Landlock ABI is unavailable" :
                            "Landlock ABI is below required minimum");
    }
}

static void aspr_hardening_add_rule(int ruleset, const char *path, int role) {
    int descriptor = open(path, O_PATH | O_CLOEXEC);
    if (descriptor < 0) {
        dprintf(STDERR_FILENO, "ASPR_SANDBOX_ENTRY: hardening root unavailable: %s\\n", path);
        aspr_hardening_fail("hardening root is unavailable");
    }
    const uint64_t read_access = ASPR_LANDLOCK_ACCESS_FS_EXECUTE |
        ASPR_LANDLOCK_ACCESS_FS_READ_FILE | ASPR_LANDLOCK_ACCESS_FS_READ_DIR;
    const uint64_t device_access = read_access | ASPR_LANDLOCK_ACCESS_FS_WRITE_FILE;
    const uint64_t regular_access = read_access | ASPR_LANDLOCK_ACCESS_FS_WRITE_FILE |
        ASPR_LANDLOCK_ACCESS_FS_REMOVE_DIR | ASPR_LANDLOCK_ACCESS_FS_REMOVE_FILE |
        ASPR_LANDLOCK_ACCESS_FS_MAKE_DIR | ASPR_LANDLOCK_ACCESS_FS_MAKE_REG |
        ASPR_LANDLOCK_ACCESS_FS_MAKE_SYM | ASPR_LANDLOCK_ACCESS_FS_REFER |
        ASPR_LANDLOCK_ACCESS_FS_TRUNCATE;
    const uint64_t socket_access = read_access |
        ASPR_LANDLOCK_ACCESS_FS_MAKE_SOCK | ASPR_LANDLOCK_ACCESS_FS_REMOVE_FILE;
    struct aspr_landlock_path_beneath_attr rule = {
        .allowed_access = role == 3 ? socket_access :
            (role == 2 ? device_access : (role ? regular_access : read_access)),
        .parent_fd = descriptor,
    };
    if (syscall(ASPR_LANDLOCK_ADD_RULE, ruleset,
                ASPR_LANDLOCK_RULE_TYPE_PATH_BENEATH, &rule, 0) != 0) {
        dprintf(STDERR_FILENO, "ASPR_SANDBOX_ENTRY: Landlock rule failed for %s: %s\\n",
                path, strerror(errno));
        close(descriptor);
        aspr_hardening_fail("Landlock rule loading failed");
    }
    close(descriptor);
}

static void __attribute__((unused)) aspr_harden_roots(
    const char *const *read_roots, size_t read_count,
    const char *const *write_roots, size_t write_count, const char *device_root) {
    aspr_hardening_require_abi();
    const uint64_t handled = ASPR_LANDLOCK_ACCESS_FS_EXECUTE |
        ASPR_LANDLOCK_ACCESS_FS_WRITE_FILE | ASPR_LANDLOCK_ACCESS_FS_READ_FILE |
        ASPR_LANDLOCK_ACCESS_FS_READ_DIR | ASPR_LANDLOCK_ACCESS_FS_REMOVE_DIR |
        ASPR_LANDLOCK_ACCESS_FS_REMOVE_FILE | ASPR_LANDLOCK_ACCESS_FS_MAKE_CHAR |
        ASPR_LANDLOCK_ACCESS_FS_MAKE_DIR | ASPR_LANDLOCK_ACCESS_FS_MAKE_REG |
        ASPR_LANDLOCK_ACCESS_FS_MAKE_SOCK | ASPR_LANDLOCK_ACCESS_FS_MAKE_FIFO |
        ASPR_LANDLOCK_ACCESS_FS_MAKE_BLOCK | ASPR_LANDLOCK_ACCESS_FS_MAKE_SYM |
        ASPR_LANDLOCK_ACCESS_FS_REFER | ASPR_LANDLOCK_ACCESS_FS_TRUNCATE;
    struct aspr_landlock_ruleset_attr attr = {.handled_access_fs = handled};
    int ruleset = syscall(ASPR_LANDLOCK_CREATE_RULESET, &attr, sizeof(attr), 0);
    if (ruleset < 0) aspr_hardening_fail("Landlock ABI is unavailable");
    for (size_t index = 0; index < read_count; ++index) {
        aspr_hardening_add_rule(ruleset, read_roots[index], 0);
    }
    for (size_t index = 0; index < write_count; ++index) {
        aspr_hardening_add_rule(ruleset, write_roots[index], 1);
    }
    if (device_root != NULL) aspr_hardening_add_rule(ruleset, device_root, 2);
    if (syscall(SYS_prctl, ASPR_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        close(ruleset);
        aspr_hardening_fail("no_new_privs could not be enabled");
    }
    struct rlimit limit = {.rlim_cur = 0, .rlim_max = 0};
    if (setrlimit(RLIMIT_CORE, &limit) != 0) {
        close(ruleset);
        aspr_hardening_fail("core dumps could not be disabled");
    }
    limit.rlim_cur = 1024;
    limit.rlim_max = 1024;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
        close(ruleset);
        aspr_hardening_fail("file descriptor limit could not be set");
    }
    limit.rlim_cur = 128;
    limit.rlim_max = 128;
    if (setrlimit(RLIMIT_NPROC, &limit) != 0) {
        close(ruleset);
        aspr_hardening_fail("process limit could not be set");
    }
    for (int capability = 0; capability < 64; ++capability) {
        if (syscall(SYS_prctl, ASPR_PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 &&
            errno != EPERM && errno != EINVAL) {
            close(ruleset);
            aspr_hardening_fail("capability bounding set could not be dropped");
        }
    }
    if (syscall(ASPR_LANDLOCK_RESTRICT_SELF, ruleset, 0) != 0) {
        close(ruleset);
        aspr_hardening_fail("Landlock restrictions could not be enabled");
    }
    close(ruleset);
}

static void __attribute__((unused)) aspr_harden_payload(
    const char *const *read_roots, size_t read_count,
    const char *const *write_roots, size_t write_count,
    const char *const *socket_roots, size_t socket_count) {
    aspr_hardening_require_abi();
    const uint64_t handled = ASPR_LANDLOCK_ACCESS_FS_EXECUTE |
        ASPR_LANDLOCK_ACCESS_FS_WRITE_FILE | ASPR_LANDLOCK_ACCESS_FS_READ_FILE |
        ASPR_LANDLOCK_ACCESS_FS_READ_DIR |
        ASPR_LANDLOCK_ACCESS_FS_REMOVE_DIR | ASPR_LANDLOCK_ACCESS_FS_REMOVE_FILE |
        ASPR_LANDLOCK_ACCESS_FS_MAKE_CHAR | ASPR_LANDLOCK_ACCESS_FS_MAKE_DIR |
        ASPR_LANDLOCK_ACCESS_FS_MAKE_REG | ASPR_LANDLOCK_ACCESS_FS_MAKE_SOCK |
        ASPR_LANDLOCK_ACCESS_FS_MAKE_FIFO | ASPR_LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        ASPR_LANDLOCK_ACCESS_FS_MAKE_SYM | ASPR_LANDLOCK_ACCESS_FS_REFER |
        ASPR_LANDLOCK_ACCESS_FS_TRUNCATE;
    struct aspr_landlock_ruleset_attr attr = {.handled_access_fs = handled};
    int ruleset = syscall(ASPR_LANDLOCK_CREATE_RULESET, &attr, sizeof(attr), 0);
    if (ruleset < 0) aspr_hardening_fail("Landlock ABI is unavailable");
    aspr_hardening_add_rule(ruleset, "/usr", 0);
    aspr_hardening_add_rule(ruleset, "/dev", 2);
    aspr_hardening_add_rule(ruleset, "/proc", 0);
    if (access("/run", F_OK) == 0) aspr_hardening_add_rule(ruleset, "/run", 3);
    for (size_t index = 0; index < socket_count; ++index) {
        aspr_hardening_add_rule(ruleset, socket_roots[index], 3);
    }
    aspr_hardening_add_rule(ruleset, "/tmp", 1);
    for (size_t index = 0; index < read_count; ++index) {
        aspr_hardening_add_rule(ruleset, read_roots[index], 0);
    }
    for (size_t index = 0; index < write_count; ++index) {
        aspr_hardening_add_rule(ruleset, write_roots[index], 1);
    }
    if (syscall(SYS_prctl, ASPR_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        close(ruleset);
        aspr_hardening_fail("no_new_privs could not be enabled");
    }
    struct rlimit limit = {.rlim_cur = 0, .rlim_max = 0};
    if (setrlimit(RLIMIT_CORE, &limit) != 0) {
        close(ruleset);
        aspr_hardening_fail("core dumps could not be disabled");
    }
    limit.rlim_cur = 1024;
    limit.rlim_max = 1024;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
        close(ruleset);
        aspr_hardening_fail("file descriptor limit could not be set");
    }
    limit.rlim_cur = 128;
    limit.rlim_max = 128;
    if (setrlimit(RLIMIT_NPROC, &limit) != 0) {
        close(ruleset);
        aspr_hardening_fail("process limit could not be set");
    }
    for (int capability = 0; capability < 64; ++capability) {
        if (syscall(SYS_prctl, ASPR_PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 &&
            errno != EPERM && errno != EINVAL) {
            close(ruleset);
            aspr_hardening_fail("capability bounding set could not be dropped");
        }
    }
    if (syscall(ASPR_LANDLOCK_RESTRICT_SELF, ruleset, 0) != 0) {
        close(ruleset);
        aspr_hardening_fail("Landlock restrictions could not be enabled");
    }
    close(ruleset);
}

#endif
