/* Packet 15A fixed native mapping worker. No mount, exec, or command interface. */
#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAP_READY_FD 3
#define MAP_CONTINUE_FD 4

static void die(const char *message) {
    perror(message);
    _exit(111);
}

static void write_byte(int descriptor, char value) {
    if (write(descriptor, &value, 1) != 1) {
        die("worker synchronization write");
    }
}

static char read_byte(int descriptor) {
    char value;
    if (read(descriptor, &value, 1) != 1) {
        die("worker synchronization read");
    }
    return value;
}

int main(int argc, char *argv[]) {
    (void)argv;
    if (argc != 1) {
        fputs("aspr namespace worker accepts no arguments\n", stderr);
        return 64;
    }
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
        die("unshare");
    }
    write_byte(MAP_READY_FD, 'R');
    if (read_byte(MAP_CONTINUE_FD) != 'C') {
        fputs("invalid worker continuation\n", stderr);
        return 65;
    }
    return 0;
}
