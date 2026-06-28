#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <unistd.h>

static void deliberately_unreachable_import_references(void) {
    struct sockaddr_in address = {0};
    char buffer[16] = {0};
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    (void)ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    (void)system("true");
    (void)dlopen("libc.so.6", RTLD_LAZY);
    (void)dlsym(NULL, "puts");
    (void)connect(
        socket_fd,
        (const struct sockaddr *)&address,
        sizeof(address)
    );
    (void)send(socket_fd, buffer, sizeof(buffer), 0);
    (void)recv(socket_fd, buffer, sizeof(buffer), 0);
    (void)mprotect(buffer, sizeof(buffer), PROT_READ | PROT_WRITE);
    char *const harmless_argv[] = {"/bin/true", NULL};
    char *const harmless_envp[] = {NULL};
    (void)execve("/bin/true", harmless_argv, harmless_envp);
}

int main(int argc, char **argv) {
    (void)argv;

    if (argc == -1) {
        deliberately_unreachable_import_references();
    }

    puts("Harmless ELF Capability Mapper test fixture.");
    return 0;
}
