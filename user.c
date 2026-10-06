#include "common.h"
#include "net_utils.h"
#include "user_commands.h"

int main(int argc, char *argv[]) {
    char *peerport = NULL;
    char *dsip = DEFAULT_DS_IP;
    char *dsport = DEFAULT_DS_PORT;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            peerport = argv[++i];
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            dsip = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            dsport = argv[++i];
        }
    }

    if (peerport == NULL) {
        fprintf(stderr, "Usage: %s -m <peerport> [-n <DSIP>] [-p <DSport>]\n", argv[0]);
        exit(1);
    }

    int fd, errcode;
    struct addrinfo hints, *res;
    char command[MAX_BUFFER];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    errcode = getaddrinfo(dsip, dsport, &hints, &res);
    if (errcode != 0) {
        fprintf(stderr, "Error: Failed to resolve Directory Server address\n");
        close(fd);
        exit(1);
    }

    SessionState session;
    memset(&session, 0, sizeof(session));
    strncpy(session.peerport, peerport, sizeof(session.peerport) - 1);

    while (1) {
        printf("> ");
        fflush(stdout);
        if (fgets(command, sizeof(command), stdin) == NULL) break;

        char op[32] = "", arg1[32] = "", arg2[32] = "";
        int num_args = sscanf(command, "%s %s %s", op, arg1, arg2);

        if (strcmp(op, "login") == 0) {
            handle_login(fd, res, &session, arg1, arg2, num_args);
        } else if (strcmp(op, "logout") == 0) {
            handle_logout(fd, res, &session);
        } else if (strcmp(op, "unregister") == 0) {
            handle_unregister(fd, res, &session);
        } else if (strcmp(op, "publish") == 0) {
            handle_publish(fd, res, &session, arg1, arg2, num_args);
        } else if (strcmp(op, "remove") == 0) {
            handle_remove(fd, res, &session, arg1, num_args);
        } else if (strcmp(op, "list") == 0) {
            handle_list(fd, res);
        } else if (strcmp(op, "versions") == 0) {
            handle_versions(dsip, dsport, arg1, num_args);
        } else if (strcmp(op, "exit") == 0) {
            if (session.logged_in) {
                printf("Error: Logout before exiting\n");
            } else {
                break;
            }
        } else if (strlen(op) > 0) {
            printf("Unknown command: %s\n", op);
        }
    }

    freeaddrinfo(res);
    close(fd);
    return 0;
}