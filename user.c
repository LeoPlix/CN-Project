#include "common.h"
#include "net_utils.h"
#include "user_commands.h"

int main(int argc, char *argv[]) {
    char *peerport = NULL;
    char *dsip = DEFAULT_DS_IP;
    char *dsport = DEFAULT_DS_PORT;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0) {
            if (i + 1 < argc) {
                peerport = argv[++i];
            } else {
                fprintf(stderr, "Error: Missing value for -m\n");
                exit(1);
            }
        } else if (strcmp(argv[i], "-n") == 0) {
            if (i + 1 < argc) {
                dsip = argv[++i];
            } else {
                fprintf(stderr, "Error: Missing value for -n\n");
                exit(1);
            }
        } else if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                dsport = argv[++i];
            } else {
                fprintf(stderr, "Error: Missing value for -p\n");
                exit(1);
            }
        } else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            fprintf(stderr, "Usage: %s -m <peerport> [-n <DSIP>] [-p <DSport>]\n", argv[0]);
            exit(1);
        }
    }

    if (peerport == NULL) {
        fprintf(stderr, "Usage: %s -m <peerport> [-n <DSIP>] [-p <DSport>]\n", argv[0]);
        exit(1);
    }

    if (!is_valid_port(peerport)) {
        fprintf(stderr, "Error: Invalid peerport '%s' (must be integer between 1 and 65535)\n", peerport);
        exit(1);
    }

    if (!is_valid_port(dsport)) {
        fprintf(stderr, "Error: Invalid DSport '%s' (must be integer between 1 and 65535)\n", dsport);
        exit(1);
    }

    int fd;
    struct addrinfo *res = NULL;
    char command[MAX_BUFFER];

    if (init_udp_client(dsip, dsport, &fd, &res) != 0) {
        exit(1);
    }

    SessionState session;
    memset(&session, 0, sizeof(session));
    strncpy(session.peerport, peerport, sizeof(session.peerport) - 1);

    while (1) {
        printf("> ");
        fflush(stdout);
        if (fgets(command, sizeof(command), stdin) == NULL) break;

        char op[64] = "", arg1[128] = "", arg2[128] = "", extra[128] = "";
        int num_args = sscanf(command, "%63s %127s %127s %127s", op, arg1, arg2, extra);
        if (num_args <= 0) continue;

        if (strcmp(op, "login") == 0) {
            handle_login(fd, res, &session, arg1, arg2, num_args);
        } else if (strcmp(op, "logout") == 0) {
            handle_logout(fd, res, &session, num_args);
        } else if (strcmp(op, "unregister") == 0) {
            handle_unregister(fd, res, &session, num_args);
        } else if (strcmp(op, "publish") == 0) {
            handle_publish(fd, res, &session, arg1, arg2, num_args);
        } else if (strcmp(op, "remove") == 0) {
            handle_remove(fd, res, &session, arg1, num_args);
        } else if (strcmp(op, "list") == 0) {
            handle_list(fd, res, num_args);
        } else if (strcmp(op, "versions") == 0) {
            handle_versions(dsip, dsport, arg1, num_args);
        } else if (strcmp(op, "exit") == 0) {
            if (num_args != 1) {
                printf("Usage: exit\n");
            } else if (session.logged_in) {
                printf("Error: Logout before exiting\n");
            } else {
                break;
            }
        } else if (strlen(op) > 0) {
            printf("Unknown command: %s\n", op);
        }
    }

    close_udp_client(fd, res);
    return 0;
}