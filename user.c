#include "common.h"
#include "net_utils.h"
#include "user_commands.h"

static volatile sig_atomic_t g_got_sigint = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_got_sigint++;
}

static int check_sigint_exit(SessionState *session, int *need_prompt) {
    if (!g_got_sigint) return 0;
    g_got_sigint = 0;

    if (session->logged_in) {
        printf("\nError: Logout before exiting\n");
        if (need_prompt) *need_prompt = 1;
        return 0;
    } else {
        printf("\n");
        return 1;
    }
}

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

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int fd;
    struct addrinfo *res = NULL;
    char command[MAX_BUFFER];

    if (init_udp_client(dsip, dsport, &fd, &res) != 0) {
        exit(1);
    }

    int tcp_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_server_fd == -1) {
        perror("socket TCP server");
        close_udp_client(fd, res);
        exit(1);
    }

    int opt = 1;
    if (setsockopt(tcp_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons((uint16_t)atoi(peerport));

    if (bind(tcp_server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind peerport");
        close(tcp_server_fd);
        close_udp_client(fd, res);
        exit(1);
    }

    if (listen(tcp_server_fd, 5) == -1) {
        perror("listen");
        close(tcp_server_fd);
        close_udp_client(fd, res);
        exit(1);
    }

    SessionState session;
    memset(&session, 0, sizeof(session));
    strncpy(session.peerport, peerport, sizeof(session.peerport) - 1);
    session.peerport[sizeof(session.peerport) - 1] = '\0';

    VersionsCache versions_cache;
    memset(&versions_cache, 0, sizeof(versions_cache));

    int need_prompt = 1;

    while (1) {
        if (check_sigint_exit(&session, &need_prompt)) break;

        if (need_prompt) {
            printf("> ");
            fflush(stdout);
            need_prompt = 0;
        }

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(tcp_server_fd, &read_fds);
        int max_fd = (STDIN_FILENO > tcp_server_fd) ? STDIN_FILENO : tcp_server_fd;

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (activity < 0) {
            if (errno == EINTR) {
                if (check_sigint_exit(&session, &need_prompt)) break;
                continue;
            }
            perror("select");
            break;
        }

        // Lidar com pedidos de transferência de ficheiros usando processos paralelos
        if (FD_ISSET(tcp_server_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int conn_fd = accept(tcp_server_fd, (struct sockaddr *)&client_addr, &client_len);

            if (conn_fd != -1) {
                pid_t pid = fork();
                if (pid < 0) {
                    perror("fork");
                    close(conn_fd);
                } else if (pid == 0) {
                    // Processo Filho: gere o download
                    signal(SIGINT, SIG_IGN);
                    close(tcp_server_fd); // Filho não precisa do socket de escuta
                    close_udp_client(fd, res);
                    handle_peer_request(conn_fd);
                    exit(0); // Termina imediatamente após a transferência
                } else {
                    // Processo Pai: fecha o socket do cliente e volta para o select()
                    close(conn_fd);
                }
            }
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (fgets(command, sizeof(command), stdin) == NULL) {
                if (check_sigint_exit(&session, &need_prompt)) break;
                if (session.logged_in) {
                    printf("Error: Logout before exiting\n");
                    need_prompt = 1;
                    continue;
                }
                break;
            }
            need_prompt = 1;

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
                handle_versions(dsip, dsport, arg1, num_args, &versions_cache);
            } else if (strcmp(op, "where") == 0) {
                handle_where(fd, res, dsip, dsport, &versions_cache, arg1, arg2, num_args);
            } else if (strcmp(op, "get") == 0) {
                handle_get(fd, res, dsip, dsport, &versions_cache, arg1, arg2, num_args);
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
    }

    close(tcp_server_fd);
    close_udp_client(fd, res);
    return 0;
}
