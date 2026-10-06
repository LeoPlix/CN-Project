#include "user_commands.h"
#include "net_utils.h"

void handle_login(int fd, struct addrinfo *res, SessionState *session, const char *arg1, const char *arg2, int num_args) {
    char buffer[MAX_BUFFER];

    if (session->logged_in) {
        printf("Error: Already logged in\n");
        return;
    }
    if (num_args == 3 && strlen(arg1) == 6 && strlen(arg2) == 8) {
        sprintf(buffer, "LIN %s %s %s\n", arg1, arg2, session->peerport);
        sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);
        
        socklen_t addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in addr;
        int n = recvfrom(fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&addr, &addrlen);
        if (n != -1) {
            buffer[n] = '\0';
            if (strncmp(buffer, "RLI OK", 6) == 0) {
                printf("Successful login\n");
                session->logged_in = 1;
                strcpy(session->uid, arg1);
                strcpy(session->pass, arg2);
            } else if (strncmp(buffer, "RLI REG", 7) == 0) {
                printf("User registered\n");
                session->logged_in = 1;
                strcpy(session->uid, arg1);
                strcpy(session->pass, arg2);
            } else if (strncmp(buffer, "RLI NOK", 7) == 0) {
                printf("Incorrect password\n");
            } else {
                printf("Unexpected response: %s\n", buffer);
            }
        }
    } else {
        printf("Usage: login <UID> <password>\n");
    }
}

void handle_logout(int fd, struct addrinfo *res, SessionState *session) {
    char buffer[MAX_BUFFER];

    if (!session->logged_in) {
        printf("Error: Not logged in\n");
        return;
    }

    sprintf(buffer, "LOU %s %s\n", session->uid, session->pass);
    sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);

    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    int n = recvfrom(fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&addr, &addrlen);
    if (n != -1) {
        buffer[n] = '\0';
        if (strncmp(buffer, "RLO OK", 6) == 0) {
            printf("Successful logout\n");
            session->logged_in = 0;
            session->uid[0] = '\0';
            session->pass[0] = '\0';
        } else if (strncmp(buffer, "RLO NLG", 7) == 0) {
            printf("Error: User not logged in\n");
        } else if (strncmp(buffer, "RLO UNR", 7) == 0) {
            printf("Error: Unknown user\n");
        } else if (strncmp(buffer, "RLO WRP", 7) == 0) {
            printf("Error: Incorrect password\n");
        } else {
            printf("Unexpected response: %s\n", buffer);
        }
    }
}

void handle_unregister(int fd, struct addrinfo *res, SessionState *session) {
    char buffer[MAX_BUFFER];

    if (!session->logged_in) {
        printf("Error: Not logged in\n");
        return;
    }

    sprintf(buffer, "UNR %s %s\n", session->uid, session->pass);
    sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);

    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    int n = recvfrom(fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&addr, &addrlen);
    if (n != -1) {
        buffer[n] = '\0';
        if (strncmp(buffer, "RUR OK", 6) == 0) {
            printf("Successful unregister\n");
            session->logged_in = 0;
            session->uid[0] = '\0';
            session->pass[0] = '\0';
        } else if (strncmp(buffer, "RUR NOK", 7) == 0) {
            printf("Error: User not logged in\n");
        } else if (strncmp(buffer, "RUR UNR", 7) == 0) {
            printf("Error: Unknown user\n");
        } else if (strncmp(buffer, "RUR WRP", 7) == 0) {
            printf("Error: Incorrect password\n");
        } else {
            printf("Unexpected response: %s\n", buffer);
        }
    }
}

void handle_publish(int fd, struct addrinfo *res, SessionState *session, const char *filename, const char *label, int num_args) {
    char buffer[MAX_BUFFER];

    if (!session->logged_in) {
        printf("Error: Not logged in\n");
        return;
    }
    if (num_args == 3) {
        struct stat st;
        if (stat(filename, &st) == 0) {
            long fsize = st.st_size;
            if (fsize > 10000000) {
                printf("Error: File exceeds max size (10MB)\n");
                return;
            }
            sprintf(buffer, "PUB %s %s %s %ld %s\n", session->uid, session->pass, filename, fsize, label);
            sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);

            socklen_t addrlen = sizeof(struct sockaddr_in);
            struct sockaddr_in addr;
            int n = recvfrom(fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&addr, &addrlen);
            if (n != -1) {
                buffer[n] = '\0';
                if (strncmp(buffer, "RPB OK", 6) == 0)
                    printf("File published\n");
                else if (strncmp(buffer, "RPB NLG", 7) == 0)
                    printf("Error: User not logged in\n");
                else if (strncmp(buffer, "RPB WRP", 7) == 0)
                    printf("Error: Incorrect password\n");
                else
                    printf("Publish error: %s\n", buffer);
            }
        } else {
            printf("Error: File '%s' not found\n", filename);
        }
    } else {
        printf("Usage: publish <filename> <label>\n");
    }
}

void handle_remove(int fd, struct addrinfo *res, SessionState *session, const char *filename, int num_args) {
    char buffer[MAX_BUFFER];

    if (!session->logged_in) {
        printf("Error: Not logged in\n");
        return;
    }
    if (num_args == 2) {
        sprintf(buffer, "REM %s %s %s\n", session->uid, session->pass, filename);
        sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);

        socklen_t addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in addr;
        int n = recvfrom(fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&addr, &addrlen);
        if (n != -1) {
            buffer[n] = '\0';
            if (strncmp(buffer, "RRM OK", 6) == 0)
                printf("File removed\n");
            else if (strncmp(buffer, "RRM NOK", 7) == 0)
                printf("Error: File not published\n");
            else
                printf("Remove error: %s\n", buffer);
        }
    } else {
        printf("Usage: remove <filename>\n");
    }
}

void handle_list(int fd, struct addrinfo *res) {
    char buffer[MAX_BUFFER];

    sprintf(buffer, "LST\n");
    sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);

    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    int n = recvfrom(fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&addr, &addrlen);
    if (n != -1) {
        buffer[n] = '\0';
        if (strncmp(buffer, "RLS NOK", 7) == 0) {
            printf("No files available\n");
        } else if (strncmp(buffer, "RLS OK", 6) == 0) {
            char *token = strtok(buffer + 7, " \n");
            while (token != NULL) {
                printf("%s\n", token);
                token = strtok(NULL, " \n");
            }
        } else {
            printf("Unexpected response: %s\n", buffer);
        }
    }
}

void handle_versions(const char *dsip, const char *dsport, const char *filename, int num_args) {
    char buffer[MAX_BUFFER];

    if (num_args == 2) {
        int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (tcp_fd == -1) {
            perror("socket");
            return;
        }

        struct addrinfo hints_tcp, *res_tcp;
        memset(&hints_tcp, 0, sizeof hints_tcp);
        hints_tcp.ai_family = AF_INET;
        hints_tcp.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(dsip, dsport, &hints_tcp, &res_tcp) != 0) {
            fprintf(stderr, "Error: Failed to resolve Directory Server address\n");
            close(tcp_fd);
            return;
        }

        if (connect(tcp_fd, res_tcp->ai_addr, res_tcp->ai_addrlen) == -1) {
            perror("connect");
            freeaddrinfo(res_tcp);
            close(tcp_fd);
            return;
        }

        sprintf(buffer, "VRS %s\n", filename);
        write(tcp_fd, buffer, strlen(buffer));

        int n = read_tcp_line(tcp_fd, buffer, sizeof(buffer));
        if (n > 0) {
            if (strncmp(buffer, "RVR NOK", 7) == 0) {
                printf("No versions available for '%s'\n", filename);
            } else if (strncmp(buffer, "RVR OK", 6) == 0) {
                char *ptr = buffer + 7;
                char v_uid[7], v_label[21], v_time[32], v_avail[4];
                long v_size;

                while (sscanf(ptr, "%6s %ld %20s %31s %3s", v_uid, &v_size, v_label, v_time, v_avail) == 5) {
                    printf("%-8s %-10ld %-16s %-20s %s\n", v_uid, v_size, v_label, v_time, v_avail);

                    for (int i = 0; i < 5; i++) {
                        while (*ptr == ' ') ptr++;
                        while (*ptr != ' ' && *ptr != '\n' && *ptr != '\0') ptr++;
                    }
                }
            } else {
                printf("Unexpected response: %s\n", buffer);
            }
        }

        freeaddrinfo(res_tcp);
        close(tcp_fd);
    } else {
        printf("Usage: versions <filename>\n");
    }
}
