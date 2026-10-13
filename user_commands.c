#include "user_commands.h"
#include "net_utils.h"

static int send_udp_msg(int fd, struct addrinfo *res, const char *msg, char *reply, int reply_size) {
    if (sendto(fd, msg, strlen(msg), 0, res->ai_addr, res->ai_addrlen) == -1) {
        perror("sendto");
        return -1;
    }

    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    int n = recvfrom(fd, reply, reply_size - 1, 0, (struct sockaddr *)&addr, &addrlen);
    if (n == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("Error: Server response timed out\n");
        } else {
            perror("recvfrom");
        }
        return -1;
    }

    reply[n] = '\0';
    return n;
}

void handle_login(int fd, struct addrinfo *res, SessionState *session, const char *arg1, const char *arg2, int num_args) {
    char buffer[MAX_BUFFER];

    if (session->logged_in) {
        printf("Error: Already logged in\n");
        return;
    }
    if (num_args != 3) {
        printf("Usage: login <UID> <password>\n");
        return;
    }
    if (!is_valid_uid(arg1)) {
        printf("Error: Invalid UID (must be exactly 6 decimal digits)\n");
        return;
    }
    if (!is_valid_password(arg2)) {
        printf("Error: Invalid password (must be exactly 8 alphanumeric characters)\n");
        return;
    }

    sprintf(buffer, "LIN %s %s %s\n", arg1, arg2, session->peerport);
    if (send_udp_msg(fd, res, buffer, buffer, sizeof(buffer)) == -1) return;

    if (strncmp(buffer, "RLI OK", 6) == 0) {
        printf("Successful login\n");
        session->logged_in = 1;
        strncpy(session->uid, arg1, sizeof(session->uid) - 1);
        strncpy(session->pass, arg2, sizeof(session->pass) - 1);
    } else if (strncmp(buffer, "RLI REG", 7) == 0) {
        printf("New user registered\n");
        session->logged_in = 1;
        strncpy(session->uid, arg1, sizeof(session->uid) - 1);
        strncpy(session->pass, arg2, sizeof(session->pass) - 1);
    } else if (strncmp(buffer, "RLI NOK", 7) == 0) {
        printf("Incorrect login attempt\n");
    } else if (strncmp(buffer, "RLI ERR", 7) == 0) {
        printf("Error: Protocol syntax error\n");
    } else {
        printf("Unexpected response: %s\n", buffer);
    }
}

void handle_logout(int fd, struct addrinfo *res, SessionState *session, int num_args) {
    char buffer[MAX_BUFFER];

    if (num_args != 1) {
        printf("Usage: logout\n");
        return;
    }
    if (!session->logged_in) {
        printf("Error: Not logged in\n");
        return;
    }

    sprintf(buffer, "LOU %s %s\n", session->uid, session->pass);
    if (send_udp_msg(fd, res, buffer, buffer, sizeof(buffer)) == -1) return;

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
    } else if (strncmp(buffer, "RLO ERR", 7) == 0) {
        printf("Error: Protocol syntax error\n");
    } else {
        printf("Unexpected response: %s\n", buffer);
    }
}

void handle_unregister(int fd, struct addrinfo *res, SessionState *session, int num_args) {
    char buffer[MAX_BUFFER];

    if (num_args != 1) {
        printf("Usage: unregister\n");
        return;
    }
    if (!session->logged_in) {
        printf("Error: Not logged in\n");
        return;
    }

    sprintf(buffer, "UNR %s %s\n", session->uid, session->pass);
    if (send_udp_msg(fd, res, buffer, buffer, sizeof(buffer)) == -1) return;

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
    } else if (strncmp(buffer, "RUR ERR", 7) == 0) {
        printf("Error: Protocol syntax error\n");
    } else {
        printf("Unexpected response: %s\n", buffer);
    }
}

void handle_publish(int fd, struct addrinfo *res, SessionState *session, const char *filename, const char *label, int num_args) {
    char buffer[MAX_BUFFER];

    if (!session->logged_in) {
        printf("Error: Not logged in\n");
        return;
    }
    if (num_args != 3) {
        printf("Usage: publish <filename> <label>\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Error: Invalid filename (max 24 characters, format 'name.ext' with 3-character extension)\n");
        return;
    }
    if (!is_valid_label(label)) {
        printf("Error: Invalid label (1-20 characters: letters, digits, '-', '_')\n");
        return;
    }

    struct stat st;
    if (stat(filename, &st) != 0) {
        printf("Error: File '%s' not found\n", filename);
        return;
    }
    if (!S_ISREG(st.st_mode)) {
        printf("Error: '%s' is not a regular file\n", filename);
        return;
    }
    long fsize = st.st_size;
    if (fsize < 0 || fsize > 10000000) {
        printf("Error: File exceeds max size (10MB)\n");
        return;
    }

    sprintf(buffer, "PUB %s %s %s %ld %s\n", session->uid, session->pass, filename, fsize, label);
    if (send_udp_msg(fd, res, buffer, buffer, sizeof(buffer)) == -1) return;

    if (strncmp(buffer, "RPB OK", 6) == 0) {
        printf("Successful publication\n");
    } else if (strncmp(buffer, "RPB NLG", 7) == 0) {
        printf("Error: User not logged in\n");
    } else if (strncmp(buffer, "RPB UNR", 7) == 0) {
        printf("Error: Unknown user\n");
    } else if (strncmp(buffer, "RPB WRP", 7) == 0) {
        printf("Error: Incorrect password\n");
    } else if (strncmp(buffer, "RPB NOK", 7) == 0) {
        printf("Error: Unsuccessful publication\n");
    } else if (strncmp(buffer, "RPB ERR", 7) == 0) {
        printf("Error: Protocol syntax error\n");
    } else {
        printf("Unexpected response: %s\n", buffer);
    }
}

void handle_remove(int fd, struct addrinfo *res, SessionState *session, const char *filename, int num_args) {
    char buffer[MAX_BUFFER];

    if (!session->logged_in) {
        printf("Error: Not logged in\n");
        return;
    }
    if (num_args != 2) {
        printf("Usage: remove <filename>\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Error: Invalid filename (max 24 characters, format 'name.ext' with 3-character extension)\n");
        return;
    }

    sprintf(buffer, "REM %s %s %s\n", session->uid, session->pass, filename);
    if (send_udp_msg(fd, res, buffer, buffer, sizeof(buffer)) == -1) return;

    if (strncmp(buffer, "RRM OK", 6) == 0) {
        printf("Successful removal\n");
    } else if (strncmp(buffer, "RRM NOK", 7) == 0) {
        printf("Error: Resource not found\n");
    } else if (strncmp(buffer, "RRM NLG", 7) == 0) {
        printf("Error: User not logged in\n");
    } else if (strncmp(buffer, "RRM UNR", 7) == 0) {
        printf("Error: Unknown user\n");
    } else if (strncmp(buffer, "RRM WRP", 7) == 0) {
        printf("Error: Incorrect password\n");
    } else if (strncmp(buffer, "RRM ERR", 7) == 0) {
        printf("Error: Protocol syntax error\n");
    } else {
        printf("Unexpected response: %s\n", buffer);
    }
}

void handle_list(int fd, struct addrinfo *res, int num_args) {
    char buffer[MAX_BUFFER];

    if (num_args != 1) {
        printf("Usage: list\n");
        return;
    }

    sprintf(buffer, "LST\n");
    if (send_udp_msg(fd, res, buffer, buffer, sizeof(buffer)) == -1) return;

    if (strncmp(buffer, "RLS NOK", 7) == 0) {
        printf("No resources available\n");
    } else if (strncmp(buffer, "RLS OK", 6) == 0) {
        printf("Available resources:\n");
        char *token = strtok(buffer + 6, " \n");
        int count = 0;
        while (token != NULL) {
            printf(" - %s\n", token);
            count++;
            token = strtok(NULL, " \n");
        }
        if (count == 0) {
            printf("No resources available\n");
        }
    } else if (strncmp(buffer, "RLS ERR", 7) == 0) {
        printf("Error: Protocol syntax error\n");
    } else {
        printf("Unexpected response: %s\n", buffer);
    }
}

void handle_versions(const char *dsip, const char *dsport, const char *filename, int num_args) {
    char buffer[MAX_BUFFER];

    if (num_args != 2) {
        printf("Usage: versions <filename>\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Error: Invalid filename (max 24 characters, format 'name.ext' with 3-character extension)\n");
        return;
    }

    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd == -1) {
        perror("socket");
        return;
    }

    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

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
    if (write(tcp_fd, buffer, strlen(buffer)) == -1) {
        perror("write");
        freeaddrinfo(res_tcp);
        close(tcp_fd);
        return;
    }

    int n = read_tcp_line(tcp_fd, buffer, sizeof(buffer));
    if (n > 0) {
        if (strncmp(buffer, "RVR NOK", 7) == 0) {
            printf("No versions available for '%s'\n", filename);
        } else if (strncmp(buffer, "RVR OK", 6) == 0) {
            printf("Available versions for '%s':\n", filename);
            printf("%-8s %-10s %-16s %-20s %s\n", "UID", "Size", "Label", "Date", "Status");
            char *ptr = buffer + 6;
            char v_uid[7], v_label[21], v_time[32], v_avail[4];
            long v_size;
            int count = 0;

            while (sscanf(ptr, "%6s %ld %20s %31s %3s", v_uid, &v_size, v_label, v_time, v_avail) == 5) {
                count++;
                const char *status_str = (strcmp(v_avail, "AVL") == 0) ? "Online" : "Offline";
                printf("%-8s %-10ld %-16s %-20s %s\n", v_uid, v_size, v_label, v_time, status_str);

                for (int i = 0; i < 5; i++) {
                    while (*ptr == ' ') ptr++;
                    while (*ptr != ' ' && *ptr != '\n' && *ptr != '\0') ptr++;
                }
            }
            if (count == 0) {
                printf("No versions available for '%s'\n", filename);
            }
        } else if (strncmp(buffer, "RVR ERR", 7) == 0) {
            printf("Error: Protocol syntax error\n");
        } else {
            printf("Unexpected response: %s\n", buffer);
        }
    } else {
        printf("Error: Failed to receive response from DS\n");
    }

    freeaddrinfo(res_tcp);
    close(tcp_fd);
}


