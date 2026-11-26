#include "user_commands.h"
#include "net_utils.h"

static int send_udp_msg(int fd, struct addrinfo *res, const char *msg, char *reply, int reply_size) {
    int max_retries = 3;
    int retries = 0;
    int n = -1;

    while (retries < max_retries) {
        if (sendto(fd, msg, strlen(msg), 0, res->ai_addr, res->ai_addrlen) == -1) {
            if (errno == EINTR) continue;
            perror("sendto");
            return -1;
        }

        socklen_t addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in addr;
        n = recvfrom(fd, reply, reply_size - 1, 0, (struct sockaddr *)&addr, &addrlen);

        if (n != -1) {
            reply[n] = '\0';
            return n;
        }

        if (errno == EINTR) {
            continue;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            retries++;
            if (retries < max_retries) {
                printf("Request timed out, retrying (%d/%d)...\n", retries + 1, max_retries);
            } else {
                printf("Server timed out after %d attempts\n", max_retries);
                return -1;
            }
        } else {
            perror("recvfrom");
            return -1;
        }
    }
    return -1;
}

static int parse_simple_reply(const char *reply, const char *expected_cmd, char *status, size_t status_size) {
    char cmd[16] = "", st[16] = "", extra[16] = "";
    if (sscanf(reply, "%15s %15s %15s", cmd, st, extra) != 2) {
        return -1;
    }
    if (strcmp(cmd, expected_cmd) != 0) {
        return -1;
    }
    strncpy(status, st, status_size - 1);
    status[status_size - 1] = '\0';
    return 0;
}

void handle_login(int fd, struct addrinfo *res, SessionState *session, const char *arg1, const char *arg2, int num_args) {
    char req[256];
    char reply[MAX_BUFFER];

    if (session->logged_in) {
        printf("Already logged in\n");
        return;
    }
    if (num_args != 3) {
        printf("Usage: login <UID> <password>\n");
        return;
    }
    if (!is_valid_uid(arg1)) {
        printf("Invalid UID\n");
        return;
    }
    if (!is_valid_password(arg2)) {
        printf("Invalid password\n");
        return;
    }

    snprintf(req, sizeof(req), "LIN %s %s %s\n", arg1, arg2, session->peerport);
    if (send_udp_msg(fd, res, req, reply, sizeof(reply)) == -1) return;

    char status[16];
    if (parse_simple_reply(reply, "RLI", status, sizeof(status)) != 0) {
        printf("Unexpected reply: %s\n", reply);
        return;
    }

    if (strcmp(status, "OK") == 0) {
        printf("Login successful\n");
        session->logged_in = 1;
        strncpy(session->uid, arg1, sizeof(session->uid) - 1);
        session->uid[sizeof(session->uid) - 1] = '\0';
        strncpy(session->pass, arg2, sizeof(session->pass) - 1);
        session->pass[sizeof(session->pass) - 1] = '\0';
    } else if (strcmp(status, "REG") == 0) {
        printf("New user registered\n");
        session->logged_in = 1;
        strncpy(session->uid, arg1, sizeof(session->uid) - 1);
        session->uid[sizeof(session->uid) - 1] = '\0';
        strncpy(session->pass, arg2, sizeof(session->pass) - 1);
        session->pass[sizeof(session->pass) - 1] = '\0';
    } else if (strcmp(status, "NOK") == 0) {
        printf("Incorrect login attempt\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("Protocol error\n");
    } else {
        printf("Unexpected reply: %s\n", reply);
    }
}

void handle_logout(int fd, struct addrinfo *res, SessionState *session, int num_args) {
    char req[256];
    char reply[MAX_BUFFER];

    if (num_args != 1) {
        printf("Usage: logout\n");
        return;
    }
    if (!session->logged_in) {
        printf("Not logged in\n");
        return;
    }

    snprintf(req, sizeof(req), "LOU %s %s\n", session->uid, session->pass);
    if (send_udp_msg(fd, res, req, reply, sizeof(reply)) == -1) return;

    char status[16];
    if (parse_simple_reply(reply, "RLO", status, sizeof(status)) != 0) {
        printf("Unexpected reply: %s\n", reply);
        return;
    }

    if (strcmp(status, "OK") == 0) {
        printf("Logout successful\n");
        session->logged_in = 0;
        session->uid[0] = '\0';
        session->pass[0] = '\0';
    } else if (strcmp(status, "NLG") == 0) {
        printf("User not logged in\n");
        session->logged_in = 0;
        session->uid[0] = '\0';
        session->pass[0] = '\0';
    } else if (strcmp(status, "UNR") == 0) {
        printf("Unknown user\n");
        session->logged_in = 0;
        session->uid[0] = '\0';
        session->pass[0] = '\0';
    } else if (strcmp(status, "WRP") == 0) {
        printf("Wrong password\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("Protocol error\n");
    } else {
        printf("Unexpected reply: %s\n", reply);
    }
}

void handle_unregister(int fd, struct addrinfo *res, SessionState *session, int num_args) {
    char req[256];
    char reply[MAX_BUFFER];

    if (num_args != 1) {
        printf("Usage: unregister\n");
        return;
    }
    if (!session->logged_in) {
        printf("Not logged in\n");
        return;
    }

    snprintf(req, sizeof(req), "UNR %s %s\n", session->uid, session->pass);
    if (send_udp_msg(fd, res, req, reply, sizeof(reply)) == -1) return;

    char status[16];
    if (parse_simple_reply(reply, "RUR", status, sizeof(status)) != 0) {
        printf("Unexpected reply: %s\n", reply);
        return;
    }

    if (strcmp(status, "OK") == 0) {
        printf("User unregistered\n");
        session->logged_in = 0;
        session->uid[0] = '\0';
        session->pass[0] = '\0';
    } else if (strcmp(status, "NOK") == 0) {
        printf("User not logged in\n");
        session->logged_in = 0;
        session->uid[0] = '\0';
        session->pass[0] = '\0';
    } else if (strcmp(status, "UNR") == 0) {
        printf("Unknown user\n");
        session->logged_in = 0;
        session->uid[0] = '\0';
        session->pass[0] = '\0';
    } else if (strcmp(status, "WRP") == 0) {
        printf("Wrong password\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("Protocol error\n");
    } else {
        printf("Unexpected reply: %s\n", reply);
    }
}

void handle_publish(int fd, struct addrinfo *res, SessionState *session, const char *filename, const char *label, int num_args) {
    char req[256];
    char reply[MAX_BUFFER];

    if (!session->logged_in) {
        printf("Not logged in\n");
        return;
    }
    if (num_args != 3) {
        printf("Usage: publish <filename> <label>\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Invalid filename\n");
        return;
    }
    if (!is_valid_label(label)) {
        printf("Invalid label\n");
        return;
    }

    struct stat st;
    if (stat(filename, &st) != 0) {
        printf("File not found: %s\n", filename);
        return;
    }
    if (!S_ISREG(st.st_mode)) {
        printf("Not a regular file: %s\n", filename);
        return;
    }
    long fsize = st.st_size;
    if (fsize < 0 || fsize > 10000000) {
        printf("File too large (max 10MB)\n");
        return;
    }

    snprintf(req, sizeof(req), "PUB %s %s %s %ld %s\n", session->uid, session->pass, filename, fsize, label);
    if (send_udp_msg(fd, res, req, reply, sizeof(reply)) == -1) return;

    char status[16];
    if (parse_simple_reply(reply, "RPB", status, sizeof(status)) != 0) {
        printf("Unexpected reply: %s\n", reply);
        return;
    }

    if (strcmp(status, "OK") == 0) {
        printf("Published %s\n", filename);
    } else if (strcmp(status, "NLG") == 0) {
        printf("User not logged in\n");
    } else if (strcmp(status, "UNR") == 0) {
        printf("Unknown user\n");
    } else if (strcmp(status, "WRP") == 0) {
        printf("Wrong password\n");
    } else if (strcmp(status, "NOK") == 0) {
        printf("Failed to publish %s\n", filename);
    } else if (strcmp(status, "ERR") == 0) {
        printf("Protocol error\n");
    } else {
        printf("Unexpected reply: %s\n", reply);
    }
}

void handle_remove(int fd, struct addrinfo *res, SessionState *session, const char *filename, int num_args) {
    char req[256];
    char reply[MAX_BUFFER];

    if (!session->logged_in) {
        printf("Not logged in\n");
        return;
    }
    if (num_args != 2) {
        printf("Usage: remove <filename>\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Invalid filename\n");
        return;
    }

    snprintf(req, sizeof(req), "REM %s %s %s\n", session->uid, session->pass, filename);
    if (send_udp_msg(fd, res, req, reply, sizeof(reply)) == -1) return;

    char status[16];
    if (parse_simple_reply(reply, "RRM", status, sizeof(status)) != 0) {
        printf("Unexpected reply: %s\n", reply);
        return;
    }

    if (strcmp(status, "OK") == 0) {
        printf("Removed %s\n", filename);
    } else if (strcmp(status, "NOK") == 0) {
        printf("Resource not found\n");
    } else if (strcmp(status, "NLG") == 0) {
        printf("User not logged in\n");
    } else if (strcmp(status, "UNR") == 0) {
        printf("Unknown user\n");
    } else if (strcmp(status, "WRP") == 0) {
        printf("Wrong password\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("Protocol error\n");
    } else {
        printf("Unexpected reply: %s\n", reply);
    }
}

void handle_list(int fd, struct addrinfo *res, int num_args) {
    char reply[MAX_BUFFER];

    if (num_args != 1) {
        printf("Usage: list\n");
        return;
    }

    if (send_udp_msg(fd, res, "LST\n", reply, sizeof(reply)) == -1) return;

    char cmd[16] = "", status[16] = "";
    int parsed = sscanf(reply, "%15s %15s", cmd, status);
    if (parsed != 2 || strcmp(cmd, "RLS") != 0) {
        printf("Unexpected reply: %s\n", reply);
        return;
    }

    if (strcmp(status, "NOK") == 0) {
        printf("No resources available\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("Protocol error\n");
    } else if (strcmp(status, "OK") == 0) {
        printf("Resources:\n");
        char *token = strtok(reply + 6, " \r\n\t");
        int count = 0;
        while (token != NULL) {
            printf("  %s\n", token);
            count++;
            token = strtok(NULL, " \r\n\t");
        }
        if (count == 0) {
            printf("No resources available\n");
        }
    } else {
        printf("Unexpected reply: %s\n", reply);
    }
}

static int fetch_versions(const char *dsip, const char *dsport, const char *filename,
                          char avl_uids[][7], int max_avl, int *avl_count, int print_output) {
    char buffer[MAX_BUFFER];
    if (avl_count) *avl_count = 0;

    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd == -1) {
        if (print_output) perror("socket");
        return -1;
    }

    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct addrinfo hints_tcp, *res_tcp;
    memset(&hints_tcp, 0, sizeof(hints_tcp));
    hints_tcp.ai_family = AF_INET;
    hints_tcp.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(dsip, dsport, &hints_tcp, &res_tcp) != 0) {
        if (print_output) fprintf(stderr, "Failed to resolve DS address\n");
        close(tcp_fd);
        return -1;
    }

    if (connect(tcp_fd, res_tcp->ai_addr, res_tcp->ai_addrlen) == -1) {
        if (print_output) perror("connect");
        freeaddrinfo(res_tcp);
        close(tcp_fd);
        return -1;
    }

    snprintf(buffer, sizeof(buffer), "VRS %s\n", filename);
    if (write_all(tcp_fd, buffer, strlen(buffer)) == -1) {
        if (print_output) perror("write");
        freeaddrinfo(res_tcp);
        close(tcp_fd);
        return -1;
    }

    int n = read_tcp_line(tcp_fd, buffer, sizeof(buffer));
    int res = -1;
    if (n > 0) {
        char cmd[16] = "", status[16] = "";
        int header_matched = sscanf(buffer, "%15s %15s", cmd, status);

        if (header_matched == 2 && strcmp(cmd, "RVR") == 0 && strcmp(status, "NOK") == 0) {
            if (print_output) printf("No versions found for %s\n", filename);
            res = 0;
        } else if (header_matched == 2 && strcmp(cmd, "RVR") == 0 && strcmp(status, "OK") == 0) {
            if (print_output) {
                printf("Versions for %s:\n", filename);
                printf("%-8s %-10s %-20s %-22s %s\n", "UID", "Size", "Label", "Date", "Status");
            }
            char *ptr = buffer + 6;
            int count = 0;

            while (1) {
                while (*ptr == ' ' || *ptr == '\t' || *ptr == '\r') ptr++;
                if (*ptr == '\n' || *ptr == '\0') break;

                char tok1[32] = "", tok2[32] = "", tok3[32] = "";
                char tok4[32] = "", tok5[32] = "", tok6[32] = "";
                int matched = sscanf(ptr, "%31s %31s %31s %31s %31s %31s",
                                     tok1, tok2, tok3, tok4, tok5, tok6);
                if (matched < 5 || !is_valid_uid(tok1)) {
                    break;
                }

                char *endptr = NULL;
                long v_size = strtol(tok2, &endptr, 10);
                if (*endptr != '\0' || v_size < 0 || v_size > 10000000) {
                    break;
                }

                char v_time[64] = "";
                const char *v_avail = NULL;
                int tokens_consumed = 0;
                if (strcmp(tok5, "AVL") == 0 || strcmp(tok5, "NAV") == 0) {
                    snprintf(v_time, sizeof(v_time), "%s", tok4);
                    v_avail = tok5;
                    tokens_consumed = 5;
                } else if (matched >= 6 && (strcmp(tok6, "AVL") == 0 || strcmp(tok6, "NAV") == 0)) {
                    snprintf(v_time, sizeof(v_time), "%s %s", tok4, tok5);
                    v_avail = tok6;
                    tokens_consumed = 6;
                } else {
                    break;
                }

                count++;
                const char *status_str = (strcmp(v_avail, "AVL") == 0) ? "Online" : "Offline";
                if (print_output) {
                    printf("%-8s %-10ld %-20s %-22s %s\n", tok1, v_size, tok3, v_time, status_str);
                }

                if (avl_uids && avl_count && strcmp(v_avail, "AVL") == 0 && *avl_count < max_avl) {
                    strncpy(avl_uids[*avl_count], tok1, 6);
                    avl_uids[*avl_count][6] = '\0';
                    (*avl_count)++;
                }

                for (int i = 0; i < tokens_consumed; i++) {
                    while (*ptr == ' ' || *ptr == '\t' || *ptr == '\r') ptr++;
                    while (*ptr != ' ' && *ptr != '\t' && *ptr != '\r' && *ptr != '\n' && *ptr != '\0') ptr++;
                }
            }
            if (count == 0 && print_output) {
                printf("No versions found for %s\n", filename);
            }
            res = count;
        } else if (header_matched == 2 && strcmp(cmd, "RVR") == 0 && strcmp(status, "ERR") == 0) {
            if (print_output) printf("Protocol error\n");
        } else {
            if (print_output) printf("Unexpected reply: %s\n", buffer);
        }
    } else {
        if (print_output) printf("No response from DS\n");
    }

    freeaddrinfo(res_tcp);
    close(tcp_fd);
    return res;
}

void handle_versions(const char *dsip, const char *dsport, const char *filename, int num_args) {
    if (num_args != 2) {
        printf("Usage: versions <filename>\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Invalid filename\n");
        return;
    }

    fetch_versions(dsip, dsport, filename, NULL, 0, NULL, 1);
}

static int query_whr(int fd, struct addrinfo *res, const char *filename, const char *uid, char *ip_out, char *port_out) {
    char req[256];
    char reply[MAX_BUFFER];

    snprintf(req, sizeof(req), "WHR %s %s\n", filename, uid);
    if (send_udp_msg(fd, res, req, reply, sizeof(reply)) == -1) {
        return -1;
    }

    char cmd[16] = "", status[16] = "";
    if (sscanf(reply, "%15s %15s", cmd, status) != 2 || strcmp(cmd, "RWH") != 0) {
        return -1;
    }

    if (strcmp(status, "OK") == 0) {
        char ip[64] = "", port[16] = "", extra[16] = "";
        if (sscanf(reply, "%*15s %*15s %63s %15s %15s", ip, port, extra) == 2 && is_valid_port(port)) {
            strncpy(ip_out, ip, 63);
            ip_out[63] = '\0';
            strncpy(port_out, port, 15);
            port_out[15] = '\0';
            return 0;
        }
    }
    return -1;
}

// Read the RGT header byte-by-byte to stop right after the space preceding binary Fdata
static int read_rgt_header(int tcp_fd, char *status, long *fsize) {
    char header[128];
    int total = 0;
    int seen_digits = 0;

    while (total < (int)sizeof(header) - 1) {
        char c;
        ssize_t n = read(tcp_fd, &c, 1);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        header[total++] = c;
        header[total] = '\0';

        if (c == '\n') {
            break;
        }

        if (total >= 8 && strncmp(header, "RGT OK ", 7) == 0) {
            if (isdigit((unsigned char)c)) {
                seen_digits = 1;
            } else if (seen_digits && c == ' ') {
                break;
            }
        }
    }

    if (strncmp(header, "RGT OK ", 7) == 0) {
        char *endptr = NULL;
        long val = strtol(header + 7, &endptr, 10);
        if (endptr == header + 7 || (*endptr != ' ' && *endptr != '\n' && *endptr != '\0')) {
            return -1;
        }
        strcpy(status, "OK");
        *fsize = val;
        return 0;
    }

    char cmd[16] = "", st[16] = "", extra[16] = "";
    if (sscanf(header, "%15s %15s %15s", cmd, st, extra) == 2 && strcmp(cmd, "RGT") == 0) {
        if (strcmp(st, "NOK") == 0 || strcmp(st, "ERR") == 0) {
            strcpy(status, st);
            *fsize = 0;
            return 0;
        }
    }

    return -1;
}

static int download_from_peer(const char *target_ip, const char *target_port, const char *filename) {
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd == -1) {
        perror("socket");
        return -1;
    }

    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct addrinfo hints_peer, *res_peer;
    memset(&hints_peer, 0, sizeof(hints_peer));
    hints_peer.ai_family = AF_INET;
    hints_peer.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(target_ip, target_port, &hints_peer, &res_peer) != 0) {
        fprintf(stderr, "Failed to resolve peer %s:%s\n", target_ip, target_port);
        close(tcp_fd);
        return -1;
    }

    if (connect(tcp_fd, res_peer->ai_addr, res_peer->ai_addrlen) == -1) {
        freeaddrinfo(res_peer);
        close(tcp_fd);
        return -1;
    }
    freeaddrinfo(res_peer);

    char req[64];
    snprintf(req, sizeof(req), "GET %s\n", filename);
    if (write_all(tcp_fd, req, strlen(req)) == -1) {
        close(tcp_fd);
        return -1;
    }

    char status[16] = "";
    long fsize = 0;
    if (read_rgt_header(tcp_fd, status, &fsize) != 0) {
        close(tcp_fd);
        return -1;
    }

    if (strcmp(status, "NOK") == 0) {
        close(tcp_fd);
        return 1;
    } else if (strcmp(status, "ERR") == 0 || strcmp(status, "OK") != 0) {
        close(tcp_fd);
        return -1;
    }

    if (fsize < 0 || fsize > 10000000) {
        printf("Invalid file size: %ld\n", fsize);
        close(tcp_fd);
        return -1;
    }

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen");
        close(tcp_fd);
        return -1;
    }

    long remaining = fsize;
    char buf[8192];
    int transfer_err = 0;
    while (remaining > 0) {
        int to_read = (remaining < (long)sizeof(buf)) ? (int)remaining : (int)sizeof(buf);
        ssize_t n = read(tcp_fd, buf, to_read);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            transfer_err = 1;
            break;
        }
        if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n) {
            perror("fwrite");
            transfer_err = 1;
            break;
        }
        remaining -= n;
    }

    fclose(fp);

    // Consume trailing '\n' sent by the peer before closing
    char trailing;
    struct timeval tv_short = {.tv_sec = 0, .tv_usec = 100000};
    setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_short, sizeof(tv_short));
    read(tcp_fd, &trailing, 1);

    close(tcp_fd);

    if (transfer_err || remaining > 0) {
        unlink(filename);
        printf("Transfer incomplete (%ld/%ld bytes)\n", fsize - remaining, fsize);
        return -1;
    }

    printf("Downloaded %s successfully (stored as ./%s, %ld bytes)\n", filename, filename, fsize);
    return 0;
}

void handle_get(int udp_fd, struct addrinfo *ds_res, const char *dsip, const char *dsport, const char *filename, int num_args) {
    if (num_args != 2) {
        printf("Usage: get <filename>\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Invalid filename\n");
        return;
    }

    char avl_uids[50][7];
    int avl_count = 0;
    int vrs_res = fetch_versions(dsip, dsport, filename, avl_uids, 50, &avl_count, 0);
    if (vrs_res < 0) {
        printf("Failed to query DS for %s\n", filename);
        return;
    }
    if (avl_count == 0) {
        printf("No available peer for %s\n", filename);
        return;
    }

    int last_status = -1;
    for (int i = 0; i < avl_count; i++) {
        char target_ip[64] = "";
        char target_port[16] = "";
        if (query_whr(udp_fd, ds_res, filename, avl_uids[i], target_ip, target_port) == 0) {
            last_status = download_from_peer(target_ip, target_port, filename);
            if (last_status == 0) {
                return;
            }
        }
    }

    if (last_status == 1) {
        printf("File %s not available on peer\n", filename);
    } else {
        printf("Failed to download %s from available peers\n", filename);
    }
}

void handle_peer_request(int conn_fd) {
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(conn_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char buffer[MAX_BUFFER];
    int n = read_tcp_line(conn_fd, buffer, sizeof(buffer));
    if (n <= 0) {
        close(conn_fd);
        return;
    }
    if (buffer[n - 1] != '\n') {
        write_all(conn_fd, "RGT ERR\n", 8);
        close(conn_fd);
        return;
    }

    char op[32] = "", req_file[64] = "", extra[64] = "";
    int num_args = sscanf(buffer, "%31s %63s %63s", op, req_file, extra);
    if (num_args != 2 || strcmp(op, "GET") != 0 || !is_valid_filename(req_file)) {
        write_all(conn_fd, "RGT ERR\n", 8);
        close(conn_fd);
        return;
    }

    FILE *fp = fopen(req_file, "rb");
    if (!fp) {
        write_all(conn_fd, "RGT NOK\n", 8);
        close(conn_fd);
        return;
    }

    struct stat st;
    if (fstat(fileno(fp), &st) != 0 || !S_ISREG(st.st_mode)) {
        fclose(fp);
        write_all(conn_fd, "RGT NOK\n", 8);
        close(conn_fd);
        return;
    }

    long fsize = st.st_size;
    if (fsize < 0 || fsize > 10000000) {
        fclose(fp);
        write_all(conn_fd, "RGT NOK\n", 8);
        close(conn_fd);
        return;
    }

    char header[64];
    int hlen = snprintf(header, sizeof(header), "RGT OK %ld ", fsize);
    if (write_all(conn_fd, header, (size_t)hlen) == -1) {
        fclose(fp);
        close(conn_fd);
        return;
    }

    char chunk[8192];
    size_t bytes_read;
    long total_sent = 0;
    int write_err = 0;
    while ((bytes_read = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        if (write_all(conn_fd, chunk, bytes_read) == -1) {
            write_err = 1;
            break;
        }
        total_sent += (long)bytes_read;
    }
    fclose(fp);

    if (!write_err && total_sent == fsize) {
        write_all(conn_fd, "\n", 1);
    }
    close(conn_fd);
}
