#include "user_commands.h"
#include "net_utils.h"

static int send_udp_msg(int fd, struct addrinfo *res, const char *msg, char *reply, int reply_size) {
    int max_retries = 3;
    int retries = 0;
    int n = -1;

    while (retries < max_retries) {
        if (sendto(fd, msg, strlen(msg), 0, res->ai_addr, res->ai_addrlen) == -1) {
            perror("sendto");
            return -1;
        }

        socklen_t addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in addr;
        n = recvfrom(fd, reply, reply_size - 1, 0, (struct sockaddr *)&addr, &addrlen);
        
        if (n != -1) {
            // Sucesso na receção
            reply[n] = '\0';
            return n;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            retries++;
            if (retries < max_retries) {
                printf("Timeout: A tentar novamente... (tentativa %d de %d)\n", retries + 1, max_retries);
            } else {
                printf("Error: Server response timed out after %d attempts\n", max_retries);
                return -1;
            }
        } else {
            perror("recvfrom");
            return -1;
        }
    }
    return -1;
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

static int fetch_versions(const char *dsip, const char *dsport, const char *filename, VersionsCache *cache, int print_output) {
    char buffer[MAX_BUFFER];

    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd == -1) {
        if (print_output) perror("socket");
        return -1;
    }

    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct addrinfo hints_tcp, *res_tcp;
    memset(&hints_tcp, 0, sizeof hints_tcp);
    hints_tcp.ai_family = AF_INET;
    hints_tcp.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(dsip, dsport, &hints_tcp, &res_tcp) != 0) {
        if (print_output) fprintf(stderr, "Error: Failed to resolve Directory Server address\n");
        close(tcp_fd);
        return -1;
    }

    if (connect(tcp_fd, res_tcp->ai_addr, res_tcp->ai_addrlen) == -1) {
        if (print_output) perror("connect");
        freeaddrinfo(res_tcp);
        close(tcp_fd);
        return -1;
    }

    sprintf(buffer, "VRS %s\n", filename);
    if (write(tcp_fd, buffer, strlen(buffer)) == -1) {
        if (print_output) perror("write");
        freeaddrinfo(res_tcp);
        close(tcp_fd);
        return -1;
    }

    int n = read_tcp_line(tcp_fd, buffer, sizeof(buffer));
    int res = -1;
    if (n > 0) {
        if (strncmp(buffer, "RVR NOK", 7) == 0) {
            if (print_output) printf("No versions available for '%s'\n", filename);
            if (cache) cache->count = 0;
            res = 0;
        } else if (strncmp(buffer, "RVR OK", 6) == 0) {
            if (print_output) {
                printf("Available versions for '%s':\n", filename);
                printf("%-8s %-10s %-16s %-20s %s\n", "UID", "Size", "Label", "Date", "Status");
            }
            char *ptr = buffer + 6;
            char v_uid[7], v_label[21], v_time[32], v_avail[4];
            long v_size;
            int count = 0;

            if (cache) {
                strncpy(cache->filename, filename, sizeof(cache->filename) - 1);
                cache->filename[sizeof(cache->filename) - 1] = '\0';
                cache->count = 0;
            }

            while (sscanf(ptr, "%6s %ld %20s %31s %3s", v_uid, &v_size, v_label, v_time, v_avail) == 5) {
                count++;
                const char *status_str = (strcmp(v_avail, "AVL") == 0) ? "Online" : "Offline";
                if (print_output) {
                    printf("%-8s %-10ld %-16s %-20s %s\n", v_uid, v_size, v_label, v_time, status_str);
                }

                if (cache && cache->count < 50) {
                    strncpy(cache->versions[cache->count].uid, v_uid, 6);
                    cache->versions[cache->count].uid[6] = '\0';
                    cache->versions[cache->count].size = v_size;
                    strncpy(cache->versions[cache->count].label, v_label, 20);
                    cache->versions[cache->count].label[20] = '\0';
                    strncpy(cache->versions[cache->count].time, v_time, 31);
                    cache->versions[cache->count].time[31] = '\0';
                    strncpy(cache->versions[cache->count].avail, v_avail, 3);
                    cache->versions[cache->count].avail[3] = '\0';
                    cache->count++;
                }

                for (int i = 0; i < 5; i++) {
                    while (*ptr == ' ') ptr++;
                    while (*ptr != ' ' && *ptr != '\n' && *ptr != '\0') ptr++;
                }
            }
            if (count == 0 && print_output) {
                printf("No versions available for '%s'\n", filename);
            }
            res = count;
        } else if (strncmp(buffer, "RVR ERR", 7) == 0) {
            if (print_output) printf("Error: Protocol syntax error\n");
        } else {
            if (print_output) printf("Unexpected response: %s\n", buffer);
        }
    } else {
        if (print_output) printf("Error: Failed to receive response from DS\n");
    }

    freeaddrinfo(res_tcp);
    close(tcp_fd);
    return res;
}

void handle_versions(const char *dsip, const char *dsport, const char *filename, int num_args, VersionsCache *cache) {
    if (num_args != 2) {
        printf("Usage: versions <filename>\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Error: Invalid filename (max 24 characters, format 'name.ext' with 3-character extension)\n");
        return;
    }

    fetch_versions(dsip, dsport, filename, cache, 1);
}

static int query_whr(int fd, struct addrinfo *res, const char *filename, const char *uid, char *ip_out, char *port_out) {
    char buffer[MAX_BUFFER];
    snprintf(buffer, sizeof(buffer), "WHR %s %s\n", filename, uid);
    if (send_udp_msg(fd, res, buffer, buffer, sizeof(buffer)) == -1) {
        return -1;
    }

    if (strncmp(buffer, "RWH OK", 6) == 0) {
        char ip[64] = "", port[16] = "";
        if (sscanf(buffer + 6, "%63s %15s", ip, port) == 2) {
            if (is_valid_port(port)) {
                if (ip_out) strncpy(ip_out, ip, 63);
                if (port_out) strncpy(port_out, port, 15);
                return 0;
            }
        }
        printf("Error: Invalid response format from DS\n");
        return -1;
    } else if (strncmp(buffer, "RWH NOK", 7) == 0) {
        printf("Resource or publisher not available\n");
        return -1;
    } else if (strncmp(buffer, "RWH ERR", 7) == 0) {
        printf("Error: Protocol syntax error\n");
        return -1;
    } else {
        printf("Unexpected response: %s\n", buffer);
        return -1;
    }
}

static int read_rgt_header(int tcp_fd, char *status, long *fsize) {
    char header[128];
    int total = 0;
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

        if (total > 7 && strncmp(header, "RGT OK ", 7) == 0) {
            if (c == ' ') {
                break;
            }
        }
    }

    if (strncmp(header, "RGT ", 4) != 0) {
        return -1;
    }

    if (strncmp(header, "RGT OK", 6) == 0) {
        strcpy(status, "OK");
        if (sscanf(header + 7, "%ld", fsize) != 1) {
            return -1;
        }
        return 0;
    } else if (strncmp(header, "RGT NOK", 7) == 0) {
        strcpy(status, "NOK");
        *fsize = 0;
        return 0;
    } else if (strncmp(header, "RGT ERR", 7) == 0) {
        strcpy(status, "ERR");
        *fsize = 0;
        return 0;
    }

    return -1;
}

void handle_get(int udp_fd, struct addrinfo *ds_res, const char *dsip, const char *dsport, VersionsCache *v_cache, const char *filename, const char *arg_uid, int num_args) {
    if (num_args < 2 || num_args > 3) {
        printf("Usage: get <filename>\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Error: Invalid filename (max 24 characters, format 'name.ext' with 3-character extension)\n");
        return;
    }

    char target_ip[64] = "";
    char target_port[16] = "";
    int peer_found = 0;

    if (num_args == 3) {
        if (!is_valid_uid(arg_uid)) {
            printf("Error: Invalid UID (must be exactly 6 decimal digits)\n");
            return;
        }
        if (query_whr(udp_fd, ds_res, filename, arg_uid, target_ip, target_port) == 0) {
            peer_found = 1;
        } else {
            return;
        }
    } else {
        // If versions for this filename are not yet cached, fetch them automatically from DS
        if (!v_cache || strcmp(v_cache->filename, filename) != 0 || v_cache->count == 0) {
            fetch_versions(dsip, dsport, filename, v_cache, 0);
        }

        if (v_cache && strcmp(v_cache->filename, filename) == 0 && v_cache->count > 0) {
            for (int i = 0; i < v_cache->count; i++) {
                if (strcmp(v_cache->versions[i].avail, "AVL") == 0) {
                    if (query_whr(udp_fd, ds_res, filename, v_cache->versions[i].uid, target_ip, target_port) == 0) {
                        peer_found = 1;
                        break;
                    }
                }
            }
        }

        if (!peer_found) {
            printf("Error: No available peer found for '%s'\n", filename);
            return;
        }
    }

    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd == -1) {
        perror("socket");
        return;
    }

    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct addrinfo hints_peer, *res_peer;
    memset(&hints_peer, 0, sizeof(hints_peer));
    hints_peer.ai_family = AF_INET;
    hints_peer.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(target_ip, target_port, &hints_peer, &res_peer) != 0) {
        fprintf(stderr, "Error: Failed to resolve peer address (%s:%s)\n", target_ip, target_port);
        close(tcp_fd);
        return;
    }

    if (connect(tcp_fd, res_peer->ai_addr, res_peer->ai_addrlen) == -1) {
        fprintf(stderr, "Error: Failed to connect to peer at %s:%s\n", target_ip, target_port);
        freeaddrinfo(res_peer);
        close(tcp_fd);
        return;
    }
    freeaddrinfo(res_peer);

    char req[64];
    snprintf(req, sizeof(req), "GET %s\n", filename);
    if (write_all(tcp_fd, req, strlen(req)) == -1) {
        fprintf(stderr, "Error: Failed to send request to peer\n");
        close(tcp_fd);
        return;
    }

    char status[16] = "";
    long fsize = 0;
    if (read_rgt_header(tcp_fd, status, &fsize) != 0) {
        printf("Error: Failed to read response from peer\n");
        close(tcp_fd);
        return;
    }

    if (strcmp(status, "NOK") == 0) {
        printf("File '%s' not available at peer\n", filename);
        close(tcp_fd);
        return;
    } else if (strcmp(status, "ERR") == 0) {
        printf("Error: Peer returned error\n");
        close(tcp_fd);
        return;
    } else if (strcmp(status, "OK") != 0) {
        printf("Unexpected response from peer\n");
        close(tcp_fd);
        return;
    }

    if (fsize < 0 || fsize > 10000000) {
        printf("Error: Invalid file size (%ld) from peer\n", fsize);
        close(tcp_fd);
        return;
    }

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen");
        close(tcp_fd);
        return;
    }

    long remaining = fsize;
    char buf[8192];
    int transfer_err = 0;
    while (remaining > 0) {
        int to_read = (remaining < (long)sizeof(buf)) ? remaining : (long)sizeof(buf);
        ssize_t n = read(tcp_fd, buf, to_read);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            transfer_err = 1;
            break;
        }
        if (fwrite(buf, 1, n, fp) != (size_t)n) {
            perror("fwrite");
            transfer_err = 1;
            break;
        }
        remaining -= n;
    }

    fclose(fp);

    // Consume optional trailing newline if present
    char trailing;
    struct timeval tv_short = {.tv_sec = 0, .tv_usec = 100000};
    setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_short, sizeof(tv_short));
    read(tcp_fd, &trailing, 1);

    close(tcp_fd);

    if (transfer_err || remaining > 0) {
        unlink(filename);
        printf("Error: File transfer incomplete (received %ld of %ld bytes)\n", fsize - remaining, fsize);
    } else {
        printf("File '%s' (%ld bytes) successfully received and stored locally\n", filename, fsize);
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

    char op[32] = "", req_file[64] = "", extra[64] = "";
    int num_args = sscanf(buffer, "%31s %63s %63s", op, req_file, extra);
    if (num_args != 2 || strcmp(op, "GET") != 0 || !is_valid_filename(req_file)) {
        write_all(conn_fd, "RGT ERR\n", 8);
        close(conn_fd);
        return;
    }

    struct stat st;
    if (stat(req_file, &st) != 0 || !S_ISREG(st.st_mode)) {
        write_all(conn_fd, "RGT NOK\n", 8);
        close(conn_fd);
        return;
    }

    long fsize = st.st_size;
    if (fsize < 0 || fsize > 10000000) {
        write_all(conn_fd, "RGT NOK\n", 8);
        close(conn_fd);
        return;
    }

    FILE *fp = fopen(req_file, "rb");
    if (!fp) {
        write_all(conn_fd, "RGT NOK\n", 8);
        close(conn_fd);
        return;
    }

    char header[64];
    int hlen = snprintf(header, sizeof(header), "RGT OK %ld ", fsize);
    if (write_all(conn_fd, header, hlen) == -1) {
        fclose(fp);
        close(conn_fd);
        return;
    }

    char chunk[8192];
    size_t bytes_read;
    int write_err = 0;
    while ((bytes_read = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        if (write_all(conn_fd, chunk, bytes_read) == -1) {
            write_err = 1;
            break;
        }
    }
    fclose(fp);

    if (!write_err) {
        write_all(conn_fd, "\n", 1);
    }
    close(conn_fd);
}