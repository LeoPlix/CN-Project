#include "net_utils.h"

int read_tcp_line(int fd, char *buffer, int max_len) {
    int n, total = 0;
    char c;
    while (total < max_len - 1) {
        n = read(fd, &c, 1);
        if (n > 0) {
            buffer[total++] = c;
            if (c == '\n') break;
        } else if (n == 0) {
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "Error: TCP read timed out\n");
            } else {
                perror("read");
            }
            break;
        }
    }
    buffer[total] = '\0';
    return total;
}

int is_valid_uid(const char *uid) {
    if (!uid || strlen(uid) != 6) return 0;
    for (int i = 0; i < 6; i++) {
        if (!isdigit((unsigned char)uid[i])) return 0;
    }
    return 1;
}

int is_valid_password(const char *pass) {
    if (!pass || strlen(pass) != 8) return 0;
    for (int i = 0; i < 8; i++) {
        if (!isalnum((unsigned char)pass[i])) return 0;
    }
    return 1;
}

int is_valid_port(const char *port_str) {
    if (!port_str || strlen(port_str) == 0) return 0;
    for (int i = 0; port_str[i] != '\0'; i++) {
        if (!isdigit((unsigned char)port_str[i])) return 0;
    }
    char *endptr = NULL;
    long port = strtol(port_str, &endptr, 10);
    if (*endptr != '\0') return 0;
    return (port >= 1 && port <= 65535);
}

int is_valid_filename(const char *filename) {
    if (!filename) return 0;
    int len = strlen(filename);
    if (len < 5 || len > 24) return 0;
    if (filename[len - 4] != '.') return 0;
    for (int i = 0; i < len - 4; i++) {
        char c = filename[i];
        if (!isalnum((unsigned char)c) && c != '-' && c != '_') return 0;
    }
    for (int i = len - 3; i < len; i++) {
        char c = filename[i];
        if (!isalnum((unsigned char)c)) return 0;
    }
    return 1;
}

int is_valid_label(const char *label) {
    if (!label) return 0;
    int len = strlen(label);
    if (len < 1 || len > 20) return 0;
    for (int i = 0; i < len; i++) {
        char c = label[i];
        if (!isalnum((unsigned char)c) && c != '-' && c != '_') return 0;
    }
    return 1;
}
