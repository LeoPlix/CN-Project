#include "net_utils.h"

int read_tcp_line(int fd, char *buffer, int max_len) {
    int n, total = 0;
    char c;
    while (total < max_len - 1) {
        n = read(fd, &c, 1);
        if (n > 0) {
            buffer[total++] = c;
            if (c == '\n') break;
        } else {
            break;
        }
    }
    buffer[total] = '\0';
    return total;
}
