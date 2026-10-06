#ifndef NET_UTILS_H
#define NET_UTILS_H

#include "common.h"

int read_tcp_line(int fd, char *buffer, int max_len);

#endif // NET_UTILS_H
