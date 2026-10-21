#ifndef NET_UTILS_H
#define NET_UTILS_H

#include "common.h"

int read_tcp_line(int fd, char *buffer, int max_len);
int write_all(int fd, const void *buf, size_t len);
int read_all(int fd, void *buf, size_t len);

int is_valid_uid(const char *uid);
int is_valid_password(const char *pass);
int is_valid_port(const char *port_str);
int is_valid_filename(const char *filename);
int is_valid_label(const char *label);

#endif // NET_UTILS_H
