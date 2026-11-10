#ifndef USER_COMMANDS_H
#define USER_COMMANDS_H

#include "common.h"

void handle_login(int fd, struct addrinfo *res, SessionState *session, const char *arg1, const char *arg2, int num_args);
void handle_logout(int fd, struct addrinfo *res, SessionState *session, int num_args);
void handle_unregister(int fd, struct addrinfo *res, SessionState *session, int num_args);
void handle_publish(int fd, struct addrinfo *res, SessionState *session, const char *filename, const char *label, int num_args);
void handle_remove(int fd, struct addrinfo *res, SessionState *session, const char *filename, int num_args);
void handle_list(int fd, struct addrinfo *res, int num_args);
void handle_versions(const char *dsip, const char *dsport, const char *filename, int num_args, VersionsCache *cache);
void handle_get(int udp_fd, struct addrinfo *ds_res, const char *dsip, const char *dsport, VersionsCache *v_cache, const char *filename, const char *arg_uid, int num_args);
void handle_peer_request(int conn_fd);

#endif // USER_COMMANDS_H
