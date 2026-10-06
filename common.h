#ifndef COMMON_H
#define COMMON_H

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <ctype.h>

#define INSIDE_LT5_IP "192.168.1.1"
#define DEFAULT_DS_IP "193.136.138.142"
#define DEFAULT_DS_PORT "59000"
#define MAX_BUFFER 4096

typedef struct {
    int logged_in;
    char uid[7];
    char pass[9];
    char peerport[16];
} SessionState;

#endif // COMMON_H
