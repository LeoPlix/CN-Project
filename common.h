#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#include <signal.h>

#define INSIDE_LT5_IP "192.168.1.1"
#define DEFAULT_DS_IP "193.136.138.142"
#define DEFAULT_DS_PORT "59000"
#define MAX_BUFFER 16384

typedef struct {
    int logged_in;
    char uid[7];
    char pass[9];
    char peerport[16];
} SessionState;

typedef struct {
    char uid[7];
    long size;
    char label[21];
    char time[32];
    char avail[4];
} VersionEntry;

typedef struct {
    char filename[25];
    int count;
    VersionEntry versions[50];
} VersionsCache;

#endif // COMMON_H
