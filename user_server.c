#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT "58000"

// Estrutura para guardar utilizadores na memória do servidor
typedef struct {
    char uid[7];
    char pass[9];
    int logged_in;
} User;

User users[100];
int user_count = 0;

int find_user(const char *uid) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].uid, uid) == 0) return i;
    }
    return -1;
}

int main() {
    int fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[256];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("Erro ao criar socket do DS");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(atoi(PORT));

    if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erro no bind do DS");
        close(fd);
        exit(1);
    }

    printf("Directory Server (DS) de teste a correr no porto %s...\n", PORT);

    while (1) {
        int n = recvfrom(fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (n <= 0) continue;
        buffer[n] = '\0';

        printf("[DS Recebeu]: %s", buffer);

        char cmd[32], uid[32], pass[32], peerport[32];
        int args = sscanf(buffer, "%s %s %s %s", cmd, uid, pass, peerport);

        char response[128] = "ERR\n";

        if (strcmp(cmd, "LIN") == 0 && args == 4) {
            int idx = find_user(uid);
            if (idx == -1) {
                // Novo utilizador -> Registar
                strcpy(users[user_count].uid, uid);
                strcpy(users[user_count].pass, pass);
                users[user_count].logged_in = 1;
                user_count++;
                strcpy(response, "RLI REG\n");
            } else {
                if (strcmp(users[idx].pass, pass) == 0) {
                    users[idx].logged_in = 1;
                    strcpy(response, "RLI OK\n");
                } else {
                    strcpy(response, "RLI NOK\n");
                }
            }
        } 
        else if (strcmp(cmd, "LOU") == 0 && args == 3) {
            int idx = find_user(uid);
            if (idx == -1) {
                strcpy(response, "RLO UNR\n");
            } else if (strcmp(users[idx].pass, pass) != 0) {
                strcpy(response, "RLO WRP\n");
            } else if (!users[idx].logged_in) {
                strcpy(response, "RLO NLG\n");
            } else {
                users[idx].logged_in = 0;
                strcpy(response, "RLO OK\n");
            }
        }
        else if (strcmp(cmd, "UNR") == 0 && args == 3) {
            int idx = find_user(uid);
            if (idx == -1) {
                strcpy(response, "RUR UNR\n");
            } else if (strcmp(users[idx].pass, pass) != 0) {
                strcpy(response, "RUR WRP\n");
            } else if (!users[idx].logged_in) {
                strcpy(response, "RUR NOK\n");
            } else {
                users[idx].logged_in = 0;
                // Para simplificar, desativa o utilizador
                users[idx].uid[0] = '\0';
                strcpy(response, "RUR OK\n");
            }
        }

        sendto(fd, response, strlen(response), 0, (struct sockaddr *)&client_addr, addr_len);
        printf("[DS Respondeu]: %s", response);
    }

    close(fd);
    return 0;
}