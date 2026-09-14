#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

// Valores por omissão (atualiza para os valores dados pelos professores)
#define DEFAULT_DS_IP "127.0.0.1" 
#define DEFAULT_DS_PORT "58000"

int main(int argc, char *argv[]) {
    char *peerport = NULL;
    char *dsip = DEFAULT_DS_IP;
    char *dsport = DEFAULT_DS_PORT;

    // Parsing dos argumentos da linha de comandos
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            peerport = argv[++i];
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            dsip = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            dsport = argv[++i];
        }
    }

    if (peerport == NULL) {
        fprintf(stderr, "Uso: %s -m peerport [-n DSIP] [-p DSport]\n", argv[0]);
        exit(1);
    }

    int fd, errcode;
    struct addrinfo hints, *res;
    char buffer[128];
    char command[128];

    // Configuração do socket UDP
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) exit(1);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    errcode = getaddrinfo(dsip, dsport, &hints, &res);
    if (errcode != 0) exit(1);

    // Estado da sessão do utilizador
    int logged_in = 0;
    char current_uid[7] = "";
    char current_pass[9] = "";

    printf("NetBox User Application iniciada.\n");

    // Ciclo principal de interface
    while (1) {
        printf("> ");
        if (fgets(command, sizeof(command), stdin) == NULL) break;

        char op[32] = "", arg1[32] = "", arg2[32] = "";
        int num_args = sscanf(command, "%s %s %s", op, arg1, arg2);

        if (strcmp(op, "login") == 0) {
            if (logged_in) {
                printf("Erro: Já existe um utilizador com sessão iniciada.\n");
                continue;
            }
            if (num_args == 3 && strlen(arg1) == 6 && strlen(arg2) == 8) {
                sprintf(buffer, "LIN %s %s %s\n", arg1, arg2, peerport);
                sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);
                
                socklen_t addrlen = sizeof(struct sockaddr_in);
                struct sockaddr_in addr;
                int n = recvfrom(fd, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&addr, &addrlen);
                if (n != -1) {
                    buffer[n] = '\0';
                    if (strncmp(buffer, "RLI OK", 6) == 0) {
                        printf("Login bem sucedido.\n");
                        logged_in = 1;
                        strcpy(current_uid, arg1);
                        strcpy(current_pass, arg2);
                    } else if (strncmp(buffer, "RLI REG", 7) == 0) {
                        printf("Novo utilizador registado com sucesso.\n");
                        logged_in = 1;
                        strcpy(current_uid, arg1);a
                        strcpy(current_pass, arg2);
                    } else if (strncmp(buffer, "RLI NOK", 7) == 0) {
                        printf("Tentativa de login incorreta (password errada).\n");
                    } else {
                        printf("Resposta inesperada: %s\n", buffer);
                    }
                }
            } else {
                printf("Formato inválido. Uso: login UID(6 digitos) password(8 caracteres)\n");
            }
        } 
        else if (strcmp(op, "logout") == 0) {
            if (!logged_in) {
                printf("Erro: Nenhum utilizador com sessão iniciada.\n");
                continue;
            }
            
            sprintf(buffer, "LOU %s %s\n", current_uid, current_pass);
            sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);
            
            socklen_t addrlen = sizeof(struct sockaddr_in);
            struct sockaddr_in addr;
            int n = recvfrom(fd, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&addr, &addrlen);
            if (n != -1) {
                buffer[n] = '\0';
                if (strncmp(buffer, "RLO OK", 6) == 0) {
                    printf("Logout efetuado com sucesso.\n");
                    logged_in = 0;
                    current_uid[0] = '\0';
                    current_pass[0] = '\0';
                } else if (strncmp(buffer, "RLO NLG", 7) == 0) {
                    printf("Erro: Utilizador não estava logado.\n");
                } else if (strncmp(buffer, "RLO UNR", 7) == 0) {
                    printf("Erro: Utilizador desconhecido.\n");
                } else if (strncmp(buffer, "RLO WRP", 7) == 0) {
                    printf("Erro: Password incorreta no pedido de logout.\n");
                } else {
                    printf("Resposta inesperada: %s\n", buffer);
                }
            }
        }
        else if (strcmp(op, "unregister") == 0) {
            if (!logged_in) {
                printf("Erro: Nenhum utilizador com sessão iniciada para cancelar registo.\n");
                continue;
            }
            
            sprintf(buffer, "UNR %s %s\n", current_uid, current_pass);
            sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);
            
            socklen_t addrlen = sizeof(struct sockaddr_in);
            struct sockaddr_in addr;
            int n = recvfrom(fd, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&addr, &addrlen);
            if (n != -1) {
                buffer[n] = '\0';
                if (strncmp(buffer, "RUR OK", 6) == 0) {
                    printf("Registo removido com sucesso. Sessão terminada.\n");
                    logged_in = 0;
                    current_uid[0] = '\0';
                    current_pass[0] = '\0';
                } else if (strncmp(buffer, "RUR NOK", 7) == 0) {
                    printf("Erro: Utilizador não estava logado.\n");
                } else if (strncmp(buffer, "RUR UNR", 7) == 0) {
                    printf("Erro: Utilizador desconhecido.\n");
                } else if (strncmp(buffer, "RUR WRP", 7) == 0) {
                    printf("Erro: Password incorreta no pedido de remoção.\n");
                } else {
                    printf("Resposta inesperada: %s\n", buffer);
                }
            }
        }
        else if (strcmp(op, "exit") == 0) {
            if (logged_in) {
                printf("Tem de executar o comando logout primeiro.\n");
            } else {
                break;
            }
        }
        else if (strlen(op) > 0) {
            printf("Comando desconhecido: %s\n", op);
        }
    }

    freeaddrinfo(res);
    close(fd);
    return 0;
}