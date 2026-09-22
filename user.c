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

// Função auxiliar para ler resposta TCP até ao '\n' ou erro
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

int main(int argc, char *argv[]) {
    char *peerport = NULL;
    char *dsip = DEFAULT_DS_IP;
    char *dsport = DEFAULT_DS_PORT;

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
    char buffer[MAX_BUFFER];
    char command[MAX_BUFFER];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) exit(1);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    errcode = getaddrinfo(dsip, dsport, &hints, &res);
    if (errcode != 0) exit(1);

    int logged_in = 0;
    char current_uid[7] = "";
    char current_pass[9] = "";

    printf("NetBox User Application iniciada.\n");

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
                        strcpy(current_uid, arg1);
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
        else if (strcmp(op, "publish") == 0) {
            if (!logged_in) {
                printf("Erro: Sessão não iniciada.\n");
                continue;
            }
            if (num_args == 3) {
                struct stat st;
                if (stat(arg1, &st) == 0) {
                    long fsize = st.st_size;
                    if (fsize > 10000000) {
                        printf("Erro: O ficheiro excede o tamanho máximo de 10MB.\n");
                        continue;
                    }
                    sprintf(buffer, "PUB %s %s %s %ld %s\n", current_uid, current_pass, arg1, fsize, arg2);
                    sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);
                    
                    socklen_t addrlen = sizeof(struct sockaddr_in);
                    struct sockaddr_in addr;
                    int n = recvfrom(fd, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&addr, &addrlen);
                    if (n != -1) {
                        buffer[n] = '\0';
                        if (strncmp(buffer, "RPB OK", 6) == 0) printf("Ficheiro publicado com sucesso.\n");
                        else if (strncmp(buffer, "RPB NLG", 7) == 0) printf("Erro: Utilizador não logado.\n");
                        else if (strncmp(buffer, "RPB WRP", 7) == 0) printf("Erro: Password incorreta.\n");
                        else printf("Erro na publicação: %s\n", buffer);
                    }
                } else {
                    printf("Erro: Ficheiro '%s' não encontrado no diretório local.\n", arg1);
                }
            } else {
                printf("Formato inválido. Uso: publish filename label\n");
            }
        }
        else if (strcmp(op, "remove") == 0) {
            if (!logged_in) {
                printf("Erro: Sessão não iniciada.\n");
                continue;
            }
            if (num_args == 2) {
                sprintf(buffer, "REM %s %s %s\n", current_uid, current_pass, arg1);
                sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);
                
                socklen_t addrlen = sizeof(struct sockaddr_in);
                struct sockaddr_in addr;
                int n = recvfrom(fd, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&addr, &addrlen);
                if (n != -1) {
                    buffer[n] = '\0';
                    if (strncmp(buffer, "RRM OK", 6) == 0) printf("Recurso removido com sucesso.\n");
                    else if (strncmp(buffer, "RRM NOK", 7) == 0) printf("Erro: Ficheiro não estava publicado.\n");
                    else printf("Erro na remoção: %s\n", buffer);
                }
            } else {
                printf("Formato inválido. Uso: remove filename\n");
            }
        }
        else if (strcmp(op, "list") == 0) {
            sprintf(buffer, "LST\n");
            sendto(fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen);
            
            socklen_t addrlen = sizeof(struct sockaddr_in);
            struct sockaddr_in addr;
            int n = recvfrom(fd, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&addr, &addrlen);
            if (n != -1) {
                buffer[n] = '\0';
                if (strncmp(buffer, "RLS NOK", 7) == 0) {
                    printf("Nenhum recurso disponível na rede neste momento.\n");
                } else if (strncmp(buffer, "RLS OK", 6) == 0) {
                    printf("--- Ficheiros Disponíveis ---\n");
                    // Ignorar o "RLS OK " inicial e imprimir os ficheiros
                    char *token = strtok(buffer + 7, " \n");
                    while (token != NULL) {
                        printf("- %s\n", token);
                        token = strtok(NULL, " \n");
                    }
                    printf("-----------------------------\n");
                } else {
                    printf("Resposta inesperada: %s\n", buffer);
                }
            }
        }
        else if (strcmp(op, "versions") == 0) {
            if (num_args == 2) {
                int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
                if (tcp_fd == -1) {
                    perror("Erro ao criar socket TCP");
                    continue;
                }

                struct addrinfo hints_tcp, *res_tcp;
                memset(&hints_tcp, 0, sizeof hints_tcp);
                hints_tcp.ai_family = AF_INET;
                hints_tcp.ai_socktype = SOCK_STREAM;
                
                if (getaddrinfo(dsip, dsport, &hints_tcp, &res_tcp) != 0) {
                    printf("Erro a resolver endereço do Directory Server para TCP.\n");
                    close(tcp_fd);
                    continue;
                }

                if (connect(tcp_fd, res_tcp->ai_addr, res_tcp->ai_addrlen) == -1) {
                    perror("Erro na ligação TCP");
                    freeaddrinfo(res_tcp);
                    close(tcp_fd);
                    continue;
                }

                sprintf(buffer, "VRS %s\n", arg1);
                write(tcp_fd, buffer, strlen(buffer));

                int n = read_tcp_line(tcp_fd, buffer, sizeof(buffer));
                if (n > 0) {
                    if (strncmp(buffer, "RVR NOK", 7) == 0) {
                        printf("Nenhuma versão disponível para o ficheiro '%s'.\n", arg1);
                    } else if (strncmp(buffer, "RVR OK", 6) == 0) {
                        printf("--- Versões de %s ---\n", arg1);
                        // O parsing salta o "RVR OK " inicial
                        char *ptr = buffer + 7;
                        char v_uid[7], v_label[21], v_time[32], v_avail[4];
                        long v_size;
                        
                        // Iterar por blocos de informação de cada peer
                        while (sscanf(ptr, "%6s %ld %20s %31s %3s", v_uid, &v_size, v_label, v_time, v_avail) == 5) {
                            printf("Peer: %s | Tamanho: %ld bytes | Label: %s | Data: %s | Estado: %s\n",
                                   v_uid, v_size, v_label, v_time, strcmp(v_avail, "AVL") == 0 ? "Online" : "Offline");
                            
                            // Avançar o ponteiro para o próximo conjunto (saltar os 5 tokens)
                            for (int i = 0; i < 5; i++) {
                                while (*ptr == ' ') ptr++;
                                while (*ptr != ' ' && *ptr != '\n' && *ptr != '\0') ptr++;
                            }
                        }
                    } else {
                        printf("Resposta inesperada do DS: %s\n", buffer);
                    }
                }
                
                freeaddrinfo(res_tcp);
                close(tcp_fd);
            } else {
                printf("Formato inválido. Uso: versions filename\n");
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