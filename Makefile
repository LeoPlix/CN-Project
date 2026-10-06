CC = gcc
CFLAGS = -Wall -Wextra -g

# Variáveis para a execução
PEERPORT = 58000
DSIP = tejo.tecnico.ulisboa.pt

SRC = user.c net_utils.c user_commands.c
OBJ = $(SRC:.c=.o)
TARGET = user

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET) -m $(PEERPORT) -n $(DSIP)

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all run clean