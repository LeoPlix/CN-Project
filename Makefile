CC = gcc
CFLAGS = -Wall -g

# Variáveis para a execução
PEERPORT = 58000
DSIP = tejo.tecnico.ulisboa.pt

all: user.c
	$(CC) $(CFLAGS) -o user user.c

run: user
	./user -m $(PEERPORT) -n $(DSIP)

clean:
	rm -f user