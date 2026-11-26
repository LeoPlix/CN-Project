CC = gcc
CFLAGS = -Wall -Wextra -g

# Execution variables
PEERPORT = 58000

SRC = user.c net_utils.c user_commands.c
OBJ = $(SRC:.c=.o)
TARGET = user

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET) -m $(PEERPORT)

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all run clean