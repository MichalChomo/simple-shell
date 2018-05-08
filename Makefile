CC = gcc
CFLAGS = -Wall -pedantic -g -pthread
NAME = shell
OBJS = $(NAME).o

.PHONY: clean

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(NAME) core* *.o

