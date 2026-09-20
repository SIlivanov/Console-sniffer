CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -O2
TARGET = sniffer

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)