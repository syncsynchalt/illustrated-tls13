CFLAGS += -I../boringssl/include
LDFLAGS += -L../boringssl -lssl -lcrypto

server: main.c
	$(CC) $(CFLAGS) -o server main.c -Wall $(LDFLAGS)

clean:
	rm -f server
