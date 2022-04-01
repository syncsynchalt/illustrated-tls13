CFLAGS += -I../openssl/include -Wall
LDFLAGS += -L../openssl -lssl -lcrypto -lpthread

server: main.c ../openssl/libssl.a ../openssl/libcrypto.a
	$(CC) $(CFLAGS) -g -o server main.c -Wall $(LDFLAGS)

clean:
	rm -f server
