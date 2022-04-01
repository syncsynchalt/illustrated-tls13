CFLAGS += -I../openssl/include -Wall
LDFLAGS += -L../openssl -lssl -lcrypto -lpthread

client: main.c ../openssl/libssl.a ../openssl/libcrypto.a
	$(CC) $(CFLAGS) -g -o client main.c -Wall $(LDFLAGS)

clean:
	rm -f client
