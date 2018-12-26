CFLAGS += -I../boringssl/include -Wall
LDFLAGS += -L../boringssl -lssl -lcrypto

server: main.c ../boringssl/libssl.a ../boringssl/libcrypto.a
	$(CC) $(CFLAGS) -o server main.c -Wall $(LDFLAGS)

clean:
	rm -f server
