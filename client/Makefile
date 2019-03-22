CFLAGS += -I../boringssl/include -Wall
LDFLAGS += -L../boringssl -lssl -lcrypto -lpthread

client: main.c ../boringssl/libssl.a ../boringssl/libcrypto.a
	$(CC) $(CFLAGS) -o client main.c -Wall $(LDFLAGS)

clean:
	rm -f client
