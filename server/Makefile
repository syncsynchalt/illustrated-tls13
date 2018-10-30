CFLAGS += -I../boringssl/include
LDFLAGS += -L../boringssl -lssl -lcrypto

client: main.c ../boringssl/libssl.a ../boringssl/libcrypto.a
	$(CC) $(CFLAGS) -o server main.c -Wall $(LDFLAGS)

clean:
	rm -f server
