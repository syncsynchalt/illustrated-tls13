CFLAGS += -I../boringssl/include
LDFLAGS += -L../boringssl -lssl -lcrypto

client: main.c
	$(CC) $(CFLAGS) -o client main.c -Wall $(LDFLAGS)

clean:
	rm -f server
