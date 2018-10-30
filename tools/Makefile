CFLAGS += -I../boringssl/include -Wall
LDFLAGS += -L../boringssl -lssl -lcrypto

all: aes_128_gcm_decrypt

aes_128_gcm_decrypt: aes_128_gcm_decrypt.c ../boringssl/libssl.a ../boringssl/libcrypto.a
	$(CC) $(CFLAGS) -o $@ aes_128_gcm_decrypt.c $(LDFLAGS)
