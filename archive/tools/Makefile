CFLAGS += -I../boringssl/include -Wall
LDFLAGS += -L../boringssl -lssl -lcrypto

all: aes_128_gcm_decrypt aes_128_gcm_encrypt

aes_128_gcm_decrypt: aes_128_gcm_decrypt.c ../boringssl/libssl.a ../boringssl/libcrypto.a
	$(CC) $(CFLAGS) -o $@ aes_128_gcm_decrypt.c $(LDFLAGS)

aes_128_gcm_encrypt: aes_128_gcm_encrypt.c ../boringssl/libssl.a ../boringssl/libcrypto.a
	$(CC) $(CFLAGS) -o $@ aes_128_gcm_encrypt.c $(LDFLAGS)
