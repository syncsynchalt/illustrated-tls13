CFLAGS += -I../openssl/include -Wall
LDFLAGS += -L../openssl -lssl -lcrypto

all: aes_256_gcm_decrypt aes_256_gcm_encrypt

aes_256_gcm_decrypt: aes_256_gcm_decrypt.c ../openssl/libssl.a ../openssl/libcrypto.a
	$(CC) $(CFLAGS) -o $@ aes_256_gcm_decrypt.c $(LDFLAGS)

aes_256_gcm_encrypt: aes_256_gcm_encrypt.c ../openssl/libssl.a ../openssl/libcrypto.a
	$(CC) $(CFLAGS) -o $@ aes_256_gcm_encrypt.c $(LDFLAGS)
