#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdint.h>

typedef unsigned char uchar;

static void die(const char *msg);
static void read_hex(const char *hex, uchar *out, size_t outmax, size_t *outlen);
static void build_iv(uchar *iv, uint64_t seq);

const int gcm_ivlen = 12;
const int gcm_taglen = 16;
const int aes_keylen = 32; // aes-256

int main(int argc, char **argv)
{
	if (argc != 5) {
		fprintf(stderr, "Usage: %s hexiv seq hexkey hexaad\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "Reads plaintext on stdin and prints ciphertext and tag on stdout\n");
		exit(1);
	}

	uchar iv[1024], key[1024], aad[1024];
	size_t ivlen, keylen, aadlen;
	read_hex(argv[1], iv, sizeof(iv), &ivlen);
	uint64_t seq = atoi(argv[2]);
	read_hex(argv[3], key, sizeof(key), &keylen);
	read_hex(argv[4], aad, sizeof(aad), &aadlen);

	if (keylen != aes_keylen)
		die("Incorrect key length, expected 32 bytes");
	if (ivlen != gcm_ivlen)
		die("Incorrect IV length, expected 12 bytes");
	build_iv(iv, seq);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		die("cipher ctx create failed");

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		die("init algorithm failed");

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL))
		die("set ivlen failed");

	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
		die("set key/iv failed");

	int len = 0;
	if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen))
		die("set aad failed");

	uchar bufin[512], bufout[1024];
	while (!feof(stdin)) {
		size_t num = fread(bufin, 1, sizeof(bufin), stdin);
		if (!EVP_EncryptUpdate(ctx, bufout, &len, bufin, num))
			die("decrypt failed");
		fwrite(bufout, 1, len, stdout);
	}

	EVP_EncryptFinal_ex(ctx, bufout, &len);
	fwrite(bufout, 1, len, stdout);

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, gcm_taglen, bufout))
		die("generate tag failed");
	fwrite(bufout, 1, gcm_taglen, stdout);

	EVP_CIPHER_CTX_free(ctx);
}

static void die(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

static void read_hex(const char *hex, uchar *out, size_t outmax, size_t *outlen)
{
	*outlen = 0;
	if (strlen(hex) > 2*outmax)
		die("read_hex overflow");
	size_t i;
	for (i = 0; hex[i] && hex[i+1]; i += 2) {
		unsigned int value = 0;
		if (!sscanf(hex + i, "%02x", &value))
			die("sscanf failure");
		out[(*outlen)++] = value;
	}
}

static void build_iv(uchar *iv, uint64_t seq)
{
	size_t i;
	for (i = 0; i < 8; i++) {
		iv[gcm_ivlen-1-i] ^= ((seq>>(i*8))&0xFF);
	}
}
