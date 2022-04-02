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
	if (argc != 6) {
		fprintf(stderr, "Usage: %s hexiv seq hexkey hexaad hextag\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "Reads ciphertext on stdin and prints plaintext on stdout\n");
		exit(1);
	}

	uchar iv[1024], key[1024], aad[1024], tag[1024];
	size_t ivlen, keylen, aadlen, taglen;
	read_hex(argv[1], iv, sizeof(iv), &ivlen);
	read_hex(argv[3], key, sizeof(key), &keylen);
	read_hex(argv[4], aad, sizeof(aad), &aadlen);
	read_hex(argv[5], tag, sizeof(tag), &taglen);
	uint64_t seq = atoi(argv[2]);

	if (keylen != aes_keylen)
		die("Incorrect key length, expected 32 bytes");
	if (ivlen != gcm_ivlen)
		die("Incorrect IV length, expected 12 bytes");
	if (taglen != gcm_taglen)
		die("Incorrect IV length, expected 16 bytes");
	build_iv(iv, seq);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		die("cipher ctx create failed");

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		die("init algorithm failed");

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL))
		die("set ivlen failed");

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		die("set key/iv failed");

	int len = 0;
	if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen))
		die("set aad failed");

	uchar bufin[1024], bufout[1024];
	char *out = NULL;
	int outlen = 0;
	while (!feof(stdin)) {
		size_t num = fread(bufin, 1, sizeof(bufin), stdin);
		if (!EVP_DecryptUpdate(ctx, bufout, &len, bufin, num))
			die("decrypt failed");
		out = realloc(out, outlen + len);
		memcpy(out + outlen, bufout, len);
		outlen += len;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, taglen, tag))
		die("set expected tag failed");

	// positive is success
	int final = EVP_DecryptFinal_ex(ctx, bufout, &len);
	out = realloc(out, outlen + len);
	memcpy(out + outlen, bufout, len);
	outlen += len;

	EVP_CIPHER_CTX_free(ctx);

	if (final > 0) {
		fwrite(out, 1, outlen, stdout);
		free(out);
	} else {
		free(out);
		die("decrypt failed; tag value didn't match");
	}
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
