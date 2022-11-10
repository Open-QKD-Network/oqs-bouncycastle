/*
 * example_kem.c
 *
 * Minimal example of a Diffie-Hellman-style post-quantum key encapsulation
 * implemented in liboqs.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <oqs/oqs.h>

/* Cleaning up memory etc */
void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len);

void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret_e,
                  uint8_t *shared_secret_d, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem);

uint8_t char2int(char c);
char* bytearray2hexstring(uint8_t* buf, int size);
uint8_t* hexstring2bytearray(char* hexstring, int* size);
int writebytearraytofile(uint8_t* buf, int size, const char* filename);
uint8_t* readbytearrayfromfile(const char* filename, int* size);
OQS_STATUS test_bouncycastle(void);
OQS_STATUS test_bouncycastle2(void);
OQS_STATUS test_kyber(void);

//0123456789abcdef
uint8_t char2int(char c) {
    if (c >= 'a' && c <= 'f') {
        return (c - 'a') + 10;
    } else if (c >= 'A' && c <= 'F') {
        return (c - 'A') + 10;
    } else {
        return (c - '0');
    }
}

//stackoverflow.com/questions/6357031/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-in-c/
char* bytearray2hexstring(uint8_t* buf, int size) {
    char *ptr = malloc(size * 2 + 1);
    char *ret = ptr;
    int i = 0;

    memset(ptr, 0, size*2 + 1);
    for (i = 0; i < size; i++)
        ptr += sprintf(ptr, "%02X", buf[i]);
    return ret;
}

uint8_t* hexstring2bytearray(char* hexstring, int* size) {
    int len = strlen(hexstring)/2;
    uint8_t *ret = malloc(len);
    memset(ret, 0, len);
    int i = 0;
    for (i = 0; i < len; i++) {
        uint8_t c0 = char2int(hexstring[i*2]);
        uint8_t c1 = char2int(hexstring[i*2 + 1]);
        uint8_t r = (c0 << 4) + c1;
        *(ret + i) = r;
        //printf("#%d %c %c %d %d %d\n", i, hexstring[i*2], hexstring[i*2 +1], c0, c1, r);
    }
    *size = len;
    return ret;
}

int writebytearraytofile(uint8_t* buf, int size, const char* filename) {
    FILE *fp;
    char* hexstring;

    hexstring = bytearray2hexstring(buf, size);
    fp = fopen(filename, "w+");
    if (fp) {
        fputs(hexstring, fp);
        fclose(fp);
        free(hexstring);
        return 0;
    } else {
        return -1;
    }
}

uint8_t* readbytearrayfromfile(const char* filename, int* size) {
    FILE *fp;
    long length;
    char *hexstring = 0;
    size_t fsize = 0;

    if (!filename)
        return NULL;
    fp = fopen(filename, "rb");
    if (!fp) {
        printf("Fails to read file:%s\n", filename);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    length = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    printf("Size of the file:%ld\n", length);
    hexstring = malloc(length + 1);
    memset(hexstring, 0, length + 1);
    if (hexstring)
    {
        fsize = fread(hexstring, 1, length, fp);
	printf("readbytearrayfromfile, fsize=%lu\n", fsize);
    }
    fclose(fp);

    //printf("Hexstring:%s\n", hexstring);
    return hexstring2bytearray(hexstring, size);
}

/* This function gives an example of the operations performed by both
 * the decapsulator and the encapsulator in a single KEM session,
 * using only compile-time macros and allocating variables
 * statically on the stack, calling a specific algorithm's functions
 * directly.
 *
 * The macros OQS_KEM_frodokem_640_aes_length_* and the functions
 * OQS_KEM_frodokem_640_aes_* are only defined if the algorithm
 * FrodoKEM-640-AES was enabled at compile-time which must be
 * checked using the OQS_ENABLE_KEM_frodokem_640_aes macro.
 *
 * <oqs/oqsconfig.h>, which is included in <oqs/oqs.h>, contains macros
 * indicating which algorithms were enabled when this instance of liboqs
 * was compiled.
 */
static OQS_STATUS example_stack(void) {
#ifndef OQS_ENABLE_KEM_frodokem_640_aes // if FrodoKEM-640-AES was not enabled at compile-time
	printf("[example_stack] OQS_KEM_frodokem_640_aes was not enabled at "
	       "compile-time.\n");
	return OQS_ERROR;
#else
	uint8_t public_key[OQS_KEM_frodokem_640_aes_length_public_key];
	uint8_t secret_key[OQS_KEM_frodokem_640_aes_length_secret_key];
	uint8_t ciphertext[OQS_KEM_frodokem_640_aes_length_ciphertext];
	uint8_t shared_secret_e[OQS_KEM_frodokem_640_aes_length_shared_secret];
	uint8_t shared_secret_d[OQS_KEM_frodokem_640_aes_length_shared_secret];

	OQS_STATUS rc = OQS_KEM_frodokem_640_aes_keypair(public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_frodokem_640_aes_keypair failed!\n");
		cleanup_stack(secret_key, OQS_KEM_frodokem_640_aes_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_frodokem_640_aes_length_shared_secret);

		return OQS_ERROR;
	}
	rc = OQS_KEM_frodokem_640_aes_encaps(ciphertext, shared_secret_e, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_frodokem_640_aes_encaps failed!\n");
		cleanup_stack(secret_key, OQS_KEM_frodokem_640_aes_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_frodokem_640_aes_length_shared_secret);

		return OQS_ERROR;
	}
	rc = OQS_KEM_frodokem_640_aes_decaps(shared_secret_d, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_frodokem_640_aes_decaps failed!\n");
		cleanup_stack(secret_key, OQS_KEM_frodokem_640_aes_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_frodokem_640_aes_length_shared_secret);

		return OQS_ERROR;
	}
	printf("[example_stack] OQS_KEM_frodokem_640_aes operations completed.\n");

	return OQS_SUCCESS; // success!
#endif
}

/* This function gives an example of the operations performed by both
 * the decapsulator and the encapsulator in a single KEM session,
 * allocating variables dynamically on the heap and calling the generic
 * OQS_KEM object.
 *
 * This does not require the use of compile-time macros to check if the
 * algorithm in question was enabled at compile-time; instead, the caller
 * must check that the OQS_KEM object returned is not NULL.
 */
static OQS_STATUS example_heap(void) {
	OQS_KEM *kem = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *ciphertext = NULL;
	uint8_t *shared_secret_e = NULL;
	uint8_t *shared_secret_d = NULL;

	kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
	if (kem == NULL) {
		printf("[example_heap]  OQS_KEM_frodokem_640_aes was not enabled at "
		       "compile-time.\n");
		return OQS_ERROR;
	}

	public_key = malloc(kem->length_public_key);
	secret_key = malloc(kem->length_secret_key);
	ciphertext = malloc(kem->length_ciphertext);
	shared_secret_e = malloc(kem->length_shared_secret);
	shared_secret_d = malloc(kem->length_shared_secret);
	if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) ||
	        (shared_secret_e == NULL) || (shared_secret_d == NULL)) {
		fprintf(stderr, "ERROR: malloc failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

	OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}
	rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}
	rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

	printf("[example_heap]  OQS_KEM_frodokem_640_aes public key size:%lu, secret key size:%lu, ciphertest size:%lu,shared_secrete size:%lu\n",
		kem->length_public_key, kem->length_secret_key, kem->length_ciphertext, kem->length_shared_secret);
	printf("[example_heap]  OQS_KEM_frodokem_640_aes operations completed.\n");
	cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
	             ciphertext, kem);

	return OQS_SUCCESS; // success
}

int main(void) {
	test_kyber();
	if (1) {
	if (example_stack() == OQS_SUCCESS && example_heap() == OQS_SUCCESS) {
		return EXIT_SUCCESS;
	} else {
		return EXIT_FAILURE;
	}
	}
	else {
		if (test_bouncycastle2() == OQS_SUCCESS) {
			return EXIT_SUCCESS;
		} else {
			return EXIT_FAILURE;
		}
	}
}

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
	OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}

void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret_e,
                  uint8_t *shared_secret_d, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem) {
	if (kem != NULL) {
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
		OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
		OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
}

OQS_STATUS test_bouncycastle(void) {
	OQS_KEM *kem = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *ciphertext = NULL;
	uint8_t *shared_secret_e = NULL;
	uint8_t *shared_secret_d = NULL;
	FILE* fp = NULL;
	int cipher_text_size = 0;
	char* secret_key_hex = NULL;

	kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
	if (kem == NULL) {
		printf("[test_bouncycastle]  OQS_KEM_frodokem_640_aes was not enabled at "
		       "compile-time.\n");
		return OQS_ERROR;
	}

	public_key = malloc(kem->length_public_key);
	secret_key = malloc(kem->length_secret_key);
	ciphertext = malloc(kem->length_ciphertext);
	shared_secret_e = malloc(kem->length_shared_secret);
	shared_secret_d = malloc(kem->length_shared_secret);
	if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) ||
	        (shared_secret_e == NULL) || (shared_secret_d == NULL)) {
		fprintf(stderr, "ERROR: malloc failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

	OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

	writebytearraytofile(public_key, kem->length_public_key, "/home/kxie/Desktop/oqs-bc/oqs_public_key.txt");
	fp = fopen("/home/kxie/Desktop/oqs-bc/bc_cipher_text.txt", "r");
	while (!fp) {
	    fprintf(stderr, "/home/kxie/Desktop/oqs-bc/bc_cipher_text does not exist, wait...\n");
            usleep(1000 * 1000 * 60);
	    fp = fopen("/home/kxie/Desktop/oqs-bc/bc_cipher_text.txt", "r");
	}
	fclose(fp);
	fprintf(stderr, "Reading cipher text from bouncycastle\n");
	ciphertext = readbytearrayfromfile("/home/kxie/Desktop/oqs-bc/bc_cipher_text.txt", &cipher_text_size);
	if (ciphertext == NULL || (size_t) cipher_text_size != kem->length_ciphertext) {
		fprintf(stderr, "ERROR: can not read ciphertext or ciphertext_size:%d\n", cipher_text_size);
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

	rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}
        secret_key_hex = bytearray2hexstring(shared_secret_d, kem->length_shared_secret);
	printf("Shared secret:%s\n", secret_key_hex);

	printf("[example_heap]  OQS_KEM_frodokem_640_aes public key size:%lu, secret key size:%lu, ciphertest size:%lu,shared_secrete size:%lu\n",
		kem->length_public_key, kem->length_secret_key, kem->length_ciphertext, kem->length_shared_secret);
	printf("[example_heap]  OQS_KEM_frodokem_640_aes operations completed.\n");
	cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
	             ciphertext, kem);

	return OQS_SUCCESS; // success
}

OQS_STATUS test_bouncycastle2(void) {
	OQS_KEM *kem = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *ciphertext = NULL;
	uint8_t *shared_secret_e = NULL;
	uint8_t *shared_secret_d = NULL;
	FILE* fp = NULL;
	int public_key_size = 0;
	char* secret_key_hex = NULL;

	kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
	if (kem == NULL) {
		printf("[test_bouncycastle]  OQS_KEM_frodokem_640_aes was not enabled at "
		       "compile-time.\n");
		return OQS_ERROR;
	}

	public_key = malloc(kem->length_public_key);
	secret_key = malloc(kem->length_secret_key);
	ciphertext = malloc(kem->length_ciphertext);
	shared_secret_e = malloc(kem->length_shared_secret);
	shared_secret_d = malloc(kem->length_shared_secret);
	if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) ||
	        (shared_secret_e == NULL) || (shared_secret_d == NULL)) {
		fprintf(stderr, "ERROR: malloc failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

	fp = fopen("/home/kxie/Desktop/oqs-bc/bc_public_key.txt", "r");
	while (!fp) {
	    fprintf(stderr, "/home/kxie/Desktop/oqs-bc/bc_public_key.txt does not exist, wait...\n");
            usleep(1000 * 1000 * 60);
	    fp = fopen("/home/kxie/Desktop/oqs-bc/bc_public_key.txt", "r");
	}
	fclose(fp);
	fprintf(stderr, "Reading public key from bouncycastle\n");
	public_key = readbytearrayfromfile("/home/kxie/Desktop/oqs-bc/bc_public_key.txt", &public_key_size);
	fprintf(stderr, "Public key size:%d\n", public_key_size);

	if (public_key == NULL || (size_t) public_key_size != kem->length_public_key) {
		fprintf(stderr, "ERROR: can not read ciphertext or ciphertext_size:%d\n", public_key_size);
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);
		return OQS_ERROR;
	}
	OQS_STATUS rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);
		return OQS_ERROR;
	}
	writebytearraytofile(ciphertext, kem->length_ciphertext, "/home/kxie/Desktop/oqs-bc/oqs_cipher_text.txt");
        secret_key_hex = bytearray2hexstring(shared_secret_e, kem->length_shared_secret);
	printf("Shared secret:%s\n", secret_key_hex);

	printf("[example_heap]  OQS_KEM_frodokem_640_aes public key size:%lu, secret key size:%lu, ciphertest size:%lu,shared_secrete size:%lu\n",
		kem->length_public_key, kem->length_secret_key, kem->length_ciphertext, kem->length_shared_secret);
	printf("[example_heap]  OQS_KEM_frodokem_640_aes operations completed.\n");
	cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
	             ciphertext, kem);
	return OQS_SUCCESS;
}

OQS_STATUS test_kyber(void) {
#ifndef OQS_ENABLE_KEM_kyber_512 // if KEM_kyber_512 was not enabled at compile-time
	printf("[example_stack] OQS_KEM_kyber_512 was not enabled at "
	       "compile-time.\n");
	return OQS_ERROR;
#else
	uint8_t public_key[OQS_KEM_kyber_512_length_public_key];
	uint8_t secret_key[OQS_KEM_kyber_512_length_secret_key];
	uint8_t ciphertext[OQS_KEM_kyber_512_length_ciphertext];
	uint8_t shared_secret_e[OQS_KEM_kyber_512_length_shared_secret];
	uint8_t shared_secret_d[OQS_KEM_kyber_512_length_shared_secret];
	char *secret_key_hex;

	OQS_STATUS rc = OQS_KEM_kyber_512_keypair(public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_kyber_512_keypair failed!\n");
		cleanup_stack(secret_key, OQS_KEM_kyber_512_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_kyber_512_length_shared_secret);

		return OQS_ERROR;
	}
	rc = OQS_KEM_kyber_512_encaps(ciphertext, shared_secret_e, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_kyber_512_encaps failed!\n");
		cleanup_stack(secret_key, OQS_KEM_kyber_512_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_kyber_512_length_shared_secret);

		return OQS_ERROR;
	}
	rc = OQS_KEM_kyber_512_decaps(shared_secret_d, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_kyber_512_decaps failed!\n");
		cleanup_stack(secret_key, OQS_KEM_kyber_512_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_kyber_512_length_shared_secret);

		return OQS_ERROR;
	}
        secret_key_hex = bytearray2hexstring(shared_secret_e, OQS_KEM_kyber_512_length_shared_secret);
	printf("Shared secret:%s\n", secret_key_hex);
        secret_key_hex = bytearray2hexstring(shared_secret_d, OQS_KEM_kyber_512_length_shared_secret);
	printf("Shared secret:%s\n", secret_key_hex);
	printf("[example_stack] OQS_KEM_kyber_512 operations completed.\n");

	return OQS_SUCCESS; // success!
#endif
}
