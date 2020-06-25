#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/bn.h>


using byte = unsigned char;

typedef struct KeySize {
	byte *Key;
	long size;
}KeySize;

typedef struct ContentSize {
	byte* content;
	long size;
}ContentSize;

typedef struct Salt {
	byte* content;
	long size;
}Salt;

typedef struct generatedKs {
	KeySize k;
	Salt salt;
}generatedKs;

typedef struct RSAPublicKey {
	BIGNUM* modulus;
	BIGNUM* exponent;
};

typedef struct RSAPrivateKey {
	BIGNUM* modulus;
	BIGNUM* pubExp; // e
	BIGNUM* privExp; // d
	BIGNUM* prime1;
	BIGNUM* prime2;
}RSAPrivateKey;

typedef struct RSAKeyPair {
	RSAPublicKey pubKey;
	RSAPrivateKey privKey;
}RSAKeyPair;


KeySize padding(long file_size, byte* content) { // lungimea textului si continutul fisierului

	// se face padding completand un block. Daca ultimul block este complet, se face padding cu un block de 0x10
	int dif = 16 - (file_size % 16);
	byte dif_to_byte = dif;
	content = (byte*)realloc(content, file_size + dif);
	for (int i = 0; i < dif; i++) {
		memcpy((void*)(content + file_size + i), &dif_to_byte, 1);
	}
	KeySize returnVal;
	returnVal.Key = content; // nu e key, e file content
	returnVal.size = file_size + dif;

	return returnVal;

}

byte* xor_this(byte* s1, byte* s2, int size) {
	byte* ret = (byte*)malloc(sizeof(byte) * size);

	for (int i = 0; i < size; i++) {
		ret[i] = s1[i] ^ s2[i];
	}
	return ret;
}

bool isPrime(long n) {
	if (n <= 1)
		return false;

	for (int i = 2; i < n; i++)
		if (n % i == 0)
			return false;
	return true;
}

int fileSize(const char* filename) {
	FILE* fin = fopen(filename, "rb");
	fseek(fin, 0, SEEK_END);
	return ftell(fin);
}

