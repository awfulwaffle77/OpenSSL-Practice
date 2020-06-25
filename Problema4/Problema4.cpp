#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "crypt32")

#include <openssl/pem.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

using byte = unsigned char;

typedef struct ContentSize {
	byte* content;
	long size;
};

byte* getSalt() {
	byte* salt = (byte*)malloc(10);
	RAND_bytes(salt, 10);

	return salt;
}

byte* xor_this(byte* s1, byte* s2, int size) {
	byte* ret = (byte*)malloc(sizeof(byte) * size);

	for (int i = 0; i < size; i++) {
		ret[i] = s1[i] ^ s2[i];
	}
	return ret;
}

byte* calculateF(int i, int n, char* passphrase, byte* salt) {
	byte* digest = (byte*)malloc(256 / 8);
	byte* concat = (byte*)malloc(strlen(passphrase) + 256 / 8);
	byte* xored = (byte*)calloc(256 / 8, 1);

	memcpy(concat, passphrase, strlen(passphrase));
	memcpy(concat + strlen(passphrase), salt, 10);
	memcpy(concat + strlen(passphrase) + 10, &i, 1);
	SHA256(concat, strlen(passphrase) + 10 + 1, digest);
	xored = xor_this(xored, digest, 256 / 8);

	for (int j = 1; j < n; j++) {
		memcpy(concat, passphrase, strlen(passphrase));
		memcpy(concat + strlen(passphrase), digest, 256/8);
		SHA256(concat, strlen(passphrase) + 256 / 8, digest);
		xored = xor_this(xored, digest, 256 / 8);
	}

	free(concat);
	free(digest);
	return xored;
}

byte* getAI(byte* K, byte* IV, byte* content, int fsize) {
	byte * digest, *encrypted;
	AES_KEY aesKey;

	AES_set_encrypt_key(K, 192, &aesKey);

	encrypted = (byte*)malloc(64);
	digest = (byte*)malloc(512 / 8);

	SHA512(content, fsize, digest);

	AES_cbc_encrypt(content, encrypted, fsize, &aesKey, IV, AES_ENCRYPT);

	free(content);
	free(digest);

	return encrypted;
}

void addAuthInfo(char* filename, char* passphrase, char n) {
	byte* salt = getSalt();
	byte* T = (byte*)malloc(64); // o sa tin doua F-uri
	byte* K = (byte*)malloc(24);
	byte* IV = (byte*)malloc(16);

	// K este 24 bytes, IV este 16 bytes, F are 32 octeti, am nevoie de 2 F-uri
	for (int i = 0; i < 2; i++) {
		memcpy(T + i * 32, calculateF(i, n, passphrase, salt), 32);
	}
	
	memcpy(K, T, 24);
	memcpy(IV, T + 24, 16);
	
	FILE* fAI = fopen(filename, "rb");
	fseek(fAI, 0, SEEK_END);
	int AIsize = ftell(fAI);
	fseek(fAI, 0, SEEK_SET);
	byte* AI_content = (byte*)malloc(AIsize);
	fread(AI_content, AIsize, 1, fAI);
	byte* AI = getAI(K, IV, AI_content, AIsize);

	fclose(fAI);

	FILE* fnew = fopen("new.txt", "wb");
	FILE* fin = fopen(filename, "rb");
	fwrite(salt, 10, 1, fnew);
	fwrite(&n, 1, 1, fnew);
	fwrite(AI, 64, 1, fnew);
	fseek(fin, 0, SEEK_END);
	int fsize = ftell(fin);
	fseek(fin, 0, SEEK_SET);
	byte* content = (byte*)malloc(fsize);
	fread(content, fsize, 1, fin);
	fwrite(content, fsize, 1, fnew);

	fclose(fnew);
	fclose(fin);
	free(salt);
	free(T);
	free(K);
	free(IV);
	free(content);
}

bool verifyAuthInfo(char* filename, char* passphrase) {
	FILE* fin = fopen(filename, "rb");

	fseek(fin, 0, SEEK_END);
	int fsize = ftell(fin);
	fseek(fin, 0, SEEK_SET);

	byte* content = (byte*)malloc(fsize);
	byte* salt = (byte*)malloc(10);
	byte* n = (byte*)malloc(1);
	byte* AI = (byte*)malloc(64);

	fseek(fin, 10 + 1 + 64, SEEK_SET);
	int oldContent_size = fsize - ftell(fin);
	fseek(fin, 0, SEEK_SET);
	byte* oldContent = (byte*)malloc(oldContent_size);
	
	fread(salt, 10, 1, fin);
	fread(n, 1, 1, fin);
	fread(AI, 64, 1, fin);
	fread(oldContent, oldContent_size, 1, fin);
	fseek(fin, 0, SEEK_SET);
	fread(content, fsize, 1, fin);


	byte* T = (byte*)malloc(64); // o sa tin doua F-uri
	byte* K = (byte*)malloc(24);
	byte* IV = (byte*)malloc(16);

	int intN = n[0];
	// K este 24 bytes, IV este 16 bytes, F are 32 octeti, am nevoie de 2 F-uri
	for (int i = 0; i < 2; i++) {
		memcpy(T + i * 32, calculateF(i, intN, passphrase, salt), 32);
	}

	memcpy(K, T, 24);
	memcpy(IV, T + 24, 16);

	byte* AI_generated = getAI(K, IV, oldContent, oldContent_size);
	
	if (memcmp(AI, AI_generated, 64) == 0)
		return true;
	return false;

	fclose(fin);
}

int main() {
	time_t t;
	RAND_seed(&t, sizeof(t));

	char passphrase[256];
	printf("Enter passphrase: \n");
	fgets(passphrase, 255, stdin);

	addAuthInfo((char*)"fin.txt", passphrase, 3);

	if (verifyAuthInfo((char*)"new.txt", passphrase))
		printf("\nAuthentic.");
	else
		printf("\nNot authentic.");

	return 1;
}