#include <stdio.h>
#include <map>
#include <string.h>

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

byte* getIV(byte* hash) {
	byte* IV;
	IV = (byte*)malloc(128 / 8);
	memcpy(IV, hash, 128 / 8);

	return IV;
}

byte* getSalt() {
	byte* salt;
	
	salt = (byte*)malloc(8);
	RAND_bytes(salt, 8);

	return salt;

}

byte* getKey(byte* hash) {
	byte* key = (byte*)malloc(128 / 8);
	memcpy(key, (hash + 128 / 8), 128 / 8);
	return key;
}

void genLoginToken(byte* salt, byte* user, byte* hash) {
	byte* plaintext, *ciphertext, *loginToken;
	AES_KEY aesKey; 
	
	loginToken = (byte*)malloc(8 + 128 / 8); // lg salt + lg cheie
	ciphertext = (byte*)malloc(128 / 8);
	byte* IV = getIV(hash);
	byte* key = getKey(hash);
	
	AES_set_encrypt_key(key, 128, &aesKey);
	// nu am nevoie de for pentru ca pot face criptarea cbc o singura data
	AES_cbc_encrypt(user, ciphertext, 128 / 8, &aesKey, IV, AES_ENCRYPT);
	
	memcpy(loginToken, salt, 8);
	memcpy(loginToken + 8, ciphertext, 128 / 8);

	FILE* fin = fopen("login.user", "wb");
	fwrite(loginToken, 8 + 128 / 8, 1, fin);
	fclose(fin);
}

byte* getHash(char* passphrase, byte* salt) {
	byte *digest, *concat;
	digest = (byte*)malloc(256/8);
	concat = (byte*)malloc(256 / 8 + 8);
	memcpy(concat, passphrase, strlen(passphrase));
	memcpy((concat + strlen(passphrase)), salt, 8);
	SHA256(concat, strlen(passphrase) + 8, digest);

	return digest;
}

void set_password(char* user, char* passphrase) {

	byte* salt = getSalt();
	byte* hash = getHash(passphrase, salt);
	genLoginToken(salt, (byte*)user, hash);
	printf("Parola setata cu succes.\n");
}

bool login(char* user, char* passphrase) {
	byte* salt = (byte*)malloc(8);
	byte* content = (byte*)malloc(128 / 8);
	byte* dec = (byte*)malloc(128 / 8);
	int usersize = strlen(user);
	
	AES_KEY aesKey;
	
	FILE* fin = fopen("login.user", "rb");
	fread(salt, 8, 1, fin);

	byte* key = getKey(getHash(passphrase, salt));
	byte* iv = getIV(getHash(passphrase, salt));
	AES_set_decrypt_key(key, 128, &aesKey);

	fread(content, 128 / 8, 1, fin);

	AES_cbc_encrypt(content, dec, 128 / 8, &aesKey, iv, AES_DECRYPT);

	int res = memcmp(user, dec, usersize);
	if (res == 0)
		return true;
	else
		return false;
}

int main() {

	time_t t;
	RAND_seed(&t, sizeof(t));

	char passphrase[128];
	char user[128];

	
	printf("Introduceti username: \n");
	fgets((char*)user, 128, stdin);
	printf("Introduceti passphrase: \n");
	fgets(passphrase, 127, stdin);

	set_password(user, passphrase);

	printf("Introduceti username: \n");
	fgets((char*)user, 128, stdin);
	printf("Introduceti passphrase: \n");
	fgets(passphrase, 127, stdin);

	if (login(user, passphrase))
		printf("\nLogare cu succes.");
	else
		printf("\nLogare invalida.");

	return 1;
}
