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

typedef struct contentSize {
	byte* content;
	int size;
};

byte* padding_RSA(byte* content, int padding_length_octets, int content_size) {
	byte* input = NULL;
	input = (byte*)malloc(content_size + padding_length_octets);
	input[0] = 0x00;
	input[1] = 0x02;
	for (int i = 0; i < padding_length_octets - 2; i++) {
		byte* r;
		r = (byte*)malloc(1);
		do {
			RAND_bytes(r, 1);

		} while (*r == 0x00);
		input[2 + i] = *r;
	}
	input[padding_length_octets - 1] = 0x00;

	memcpy((void*)(input + padding_length_octets), content, content_size);

	return input;
}

RSA* getPubKey(char* filename) {
	FILE* f = fopen(filename, "rb");
	RSA* key;
	key = PEM_read_RSA_PUBKEY(f, nullptr, nullptr, nullptr);

	return key;
}

RSA* getPrivKey(char* filename) {
	FILE* f = fopen(filename, "rb");
	RSA* key;
	key = PEM_read_RSAPrivateKey(f, nullptr, nullptr, nullptr);

	return key;
}

AES_KEY* getSymKey(byte* KSym) {
	AES_KEY* aesKey;
	aesKey = (AES_KEY*)malloc(sizeof(AES_KEY));
	AES_set_encrypt_key(KSym, 256, aesKey);

	return aesKey;
}

contentSize padding(long file_size, byte* content) { // lungimea textului si continutul fisierului

	// se face padding completand un block. Daca ultimul block este complet, se face padding cu un block de 0x10
	int dif = 16 - (file_size % 16);
	byte dif_to_byte = dif;
	content = (byte*)realloc(content, file_size + dif);
	for (int i = 0; i < dif; i++) {
		memcpy((void*)(content + file_size + i), &dif_to_byte, 1);
	}
	contentSize returnVal;
	returnVal.content = content;
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

contentSize encrypt_RSA(byte* salt_symKey, int content_size, RSA* key) {
	byte* enc, *content;
	BIGNUM* message, * message_length, *bn_filesize, *r;
	BN_CTX* ctx;

	ctx = BN_CTX_new();
	message = BN_new();
	message_length = BN_new();
	bn_filesize = BN_new();
	r = BN_new();

	// RSA Should be padded to match key size;
	content = (byte*)malloc(256);
	content = padding_RSA(salt_symKey, 256 - content_size, content_size);

	// veirific content sa nu fie mai mare decat modulus
	if (content_size > RSA_size(key)){ // daca bn_filesize > modulus
		printf("Mesajul este prea mare pentru cheie");
		exit(0);
	}

	BN_bin2bn(content, RSA_size(key), message);
	const BIGNUM* e = RSA_get0_e(key);
	const BIGNUM* n = RSA_get0_n(key);

	BN_mod_exp(r, message, e, n, ctx);
	enc = (byte*)malloc(BN_num_bytes(r));
	BN_bn2bin(r, enc);
	// Even after padding, the output is not 192 bytes, but less

	contentSize c;
	c.content = enc;
	c.size = 256;

	return c;
}

contentSize removePadding_RSA(byte* decrypted, int dec_size) {
	int size = dec_size;
	int idx = 1;

	// deoarece in BIGNUM se transforma numarul fara leading 0, paddingul meu va incepe cu 0x02
	if (decrypted[0] != 0x02) {
		printf("Eroare la deppading");
		exit(0);
	}
	while (decrypted[idx] != 0x00) {
		size--;
		idx++;
	}
	byte* deppded_content = (byte*)malloc(size);
	memcpy(deppded_content, decrypted + (idx + 1), dec_size - (idx+1));

	contentSize depadded;
	depadded.content = deppded_content;
	depadded.size = dec_size - (idx + 1);

	return depadded;
}

contentSize decrypt_RSA(byte* encrypted, int size, RSA* key) {
	byte* dec, *content;
	BIGNUM* message, * message_length, *bn_filesize, *r;
	BN_CTX* ctx;

	ctx = BN_CTX_new();
	message = BN_new();
	message_length = BN_new();
	bn_filesize = BN_new();
	r = BN_new();

	dec = (byte*)malloc(size);

	BN_bin2bn(encrypted, size, message);
	const BIGNUM* d = RSA_get0_d(key);
	const BIGNUM* n = RSA_get0_n(key);

	BN_mod_exp(r, message, d, n, ctx);
	BN_bn2bin(r, dec);

	return removePadding_RSA(dec, BN_num_bytes(r));
}

contentSize encrypt_AES256CTR(byte* salt, byte* content, int content_size, AES_KEY aesKey) {
	byte* temp;
	byte* encrypted;
	byte *enc, block[AES_BLOCK_SIZE], * ciphertext;
	BIGNUM* Counter = BN_new();

	enc = (byte*)malloc(AES_BLOCK_SIZE);

	ciphertext = (byte*)malloc(sizeof(byte) * AES_BLOCK_SIZE);
	temp = (byte*)calloc(AES_BLOCK_SIZE, 1);
	memcpy(temp, salt, 12);

	BN_bin2bn(temp, AES_BLOCK_SIZE, Counter);
	free(temp);

	contentSize k = padding(content_size, content);
	//free(content);
	content = k.content;
	
	encrypted = (byte*)malloc(k.size);

	int sz = k.size / AES_BLOCK_SIZE;
	for (int i = 0; i < sz; i++) {
		temp = (byte*)malloc(BN_num_bytes(Counter));
		BN_bn2bin(Counter, temp); // transform in binar pe Counter si il stochez in temp
		AES_encrypt(temp, enc, &aesKey); // criptez counter stocat in temp, rezultatul il am in enc

		memcpy(block, (content + (i * AES_BLOCK_SIZE)), AES_BLOCK_SIZE); // copiez un bloc de plaintext

		ciphertext = xor_this(block, enc, AES_BLOCK_SIZE); // xor plaintext cu counter
		
		memcpy((encrypted + (i * AES_BLOCK_SIZE)), ciphertext, AES_BLOCK_SIZE);
		BN_add(Counter, Counter, BN_value_one());
		free(temp);
	}

	BN_free(Counter);

	contentSize c;
	c.content = encrypted;
	c.size = k.size;

	return c;
}

contentSize removePadding(byte* content, int size) {
	// Inlatura paddingul de la AES si pad_to_fit
	int check = content[size - 1];
	int retSize = size;
	for (int i = size - 1;  i >= 0; i--) {
		if (content[i] != check)
			break;
		retSize--;
	}
	contentSize c;
	c.content = content;
	c.size = retSize;

	return c;
}

contentSize decrypt_AES256CTR(byte* salt, byte* content, int content_size, AES_KEY aesKey) {
	byte* temp;
	byte* encrypted;
	byte *enc, block[AES_BLOCK_SIZE], * ciphertext;
	BIGNUM* Counter = BN_new();

	enc = (byte*)malloc(AES_BLOCK_SIZE);

	ciphertext = (byte*)malloc(sizeof(byte) * AES_BLOCK_SIZE);
	temp = (byte*)calloc(AES_BLOCK_SIZE, 1);
	memcpy(temp, salt, 12);

	BN_bin2bn(temp, 16, Counter);
	free(temp);

	encrypted = (byte*)malloc(content_size);

	int sz = content_size / AES_BLOCK_SIZE;
	for (int i = 0; i < sz; i++) {
		temp = (byte*)malloc(BN_num_bytes(Counter));
		BN_bn2bin(Counter, temp); // transform in binar pe Counter si il stochez in temp
		AES_encrypt(temp, enc, &aesKey); // criptez counter stocat in temp
		// in enc am Counterul criptat
		memcpy(block, (content + (i * AES_BLOCK_SIZE)), AES_BLOCK_SIZE);
		// iau un block de ciphertext

		ciphertext = xor_this(block, enc, AES_BLOCK_SIZE); // xor ciphertext cu counter criptat
		
		memcpy((encrypted + (i * AES_BLOCK_SIZE)), ciphertext, AES_BLOCK_SIZE);
		BN_add(Counter, Counter, BN_value_one());
		free(temp);
	}

	BN_free(Counter);

	return removePadding(encrypted, content_size);
}

void encrypt(const char* filename, const char* out_filename, byte* salt, RSA* key) {
	byte* content, *KSym, *concat;
	contentSize aes, rsa;
	FILE* fin = fopen(filename, "rb");

	fseek(fin, 0, SEEK_END);
	int fsize = ftell(fin);
	fseek(fin, 0, SEEK_SET);
	
	content = (byte*)malloc(fsize);
	concat = (byte*)malloc(64);
	KSym = (byte*)malloc(256 / 8);
	RAND_bytes(KSym, 256 / 8);

	fread(content, fsize, 1, fin);

	fclose(fin);

	memcpy(concat, salt, 32);
	memcpy(concat+32, KSym, 32);

	AES_KEY* aesKey = getSymKey(KSym);
	aes = encrypt_AES256CTR(salt, content, fsize, *aesKey);
	rsa = encrypt_RSA(concat, 64, key);
	
	FILE* fout = fopen(out_filename, "wb");
	fwrite(rsa.content, rsa.size, 1, fout);
	fwrite(aes.content, aes.size, 1, fout);

	fclose(fout);
	free(concat);
	free(salt);
	free(KSym);

}

void decrypt(const char* filename, const char* outDecryptedFilename,  RSA* key) {
	byte* rsa_content, *aes_content, *salt, *KSym;
	contentSize rsa_fresh;
	FILE* fout = fopen(filename, "rb"); // fisierul criptat
	// stiu ca RSA_encrypted are 2048 / 8 octeti, pentru ca am cheia pe 2048 biti

	salt = (byte*)malloc(32);
	KSym = (byte*)malloc(32);

	fseek(fout, 0, SEEK_END);
	int fsize = ftell(fout);
	fseek(fout, 0, SEEK_SET);

	rsa_content = (byte*)malloc(fsize);
	fread(rsa_content, 2048 / 8, 1, fout);


	// Pentru ca am facut padding criptarii RSA ca sa fie pe 256 bytes ca sa stiu lg exacta, acum ii dau remove
	rsa_fresh = decrypt_RSA(rsa_content, RSA_size(key), key);
	memcpy(salt, rsa_fresh.content, 32);
	memcpy(KSym, rsa_fresh.content + 32, 32);

	aes_content = (byte*)malloc(fsize - 2048 / 8);
	fread(aes_content, fsize - 2048 / 8, 1, fout);
	fclose(fout);

	// salt si KSym se citesc bine. eroare mai jos, la decriptarea cu AES
	AES_KEY* aesKey = getSymKey(KSym);
	contentSize decrypted = decrypt_AES256CTR(salt, aes_content, fsize - 256, *aesKey);

	fout = fopen(outDecryptedFilename, "wb");
	fwrite(decrypted.content, decrypted.size, 1, fout);
	fclose(fout);

}

int main() {
	time_t t;
	RAND_seed(&t, sizeof(t));

	byte* salt = (byte*)malloc(32);
	RAND_bytes(salt, 32);

	RSA* Kpub = getPubKey((char*)"rsakey.pub");
	encrypt("input.dat", "output.dat", salt, Kpub);

	RSA* Kpriv = getPrivKey((char*)"rsakey.prv");
	decrypt("output.dat", "decrypted.txt", Kpriv);
}