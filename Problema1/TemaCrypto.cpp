#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "crypt32")

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>

using byte = unsigned char;

typedef struct KeySize {
	byte* Key;
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

generatedKs generate_Ks(char* username, char* password) {
	byte* token_seed, * input_id, * digest, * Ks;
	int maxlen;
	time_t time;
	RAND_seed(&time, sizeof(time));

	if (strlen(username) > strlen(password))
		maxlen = strlen(username);
	else
		maxlen = strlen(password);

	char* xor_string = (char*)malloc(maxlen);

	input_id = (byte*)malloc(strlen(username) + strlen(password));
	memcpy((void*)input_id, username, strlen(username));
	memcpy((void*)(input_id + strlen(username)), password, strlen(password));

	token_seed = (byte*)malloc(64);
	RAND_bytes(token_seed, 64);

	digest = (byte*)malloc(strlen(username) + strlen(password));
	SHA512(input_id, strlen(username) + strlen(password), digest);
	Ks = (byte*)malloc(512);

	for (int i = 0; i < maxlen; i++) {
		xor_string[i] = digest[i] ^ token_seed[i];
	}

	memcpy((void*)Ks, xor_string, maxlen);

	generatedKs genKs;
	KeySize k;
	k.Key = Ks;
	k.size = strlen(username) + strlen(password);
	genKs.k = k;
	genKs.salt.content = token_seed;
	genKs.salt.size = 64;

	return genKs;
}

void encrypt_AES256CTR(char* infile, char* outfile, generatedKs genKs) {
	byte tempVal[48]; // SHA384 - 48 bytes
	byte K_aes[32];
	byte temp[16]; // valorile concatenate
	byte* file_content;
	byte enc[AES_BLOCK_SIZE], block[AES_BLOCK_SIZE], * ciphertext;
	AES_KEY aesKey;
	BIGNUM* Counter = BN_new();
	double x = 0x0000000000000000;
	int infile_size;

	ciphertext = (byte*)malloc(sizeof(byte) * AES_BLOCK_SIZE);

	AES_set_encrypt_key(genKs.k.Key, 256, &aesKey); // AES 256

	SHA384(genKs.k.Key, genKs.k.size, tempVal);
	memcpy((void*)K_aes, tempVal, 32);
	memcpy((void*)temp, (tempVal + 48 - 8), 8);
	memcpy((void*)(temp + 8), &x, 8); // CHECK IF THIS WORKS
	BN_bin2bn(temp, 16, Counter);

	FILE* fin = fopen(infile, "rb");
	FILE* fout = fopen(outfile, "wb");
	fseek(fin, 0, SEEK_END);
	infile_size = ftell(fin);
	fseek(fin, 0, SEEK_SET);

	file_content = (byte*)malloc(infile_size);
	fread(file_content, infile_size, 1, fin);

	KeySize k = padding(infile_size, file_content);
	file_content = k.Key; // e content, nu key

	fwrite(genKs.salt.content, genKs.salt.size, 1, fout);
	int it_end = k.size / 32; // iteration end
	for (int i = 0; i < k.size / AES_BLOCK_SIZE; i++) {
		if (i > k.size / 32)
			BN_add(Counter, Counter, BN_value_one());

		BN_bn2bin(Counter, temp); // transform in binar pe Counter si il stochez in temp
		AES_encrypt(temp, enc, &aesKey); // criptez counter stocat in temp

		// afisez temp in hex
		for (int i = 0; i < 16; i++) {
			printf("%02X", temp[i]);
		}
		printf("\n");

		BN_add(Counter, Counter, BN_value_one());
		memcpy((void*)block, (void*)(file_content + i * AES_BLOCK_SIZE), AES_BLOCK_SIZE); // blockul de plaintext e salvat in block
		ciphertext = xor_this(block, enc, AES_BLOCK_SIZE);

		fwrite(ciphertext, AES_BLOCK_SIZE, 1, fout);
	}
	BN_free(Counter);
	free(file_content);
	fclose(fin);
	fclose(fout);
}

int get_exp(KeySize Ks) {
	for (int i = 0; i < Ks.size; i++) {
		if (isPrime(int(Ks.Key[i])))
			return int(Ks.Key[i]);
	}
	return 43;
}

RSAKeyPair generate_RSAKeyPair(int exp) {
	RSAPrivateKey privKey;
	RSAPublicKey pubKey;

	BIGNUM* p, * q, * n, * totient, * p_1, * q_1, * e, * d, * gdc;
	BN_CTX* ctx;

	p = BN_new();
	q = BN_new();
	n = BN_new();
	totient = BN_new();
	p_1 = BN_new();
	q_1 = BN_new();
	e = BN_new();
	d = BN_new();
	gdc = BN_new();
	ctx = BN_CTX_new();

	BN_set_word(e, exp);

	BN_generate_prime(p, 1024, 0, nullptr, nullptr, nullptr, nullptr);
	BN_generate_prime(q, 1024, 0, nullptr, nullptr, nullptr, nullptr);
	BN_mul(n, p, q, ctx);

	BN_sub(p_1, p, BN_value_one());
	BN_sub(q_1, q, BN_value_one());
	BN_mul(totient, p_1, q_1, ctx);

	BN_mod_inverse(d, e, totient, ctx);

	// nu stiu exact daca trebuie initializate
	privKey.modulus = BN_new();
	privKey.pubExp = BN_new();
	privKey.privExp = BN_new();
	privKey.prime1 = BN_new();
	privKey.prime2 = BN_new();

	pubKey.exponent = BN_new();
	pubKey.modulus = BN_new();
	// 
	BN_copy(privKey.modulus, n);
	BN_copy(privKey.pubExp, e);
	BN_copy(privKey.privExp, d);
	BN_copy(privKey.prime1, p);
	BN_copy(privKey.prime2, q);


	BN_copy(pubKey.exponent, e);
	BN_copy(pubKey.modulus, n);

	RSAKeyPair pair;
	pair.privKey = privKey;
	pair.pubKey = pubKey;

	return pair;
}

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

ContentSize encrypt_RSA(const char* infileName, RSAPrivateKey privKey) {
	byte* enc, *file_content;
	BIGNUM* message, * message_length, *bn_filesize, *r;
	BN_CTX* ctx;
	int filesize;

	ctx = BN_CTX_new();
	message = BN_new();
	message_length = BN_new();
	bn_filesize = BN_new();
	r = BN_new();


	FILE* fin = fopen(infileName, "rb");
	fseek(fin, 0, SEEK_END);
	filesize = ftell(fin);
	fseek(fin, 0, SEEK_SET);

	file_content = (byte*)malloc(filesize);
	fread(file_content, filesize, 1, fin);

	file_content = padding_RSA(file_content, 256 - filesize, filesize);

	// veirific content sa nu fie mai mare decat modulus
	BN_set_word(bn_filesize, filesize);
	if (filesize > BN_num_bytes(privKey.modulus) - 11){ // daca bn_filesize > modulus
		printf("Mesajul este prea mare pentru cheie");
		exit(0);
	}

	BN_bin2bn(file_content, filesize, message);
	BN_mod_exp(r, message, privKey.privExp, privKey.modulus, ctx);
	enc = (byte*)malloc(BN_num_bytes(r));
	BN_bn2bin(r, enc);

	fclose(fin);

	ContentSize c;
	c.content = enc;
	c.size = BN_num_bytes(r);

	return c;
}

void sign(Salt token_seed, RSAPrivateKey privKey, const char* infileName, const char* outfileName) {

	byte* infile_content, * outfile_content;
	ContentSize c;

	FILE* fin = fopen(infileName, "rb");
	FILE* fout = fopen(outfileName, "wb");

	c = encrypt_RSA(infileName, privKey);
	int infile_size = fileSize(infileName);
	infile_content = (byte*)malloc(fileSize(infileName));
	outfile_content = (byte*)malloc(token_seed.size + infile_size + c.size);
	fread(infile_content, infile_size, 1, fin);

	memcpy((void*)outfile_content, token_seed.content, token_seed.size);
	memcpy((void*)(outfile_content + token_seed.size), infile_content, infile_size);
	memcpy((void*)(outfile_content + token_seed.size + infile_size), c.content, c.size);

	fwrite(outfile_content, token_seed.size + infile_size + c.size, 1, fout);

	fclose(fin);
	fclose(fout);
}

int main() {
	char username[256], password[256];
	generatedKs Ks;
	RSAKeyPair pair;

	printf("Enter username: \n");
	fgets(username, 255, stdin);
	printf("Enter password: \n");
	fgets(password, 255, stdin);

	Ks = generate_Ks(username, password);
	encrypt_AES256CTR((char*)"in.txt", (char*)"out.txt", Ks);

	pair = generate_RSAKeyPair(get_exp(Ks.k));
	sign(Ks.salt, pair.privKey, "in.txt", "signed.txt");

	unsigned long eroare = ERR_get_error();
	if (eroare)
		printf("%s", ERR_reason_error_string(eroare));

	return 1;
}