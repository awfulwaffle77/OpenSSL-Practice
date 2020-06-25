#include <stdio.h>
#include <vector>

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

using namespace std;
using byte = unsigned char;

typedef struct ContentSize {
	byte* content;
	long size;
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

ContentSize padding(long file_size, byte* content) { // lungimea textului si continutul fisierului

	// se face padding completand un block. Daca ultimul block este complet, se face padding cu un block de 0x10
	int dif = 16 - (file_size % 16);
	byte dif_to_byte = dif;
	content = (byte*)realloc(content, file_size + dif);
	for (int i = 0; i < dif; i++) {
		memcpy((void*)(content + file_size + i), &dif_to_byte, 1);
	}
	ContentSize returnVal;
	returnVal.content = content; // nu e key, e file content
	returnVal.size = file_size + dif;

	return returnVal;

}

vector<RSA*> generateKeyTriplet(const char* f1, const char* f2, const char* f3) {
	// Nu am putut genera cheile din cod, deoarece cheia era prea scurta. Am generat cu openssl in cmd
	vector<RSA*> KeyTriplet;
	RSA* key;
	BIO* bp1, *bp2, *bp3;
	bp1 = BIO_new_file(f1,"rb");
	bp2 = BIO_new_file(f2, "rb");
	bp3 = BIO_new_file(f3, "rb");

	key = PEM_read_bio_RSAPrivateKey(bp1, nullptr, nullptr, nullptr);
	KeyTriplet.push_back(key);
	key = PEM_read_bio_RSAPrivateKey(bp2, nullptr, nullptr, nullptr);
	KeyTriplet.push_back(key);
	key = PEM_read_bio_RSAPrivateKey(bp3, nullptr, nullptr, nullptr);
	KeyTriplet.push_back(key);
	
	return KeyTriplet;
}

byte* generateSeedKey(vector<RSA*> RSATriplet, int keySize) {
	BIGNUM* exp1, * exp2, * exp3;
	byte* x1, * x2, * x3, * seed_key;

	exp1 = BN_new();
	exp2 = BN_new();
	exp3 = BN_new();

	x1 = (byte*)malloc(keySize);
	x2 = (byte*)malloc(keySize);
	x3 = (byte*)malloc(keySize);
	seed_key = (byte*)malloc(keySize);

	BN_copy(exp1, RSA_get0_d(RSATriplet[0]));
	BN_copy(exp2, RSA_get0_d(RSATriplet[1]));
	BN_copy(exp3, RSA_get0_d(RSATriplet[2]));

	BN_bn2bin(exp1, x1);
	BN_bn2bin(exp2, x2);
	BN_bn2bin(exp3, x3);

	for (int i = 0; i < keySize; i++) {
		seed_key[i] = x1[i] ^ x2[i];
	}
	for (int i = 0; i < keySize; i++) {
		seed_key[i] = seed_key[i] ^ x3[i];
	}

	return seed_key;
}

vector<byte*> generateSymmetricKey(byte* seed_key) {
	vector<byte*> symKeys;
	byte* x, * K1, * K2, * K3;
	x = (byte*)calloc(512, 1);
	K1 = (byte*)calloc(64, 1);
	K2 = (byte*)calloc(64, 1);
	K3 = (byte*)calloc(64, 1);

	SHA512(seed_key, 80, x);  
	for (int i = 2; i < 1576; i++) { // cerinta specifica iteratii de la 1 la 1576, am facut prima iteratie anterior
		SHA512(x, 512, x);
	}
		
	symKeys.push_back(K1);
	symKeys.push_back(K2);
	symKeys.push_back(K3);

	for (int i = 0; i < 3; i++) {
		memcpy(symKeys[i], (x + 64 / 8 * i), 64 / 8); // copiez 8 octeti
	}

	return symKeys;
}

ContentSize enc3DES(vector<byte*> keys, const char* filename) {
	byte* content;
	FILE* fin = fopen(filename, "rb");

	fseek(fin, 0, SEEK_END);
	int fsize = ftell(fin);
	fseek(fin, 0, SEEK_SET);

	content = (byte*)calloc(fsize, 1);
	fread(content, fsize, 1, fin);
	ContentSize c = padding(fsize, content);
	memcpy(content, c.content, c.size);
	
	DES_cblock b1[8], b2[8], b3[8], *input, *output;
	DES_key_schedule sk1, sk2, sk3;
	memcpy(b1, keys[0], 8);
	memcpy(b2, keys[1], 8);
	memcpy(b3, keys[2], 8);

	input = (DES_cblock*)malloc(8);
	output = (DES_cblock*)malloc(8);
	//memcpy(input, content, fsize);

	DES_set_key_checked(b1, &sk1);
	DES_set_key_checked(b2, &sk2);
	DES_set_key_checked(b3, &sk3);

	ContentSize ret;
	ret.size = 0;
	for (int i = 0; i < c.size / 8; i++) { // pentru ca fiecare encryption cripteaza doar 8 bytes
		memcpy(input, content + 8 * i, 8);
		DES_ecb3_encrypt(input, output, &sk1, &sk2, &sk3, DES_ENCRYPT);
		memcpy(content + 8*i, output, 8);
		ret.size += 8;
	}
	free(input);
	free(output);

	ret.content = content;

	return ret;
}

vector<ContentSize> encSymKeys(vector<RSA*> keyTriplet, vector<byte*> symKeys) {
	byte* temp;
	BIGNUM* k, * n, * r, * cst;
	BN_CTX* ctx;
	vector<ContentSize> encryptedSymKeys;

	k = BN_new();
	n = BN_new();
	r = BN_new();
	cst = BN_new();
	ctx = BN_CTX_new();
	BN_set_word(cst, 17);
		
	for (int i = 0; i < 3; i++) {
		ContentSize c;
		temp = (byte*)malloc(80);
		c.content = temp;
		c.size = -1;
		encryptedSymKeys.push_back(c);
	}
	for (int i = 0; i < keyTriplet.size(); i++) { // cripteaza RSA cele 3 chei simetrice K1, K2, K3 de 8 bytes
		BN_bin2bn(symKeys[i], 8, k);
		n = BN_dup(RSA_get0_n(keyTriplet[i]));
		BN_mod_exp(r, k, cst, n, ctx);
		BN_bn2bin(r, encryptedSymKeys[i].content);
		encryptedSymKeys[i].size = BN_num_bytes(r);
	}

	return encryptedSymKeys;
}

void lastAssembly(ContentSize encFiledata, vector<ContentSize> encSymKeys) {

	for (int i = 0; i < 3; i++) {
		printf("%02X\n", encSymKeys[i].size);
		for (int j = 0; j < encSymKeys[i].size; j++) {
			if (j % 10 == 0)
				printf("\n");
			printf("%02X", encSymKeys[i].content[j]);
		}
	}

	printf("%02X\n", encFiledata.size);
	for (int j = 0; j < encFiledata.size; j++) {
			if (j % 10 == 0)
				printf("\n");

			printf("%02X", encFiledata.content[j]);
	}
}

int main() {

	time_t t;
	RAND_seed(&t, sizeof(t));

	int keySize = 80;
	ContentSize encryptedFiledata;
	vector<ContentSize> encryptedSymKeys;

	vector<RSA*> keyTriplet = generateKeyTriplet("rsa1.prv", "rsa2.prv", "rsa3.prv");
	byte* seed_key = generateSeedKey(keyTriplet, keySize);
	vector<byte*> symKeys = generateSymmetricKey(seed_key);

	// // // // // // // // // 
	// Uneori nu se aloca corespunzator memorie in functia enc3DES si encryptedFiledata e garbage
	// // // // // // // // //
	
	encryptedFiledata = enc3DES(symKeys, "fin.txt");
	encryptedSymKeys = encSymKeys(keyTriplet, symKeys);
	lastAssembly(encryptedFiledata, encryptedSymKeys);

	unsigned long eroare = ERR_get_error();
	if (eroare)
		printf("%s", ERR_reason_error_string(eroare));

	return 1;
}
