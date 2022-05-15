// 编译: gcc -g sm4_en_de.c -o sm4_en_de -L/usr/lib -lssl -lcrypto
// 加密之后数据：2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B
/** 文件名: main.c */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<Windows.h>
#include "openssl/err.h"
#include "openssl/evp.h"

typedef struct
{
	const unsigned char* in_data;
	size_t in_data_len;
	int in_data_is_already_padded;
	const unsigned char* in_ivec;
	const unsigned char* in_key;
	size_t in_key_len;
} test_case_t;

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int test_decrypt_with_cipher(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
	unsigned char* iv, unsigned char* plaintext)
{
	EVP_CIPHER_CTX* ctx;
	int len;
	int plaintext_len;
	int i;
	int count;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
	}
	/*
	 * Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */

	 // EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (1 != EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv)) {
		handleErrors();
	}
	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary.
	 */
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	// 解密数据只能按照向量的整数倍进行，这里向量的长度是16
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		handleErrors();
	}

	/*printf("解密数据：%d\n", len);
	for (i = 0; i < 32; i++) {
		printf("%02x ", *(plaintext + i));
	}
	printf("\n");*/
	plaintext_len = len;
	
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

void test_encrypt_with_cipher(const test_case_t* in, const EVP_CIPHER* cipher,unsigned char* buf, int* len)
{
	unsigned char* out_buf = buf;
	int out_len;
	int out_padding_len;
	int i;
	EVP_CIPHER_CTX* ctx;

	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, cipher, NULL, in->in_key, in->in_ivec);

	//当填充之后会调用该函数
	if (in->in_data_is_already_padded)
	{
		/* Check whether the input data is already padded.
		And its length must be an integral multiple of the cipher's block size. */
		const size_t bs = EVP_CIPHER_block_size(cipher);
		printf("bs %d\n", bs);
		if (in->in_data_len % bs != 0)
		{
			printf("ERROR-1: data length=%d which is not added yet; block size=%d\n", (int)in->in_data_len, (int)bs);
			/* Warning: Remember to do some clean-ups */
			EVP_CIPHER_CTX_free(ctx);
			return;
		}
		/* Disable the implicit PKCS#7 padding defined in EVP_CIPHER */
		EVP_CIPHER_CTX_set_padding(ctx, 0);
	}

	out_len = 0;
	EVP_EncryptUpdate(ctx, out_buf, &out_len, in->in_data, in->in_data_len);
	out_padding_len = 0;
	EVP_EncryptFinal_ex(ctx, out_buf + out_len, &out_padding_len);

	EVP_CIPHER_CTX_free(ctx);
	*len = out_len + out_padding_len;
}

void main()
{
	unsigned char buf[5000];
	unsigned char buf_2[5000];
	int  len;
	int  i;
	const unsigned char data[] =
	{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
	};
	// 上面data 明文对应的密文
	/*const unsigned char data_c[] =
	{
		0x26, 0x77, 0xf4, 0x6b, 0x09, 0xc1, 0x22, 0xcc,
		0x97, 0x55, 0x33, 0x10, 0x5b, 0xd4, 0xa2, 0x2a,
		0xf6, 0x12, 0x5f, 0x72, 0x75, 0xce, 0x55, 0x2c,
		0x3a, 0x2b, 0xbc, 0xf5, 0x33, 0xde, 0x8a, 0x3b,
	};*/
	unsigned char ivec[EVP_MAX_IV_LENGTH] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

     unsigned char key1[16] = ///< key_data, 密钥内容, 至少16字节
	{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
	};

	test_case_t tc;

	tc.in_data = data;
	tc.in_data_len = sizeof(data);
	tc.in_data_is_already_padded = (tc.in_data_len % 16) == 0; // Hard coded 16 as the cipher's block size
	tc.in_key = key1;
	tc.in_key_len = sizeof(key1);
	tc.in_ivec = ivec;

	printf("加密之前数据 %d\n", sizeof(data));
	for (i = 0; i < sizeof(data); i++) {
		printf("%02x ", data[i]);
	}
	printf("\n");

	memset(buf, 0, sizeof(buf));
	_LARGE_INTEGER start_time;
	_LARGE_INTEGER end_time;
	double dqFreq;
	double run_time;
	LARGE_INTEGER f;
	QueryPerformanceFrequency(&f);
	dqFreq = (double)f.QuadPart;
	QueryPerformanceCounter(&start_time);
	test_encrypt_with_cipher(&tc, EVP_sm4_cbc(), buf, &len);
	QueryPerformanceCounter(&end_time);
	run_time = 1000000 * (start_time.QuadPart - end_time.QuadPart) / dqFreq;
	printf("运行时间为：%d\n", run_time);
	printf("加密之后数据 %d\n", len);
	for (i = 0; i < len; i++) {
		printf("%02x ", *(buf + i));
	}
	printf("\n");
	/*
	memset(buf_2, 0, sizeof(buf_2));
	len = test_decrypt_with_cipher(buf, 32, key1, ivec, buf_2);
	printf("解密之后数据 %d \n", len);
	for (i = 0; i < len; i++) {
		printf("%02x ", *(buf_2 + i));
	}
	printf("\n");*/
}
