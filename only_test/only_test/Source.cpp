//#include <iomanip>
//#include <string>
//#include <string.h>
//#include <stdio.h>
//#include <openssl/rsa.h>
//#include <openssl/pem.h>
//
//#pragma comment (lib, "libcrypto.lib")
//#pragma comment (lib, "libssl.lib")
//
//#pragma warning(disable : 4996)
//
//
//bool generate_key()
//{
//	int				ret = 0;
//	RSA* r = NULL;
//	BIGNUM* bne = NULL;
//	BIO* bp_public = NULL, * bp_private = NULL;
//
//	int				bits = 2048;
//	unsigned long	e = RSA_F4;
//
//	// 1. generate rsa key
//	bne = BN_new();
//	ret = BN_set_word(bne, e);
//	if (ret != 1) {
//		goto free_all;
//	}
//
//	r = RSA_new();
//	ret = RSA_generate_key_ex(r, bits, bne, NULL);
//	if (ret != 1) {
//		goto free_all;
//	}
//
//	// 2. save public key
//	bp_public = BIO_new_file("public.pem", "w+");
//	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
//	if (ret != 1) {
//		goto free_all;
//	}
//
//	// 3. save private key
//	bp_private = BIO_new_file("private.pem", "w+");
//	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
//
//	// 4. free
//free_all:
//
//	BIO_free_all(bp_public);
//	BIO_free_all(bp_private);
//	RSA_free(r);
//	BN_free(bne);
//
//	return (ret == 1);
//}
//
//int main(int argc, char* argv[])
//{
//	generate_key();
//	return 0;
//}

#include <iostream>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "libssl.lib")
#pragma warning(disable : 4996)

void handleErrors(void);
int envelope_seal(EVP_PKEY** pub_key, unsigned char* plaintext, int plaintext_len,
    unsigned char** encrypted_key, int* encrypted_key_len, unsigned char* iv,
    unsigned char* ciphertext);
int envelope_open(EVP_PKEY* priv_key, unsigned char* ciphertext, int ciphertext_len,
    unsigned char* encrypted_key, int encrypted_key_len, unsigned char* iv,
    unsigned char* plaintext);

using namespace std;

int main()
{
    RSA* rsa_pubkey = RSA_new();
    RSA* rsa_prikey = RSA_new();
    EVP_PKEY* evp_pubkey = EVP_PKEY_new();
    EVP_PKEY* evp_prikey = EVP_PKEY_new();
    FILE* rsa_prikey_file = NULL;
    FILE* rsa_pubkey_file = NULL;
    rsa_pubkey_file = fopen("pubkey.pem", "r");
    if (!rsa_pubkey_file)
    {
        fprintf(stderr, "Error loading PEM RSA Public Key File.\n");
        exit(2);
    }

    PEM_read_RSA_PUBKEY(rsa_pubkey_file, &rsa_pubkey, NULL, NULL);

    EVP_PKEY_assign_RSA(evp_pubkey, rsa_pubkey);

    rsa_prikey_file = fopen("key.pem", "r");
    if (!rsa_prikey_file)
    {
        fprintf(stderr, "Error loading PEM RSA private Key File.\n");
        exit(2);
    }
    PEM_read_RSAPrivateKey(rsa_prikey_file, &rsa_prikey, NULL, NULL);

    EVP_PKEY_assign_RSA(evp_prikey, rsa_prikey);


    unsigned char* plaintext = (unsigned char*)"The quick brown fox jumps over thes lazy dog";
    unsigned char ciphertext[256] = {};
    unsigned char plaintextt[256] = {};
    int ciphertextlength;
    unsigned char* encKey = (unsigned char*)malloc(RSA_size(rsa_pubkey));
    unsigned char iv[16] = {};


    envelope_seal(&evp_pubkey, plaintext, strlen((const char*)plaintext), &encKey, &ciphertextlength, iv, ciphertext);

    envelope_open(evp_prikey, ciphertext, strlen((const char*)ciphertext), encKey, strlen((const char*)encKey), iv, plaintextt);

    std::cout << "Result: " << plaintextt << std::endl;

    EVP_PKEY_free(evp_pubkey);
    EVP_PKEY_free(evp_prikey);
    free(ciphertext);
    free(encKey);

}

int envelope_seal(EVP_PKEY** pub_key, unsigned char* plaintext, int plaintext_len,
    unsigned char** encrypted_key, int* encrypted_key_len, unsigned char* iv,
    unsigned char* ciphertext)
{
    EVP_CIPHER_CTX* ctx;

    int ciphertext_len;

    int len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_SealInit(ctx, EVP_aes_128_cbc(),
        encrypted_key,
        encrypted_key_len,
        iv,
        pub_key, 1))
    {
        handleErrors();
    }

    if (1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        handleErrors();
    }
    ciphertext_len = len;

    if (1 != EVP_SealFinal(ctx, ciphertext + len, &len))
    {
        handleErrors();
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}



int envelope_open(EVP_PKEY* priv_key, unsigned char* ciphertext, int ciphertext_len,
    unsigned char* encrypted_key, int encrypted_key_len, unsigned char* iv,
    unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx;

    int len;

    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
    }

    if (1 != EVP_OpenInit(ctx, EVP_aes_128_cbc(), encrypted_key,
        encrypted_key_len, iv, priv_key))
    {
        handleErrors();
    }

    if (1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_OpenFinal(ctx, plaintext + len, &len))
    {
        handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext[plaintext_len] = '\0';

    return plaintext_len;
}


void handleErrors(void)
{
    perror("Error: ");
    ERR_print_errors_fp(stderr);
    abort();
}