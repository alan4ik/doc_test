#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <iostream>
#include <WinSock2.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "libssl.lib")
#pragma warning(disable : 4996)

int padding = RSA_PKCS1_PADDING;
constexpr auto SERVERADDR = "127.0.0.1";

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
	unsigned char* iv, unsigned char* ciphertext)
{
	EVP_CIPHER_CTX* ctx;
	int len;
	int ciphertext_len;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
	if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv))
		handleErrors();
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handleErrors();
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
	unsigned char* iv, unsigned char* plaintext)
{
	EVP_CIPHER_CTX* ctx;
	int len;
	int plaintext_len;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
	if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv))
		handleErrors();
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		handleErrors();
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

RSA* createRSA(unsigned char* key, int public_key);
char* generetStringPublicKey(RSA* public_key, RSA* keypair);
char* generetStringPrivateKey(RSA* private_key, RSA* keypair);
int public_encrypt(unsigned char* data, int data_len, unsigned char* key, unsigned char* encrypted);
int private_decrypt(unsigned char* enc_data, int data_len, unsigned char* key, unsigned char* decrypted);
std::string base64_encode(char const* bytes_to_encode, int in_len);
std::string base64_decode(std::string& encoded_string);


SOCKET startWSA(SOCKET mysocket);

int main()
{
	// RSA algoritm
	RSA* keypair, * private_key, * public_key = NULL;
	keypair = RSA_new();
	private_key = RSA_new();
	public_key = RSA_new();
	BIGNUM* bne = BN_new();
	BN_set_word(bne, RSA_F4);
	RSA_generate_key_ex(keypair, 2048, bne, NULL);

	char* public_key_char = generetStringPublicKey(public_key, keypair);
	char* private_key_char = generetStringPrivateKey(private_key, keypair);

	public_key = createRSA((unsigned char*)public_key_char, 1);
	private_key = createRSA((unsigned char*)private_key_char, 0);

	unsigned char  encrypted[4098] = {};
	unsigned char decrypted[4098] = {};

	char recvbuf[4096] = "test message";

	int encrypted_length = public_encrypt((unsigned char*)recvbuf, strlen(recvbuf), (unsigned char*)public_key_char, encrypted);
	std::string base64_message_encode = base64_encode((char*)encrypted, strlen((char*)encrypted));
	std::cout << "encrypted: " << encrypted << std::endl;
	std::cout << "base64_message_encode: " << base64_message_encode << std::endl;
	std::cout << "encrypted_length: " << encrypted_length << std::endl;

	int decrypted_length = private_decrypt(encrypted, encrypted_length, (unsigned char*)private_key_char, decrypted);
	decrypted[decrypted_length] = '\0';
	std::cout << "decrypted: " << decrypted << std::endl;
	std::cout << "decrypted_length: " << decrypted_length << std::endl;

	// Client
	SOCKET mysocket = 0;
	char buff[200];
	mysocket = startWSA(mysocket);

	struct sockaddr_in local_addr;
	local_addr.sin_port = htons(1234);
	local_addr.sin_family = AF_INET;
	HOSTENT *hst;
	
	if (inet_addr(SERVERADDR) != INADDR_NONE)
		local_addr.sin_addr.s_addr = inet_addr(SERVERADDR);
	else
		if (hst = gethostbyname(SERVERADDR))
			((unsigned long*)&local_addr.sin_addr)[0] = ((unsigned long**)hst->h_addr_list)[0][0];
		else
		{
			std::cout << "Invalid address\n";
			closesocket(mysocket);
			WSACleanup();
			return -1;
		}
	if (connect(mysocket, (sockaddr*)&local_addr, sizeof(local_addr)))
	{
		std::cout << "Connect error\n";
		return -1;
	}

	char public_key_server_char[10 * 1024];
	int tmp_q = recv(mysocket, public_key_server_char, strlen(public_key_server_char), 0);
	public_key_server_char[tmp_q] = 0;
	std::cout << public_key_server_char << std::endl;
	send(mysocket, public_key_char, strlen(public_key_char), 0);

	int nsize = 0;
	while ((nsize = recv(mysocket, buff, strlen(buff), 0)) != SOCKET_ERROR)
	{
		//std::cout << "strlen 1: " << strlen(buff) << std::endl;
		buff[nsize] = 0;
		//std::cout << "strlen 2: " << strlen(buff) << std::endl;

		std::cout << "S=>C: " << buff << std::endl;
		std::cout << "S<=C: ";
		std::cin >> buff;

		int encrypted_length = public_encrypt((unsigned char*)buff, strlen(buff), (unsigned char*)public_key_server_char, encrypted);
		std::cout << encrypted << std::endl;

		if (!strcmp(&buff[0], "quit\n"))
		{
			std::cout << "Exit...";
			closesocket(mysocket);
			WSACleanup();
			return 0;
		}

		send(mysocket, (char*)encrypted, strlen((char*)encrypted), 0);
	}

	std::cout << "Recv error\n";
	closesocket(mysocket);
	WSACleanup();
	return -1;
}

char* generetStringPublicKey(RSA* public_key, RSA* keypair)
{
	BIO* public_bio_key = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(public_bio_key, keypair);
	size_t pub_len = BIO_pending(public_bio_key);
	char* public_key_char = (char*)malloc(pub_len + 1);
	BIO_read(public_bio_key, public_key_char, pub_len);
	public_key_char[pub_len] = '\0';
	std::cout << public_key_char << std::endl;
	return public_key_char;
}

char* generetStringPrivateKey(RSA* private_key, RSA* keypair)
{
	BIO* private_bio_key = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(private_bio_key, keypair, NULL, NULL, 0, NULL, NULL);
	size_t pri_len = BIO_pending(private_bio_key);
	char* private_key_char = (char*)malloc(pri_len + 1);
	BIO_read(private_bio_key, private_key_char, pri_len);
	private_key_char[pri_len] = '\0';
	std::cout << private_key_char << std::endl;
	return private_key_char;
}

RSA* createRSA(unsigned char* key, int public_key)
{
	RSA* rsa = NULL;
	BIO* keybio;
	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL)
	{
		printf("Failed to create key BIO");
		return 0;
	}
	if (public_key)
	{
		rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
		//rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	}
	else
	{
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}
	if (rsa == NULL)
	{
		printf("Failed to create RSA");
	}

	return rsa;
}

int public_encrypt(unsigned char* data, int data_len, unsigned char* key, unsigned char* encrypted)
{
	RSA* rsa = createRSA(key, 1);
	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}

int private_decrypt(unsigned char* enc_data, int data_len, unsigned char* key, unsigned char* decrypted)
{
	RSA* rsa = createRSA(key, 0);
	int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}

std::string base64_encode(char const* bytes_to_encode, int in_len) {
	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i < 4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';

	}

	return ret;

}

std::string base64_decode(std::string& encoded_string) {
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			char_array_4[j] = 0;

		for (j = 0; j < 4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	}

	return ret;
}

SOCKET startWSA(SOCKET mysocket)
{
	char buff[1024];
	if (WSAStartup(0x0202, (WSADATA*)&buff[0]))
	{
		std::cout << "Error wsastartup\n";
		return true;
	}

	if ((mysocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		std::cout << "Error socket\n";
		WSACleanup();
		return true;
	}
	return mysocket;
}
