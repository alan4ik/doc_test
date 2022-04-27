#pragma once
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

#include <limits>
#include <iostream>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "libssl.lib")
#pragma warning(disable : 4996)

using namespace std;

int padding = RSA_PKCS1_PADDING;

SOCKET create_socket(int port)
{
    SOCKET s = 0;
    struct sockaddr_in addr;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("WSAStartup()fail:%d\n", GetLastError());
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 10) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

RSA* createRSA(unsigned char* key, int public_t)
{
    RSA* rsa = NULL;
    BIO* keybio;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
    {
        printf("Failed to create key BIO");
        return 0;
    }
    if (public_t)
    {
        rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }

    return rsa;
}

//int public_encrypt(unsigned char* data, int data_len, unsigned char* key, unsigned char* encrypted)
//{
//    RSA* rsa = createRSA(key, 1);
//    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
//    return result;
//}

int private_decrypt(unsigned char* enc_data, int data_len, unsigned char* key, unsigned char* decrypted)
{
    RSA* rsa = createRSA(key, 0);
    int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

RSA* generate_keypair() {
    BIGNUM* bne = nullptr;
    bne = BN_new();
    int ret = BN_set_word(bne, RSA_F4);
    if (ret != 1) {
        BN_free(bne);
        return nullptr;
    }

    RSA* keypair = nullptr;
    keypair = RSA_new();
    ret = RSA_generate_key_ex(keypair, 1024, bne, nullptr);
    if (ret != 1) {
        RSA_free(keypair);
        return nullptr;
    }
    BN_free(bne);
    return keypair;
}

char* generate_rsa_public_key(RSA* keypair, size_t& pub_len) {
    BIO* bp_public = nullptr;
    bp_public = BIO_new(BIO_s_mem());
    int ret = PEM_write_bio_RSAPublicKey(bp_public, keypair);
    if (ret != 1) {
        return nullptr;
    }

    pub_len = BIO_pending(bp_public);
    char* pub_key = (char*)malloc(pub_len + 1);
    BIO_read(bp_public, pub_key, pub_len);
    if (pub_key != nullptr)
        pub_key[pub_len] = '\0';

    BIO_free_all(bp_public);

    return pub_key;
}

char* generate_rsa_private_key(RSA* keypair, size_t& pri_len) {
    BIO* bp_private = nullptr;
    bp_private = BIO_new(BIO_s_mem());
    int ret = PEM_write_bio_RSAPrivateKey(bp_private, keypair, nullptr, nullptr, 0, nullptr, nullptr);
    if (ret != 1) {
        return nullptr;
    }

    pri_len = BIO_pending(bp_private);
    char* pri_key = (char*)malloc(pri_len + 1);
    BIO_read(bp_private, pri_key, pri_len);
    if (pri_key != nullptr)
        pri_key[pri_len] = '\0';

    BIO_free_all(bp_private);

    return pri_key;
}

EVP_PKEY* convert_rsa_public_key_to_evp_pkey(void* pub_key, size_t pub_len) {
    BIO* pbkeybio = nullptr;
    pbkeybio = BIO_new_mem_buf((void*)pub_key, pub_len);
    if (pbkeybio == nullptr) {
        return nullptr;
    }
    RSA* pb_rsa = nullptr;
    pb_rsa = PEM_read_bio_RSAPublicKey(pbkeybio, &pb_rsa, nullptr, nullptr);
    if (pb_rsa == nullptr) {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        printf("Error reading public key:%s\n", buffer);
    }
    EVP_PKEY* evp_pbkey = nullptr;
    evp_pbkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_pbkey, pb_rsa);
    BIO_free(pbkeybio);
    RSA_free(pb_rsa);
    return evp_pbkey;
}

EVP_PKEY* convert_rsa_private_key_to_evp_pkey(void* pri_key, size_t pri_len) {
    BIO* pkeybio = nullptr;
    pkeybio = BIO_new_mem_buf((void*)pri_key, pri_len);
    if (pkeybio == nullptr) {
        return nullptr;
    }

    RSA* p_rsa = nullptr;
    p_rsa = PEM_read_bio_RSAPrivateKey(pkeybio, &p_rsa, nullptr, nullptr);
    if (p_rsa == nullptr) {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        printf("Error reading private key:%s\n", buffer);
    }
    EVP_PKEY* evp_pkey = nullptr;
    evp_pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_pkey, p_rsa);
    BIO_free(pkeybio);
    RSA_free(p_rsa);
    return evp_pkey;
}

bool generate_key() {
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char* pri_key;           // Private key in PEM
    char* pub_key;           // Public key in PEM

    int ret = 0;
    RSA* r = NULL;
    BIGNUM* bne = NULL;
    BIO* bp_public = NULL, * bp_private = NULL;
    int bits = 1024;
    unsigned long e = RSA_F4;

    RSA* pb_rsa = NULL;
    RSA* p_rsa = NULL;
    EVP_PKEY* evp_pbkey = NULL;
    EVP_PKEY* evp_pkey = NULL;

    BIO* pbkeybio = NULL;
    BIO* pkeybio = NULL;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if (ret != 1) {
        goto free_all;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, nullptr);
    if (ret != 1) {
        goto free_all;
    }

    // 2. save public key
    bp_public = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if (ret != 1) {
        goto free_all;
    }

    // 3. save private key
    bp_private = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, nullptr, nullptr, 0, nullptr, nullptr);

    //4. Get the keys are PEM formatted strings
    pri_len = BIO_pending(bp_private);
    pub_len = BIO_pending(bp_public);

    pri_key = (char*)malloc(pri_len + 1);
    pub_key = (char*)malloc(pub_len + 1);

    BIO_read(bp_private, pri_key, pri_len);
    BIO_read(bp_public, pub_key, pub_len);

    if (pri_key != nullptr)
        pri_key[pri_len] = '\0';
    if (pub_key != nullptr)
        pub_key[pub_len] = '\0';

    printf("\n%s\n%s\n", pri_key, pub_key);

    //verify if you are able to re-construct the keys
    pbkeybio = BIO_new_mem_buf((void*)pub_key, pub_len);
    if (pbkeybio == nullptr) {
        return false;
    }
    pb_rsa = PEM_read_bio_RSAPublicKey(pbkeybio, &pb_rsa, nullptr, nullptr);
    if (pb_rsa == nullptr) {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        printf("Error reading public key:%s\n", buffer);
    }
    evp_pbkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_pbkey, pb_rsa);

    pkeybio = BIO_new_mem_buf((void*)pri_key, pri_len);
    if (pkeybio == nullptr) {
        return false;
    }

    p_rsa = PEM_read_bio_RSAPrivateKey(pkeybio, &p_rsa, nullptr, nullptr);
    if (p_rsa == nullptr) {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        printf("Error reading private key:%s\n", buffer);
    }
    evp_pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_pkey, p_rsa);

    BIO_free(pbkeybio);
    BIO_free(pkeybio);

    // 4. free
free_all:

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    RSA_free(pb_rsa);
    RSA_free(p_rsa);
    BN_free(bne);

    return (ret == 1);
}

class ByteArray {
    uint8_t* byte_array = nullptr;
    uint64_t _length = 0;
public:
    typedef uint8_t* iterator;

    ByteArray() = default;

    ByteArray(uint64_t length)
        : byte_array(new uint8_t[length]), _length(length) {}

    ByteArray(void* buffer, uint64_t length)
        : byte_array(new uint8_t[length]),
        _length(length) {
        memcpy(byte_array, buffer, _length);
    }

    ByteArray(ByteArray& other)
        : byte_array(new uint8_t[other._length]),
        _length(other._length) {
        memcpy(byte_array, other.byte_array, _length);
    }

    ByteArray(ByteArray&& other)
        : byte_array(other.byte_array),
        _length(other._length) {
        other.byte_array = nullptr;
    }

    ~ByteArray() { if (byte_array) delete[] byte_array; }

    void resize(uint64_t new_length) {
        _length = new_length;
        byte_array = (uint8_t*)realloc(byte_array, _length);
    }

    iterator addSize(uint64_t add) {
        byte_array = (uint8_t*)realloc(byte_array, _length + add);
        iterator it = byte_array + _length;
        _length += add;
        memset(it, 0, add);
        return it;
    }

    inline uint64_t length() { return _length; }

    inline uint8_t& operator[](uint64_t index) { return byte_array[index]; }

    inline ByteArray& operator=(ByteArray other) {
        if (this == &other)
            return *this;
        _length = other._length;
        byte_array = other.byte_array;
        other.byte_array = nullptr;
        return *this;
    }

    inline iterator begin() { return byte_array; }
    inline iterator end() { return byte_array + _length; }

};

struct RSA_t {
    uint8_t* rsa_key = NULL;
    size_t rsa_len = 0;

    bool isEmpty() const {
        static const RSA_t empty_rsa;
        return !memcmp(this, &empty_rsa, sizeof(RSA_t));
    }

    void clear() 
    { 
        *this = RSA_t(); 
    }
    RSA_t() = default;
    RSA_t(ByteArray data) {
        *this = *reinterpret_cast<RSA_t*>(data.begin());
    }
};

void handleErrors() {
    ERR_print_errors_fp(stderr);
    throw std::runtime_error("Security error");
}


ByteArray encrypt(ByteArray plaint_text, ByteArray pub_key)
{
    unsigned char encrypt[10241];
    RSA* rsa = createRSA(pub_key.begin(), 1);
    int result = RSA_public_encrypt((int)plaint_text.length(), plaint_text.begin(), encrypt, rsa, padding);
    encrypt[result] = '\0';

    ByteArray ciphertext(encrypt, result);
    return ciphertext;
}

ByteArray decrypt(ByteArray plaint_text, ByteArray pri_key)
{
    unsigned char decrypt[10241];
    RSA* rsa = createRSA(pri_key.begin(), 0);
    int result = RSA_private_decrypt((int)plaint_text.length(), plaint_text.begin(), decrypt, rsa, padding);
    decrypt[result] = '\0';

    ByteArray plain_text(decrypt, result);
    return plain_text;
}