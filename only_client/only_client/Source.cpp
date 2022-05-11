//#include <openssl/rsa.h>
//#include <openssl/pem.h>
//#include <openssl/bio.h>
//#include <openssl/err.h>
//#include <openssl/ssl.h>
//#include <openssl/aes.h>
//#include <openssl/rand.h>
//#include <openssl/x509.h>
//#include <stdio.h>
//#include <vector>
//#include <assert.h>
//#include <iostream>
//#include <string>
//#include <WinSock2.h>
//
//#pragma comment(lib, "Ws2_32.lib")
//#pragma comment (lib, "libcrypto.lib")
//#pragma comment (lib, "libssl.lib")
//#pragma warning(disable : 4996)
//
//char* generetStringPublicKey(RSA* public_key, RSA* keypair)
//{
//    BIO* public_bio_key = BIO_new(BIO_s_mem());
//    PEM_write_bio_RSAPublicKey(public_bio_key, keypair);
//    size_t pub_len = BIO_pending(public_bio_key);
//    char* public_key_char = (char*)malloc(pub_len + 1);
//    BIO_read(public_bio_key, public_key_char, pub_len);
//    public_key_char[pub_len] = '\0';
//    return public_key_char;
//}
//
//EVP_PKEY* open_public_key(unsigned char* pub_key_file)
//{
//    EVP_PKEY* key = NULL;
//    RSA* rsa = NULL;
//
//    OpenSSL_add_all_algorithms();
//    //BIO* bio_pub = BIO_new(BIO_s_file());
//    BIO* bio_pub = BIO_new(BIO_s_mem());;
//    BIO_read(bio_pub, pub_key_file, strlen((const char*)pub_key_file));
//    if (NULL == bio_pub)
//    {
//        printf("open_public_key bio file new error!\n");
//        return NULL;
//    }
//
//    rsa = PEM_read_bio_RSAPublicKey(bio_pub, NULL, NULL, NULL);
//    if (rsa == NULL)
//    {
//        printf("open_public_key failed to PEM_read_bio_RSAPublicKey!\n");
//        BIO_free(bio_pub);
//        RSA_free(rsa);
//
//        return NULL;
//    }
//
//    printf("open_public_key success to PEM_read_bio_RSAPublicKey!\n");
//    key = EVP_PKEY_new();
//    if (NULL == key)
//    {
//        printf("open_public_key EVP_PKEY_new failed\n");
//        RSA_free(rsa);
//
//        return NULL;
//    }
//
//    EVP_PKEY_assign_RSA(key, rsa);
//    return key;
//}
//
//EVP_PKEY* open_private_key(const char* priv_key_file, const unsigned char* passwd)
//{
//    EVP_PKEY* key = NULL;
//    RSA* rsa = RSA_new();
//    OpenSSL_add_all_algorithms();
//    BIO* bio_priv = NULL;
//    bio_priv = BIO_new_file(priv_key_file, "rb");
//    if (NULL == bio_priv)
//    {
//        printf("open_private_key bio file new error!\n");
//
//        return NULL;
//    }
//
//    rsa = PEM_read_bio_RSAPrivateKey(bio_priv, &rsa, NULL, (void*)passwd);
//    if (rsa == NULL)
//    {
//        printf("open_private_key failed to PEM_read_bio_RSAPrivateKey!\n");
//        BIO_free(bio_priv);
//        RSA_free(rsa);
//
//        return NULL;
//    }
//
//    printf("open_private_key success to PEM_read_bio_RSAPrivateKey!\n");
//    key = EVP_PKEY_new();
//    if (NULL == key)
//    {
//        printf("open_private_key EVP_PKEY_new failed\n");
//        RSA_free(rsa);
//
//        return NULL;
//    }
//
//    EVP_PKEY_assign_RSA(key, rsa);
//    return key;
//}
//
//int create_socket(int port)
//{
//    SOCKET s = 0;
//    struct sockaddr_in addr;
//
//    WSADATA wsaData;
//    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
//    {
//        printf("WSAStartup()fail:%d\n", GetLastError());
//        return -1;
//    }
//
//    addr.sin_family = AF_INET;
//    addr.sin_port = htons(port);
//    addr.sin_addr.s_addr = htonl(INADDR_ANY);
//
//    s = socket(AF_INET, SOCK_STREAM, 0);
//    if (s < 0) {
//        perror("Unable to create socket");
//        exit(EXIT_FAILURE);
//    }
//
//    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
//        perror("Unable to bind");
//        exit(EXIT_FAILURE);
//    }
//
//    if (listen(s, 1) < 0) {
//        perror("Unable to listen");
//        exit(EXIT_FAILURE);
//    }
//
//    return s;
//}
//
//SSL_CTX* create_context()
//{
//    const SSL_METHOD* method;
//    SSL_CTX* ctx;
//
//    method = TLS_server_method();
//
//    ctx = SSL_CTX_new(method);
//    if (!ctx) {
//        perror("Unable to create SSL context");
//        ERR_print_errors_fp(stderr);
//        exit(EXIT_FAILURE);
//    }
//
//    return ctx;
//}
//
//void configure_context(SSL_CTX* ctx)
//{
//    /* Set the key and cert */
//    if (SSL_CTX_use_certificate_file(ctx, "cert_test.pem", SSL_FILETYPE_PEM) <= 0) {
//        ERR_print_errors_fp(stderr);
//        exit(EXIT_FAILURE);
//    }
//
//    if (SSL_CTX_use_PrivateKey_file(ctx, "key_test.pem", SSL_FILETYPE_PEM) <= 0) {
//        ERR_print_errors_fp(stderr);
//        exit(EXIT_FAILURE);
//    }
//}
//
//std::string pem(X509* x509)
//{
//    BIO* bio_out = BIO_new(BIO_s_mem());
//    PEM_write_bio_X509(bio_out, x509);
//    BUF_MEM* bio_buf;
//    BIO_get_mem_ptr(bio_out, &bio_buf);
//    std::string pem = std::string(bio_buf->data, bio_buf->length);
//    BIO_free(bio_out);
//    return pem;
//}
//
//void createCertificate()
//{
//    EVP_PKEY* pkey;
//    pkey = EVP_PKEY_new();
//
//    RSA* rsa;
//    rsa = RSA_generate_key(
//        2048,   /* number of bits for the key - 2048 is a sensible value */
//        RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
//        NULL,   /* callback - can be NULL if we aren't displaying progress */
//        NULL    /* callback argument - not needed in this case */
//    );
//
//    EVP_PKEY_assign_RSA(pkey, rsa);
//
//    X509* x509;
//    x509 = X509_new();
//
//    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
//
//    X509_gmtime_adj(X509_get_notBefore(x509), 0);
//    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
//
//    X509_set_pubkey(x509, pkey);
//
//    auto name = X509_get_subject_name(x509);
//
//    int ret = X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
//        (unsigned char*)"CA", -1, -1, 0);
//    std::cout << ret << std::endl;
//    ret = X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
//        (unsigned char*)"MyCompany Inc.", -1, -1, 0);
//    std::cout << ret << std::endl;
//    ret = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
//        (unsigned char*)"localhost", -1, -1, 0);
//    std::cout << ret << std::endl;
//
//    ret = X509_set_issuer_name(x509, name);
//    std::cout << ret << std::endl;
//    
//    ret = X509_sign(x509, pkey, EVP_sha1());
//    std::cout << ret << std::endl;
//
//    ret = X509_verify(x509, pkey);
//    std::cout << ret << std::endl;
//
//   /* BIO* f = BIO_new(BIO_s_mem());
//    PEM_write_bio_X509(f, x509);
//    size_t pri_len = BIO_pending(f);
//    char* private_key_char = (char*)malloc(pri_len + 1);
//    BIO_read(f, private_key_char, pri_len);
//    private_key_char[pri_len] = '\0';*/
//    
//    //BIO* bio_file = NULL;
//
//    //bio_file = BIO_new_file("AAAAAAA.pem", "w");
//    //if (bio_file == NULL) {
//    //    ret = -1;
//    //}
//    //ret = PEM_write_bio_X509(bio_file, x509);
//    //if (ret != 1) {
//    //    ret = -1;
//    //}
//    //BIO_free(bio_file);
//
//
//    BIO* w = NULL;
//    w = BIO_new_file("key_test.pem", "wb");
//    PEM_write_bio_PrivateKey(
//        w,                  /* write the key to the file we've opened */
//        pkey,               /* our key from earlier */
//        NULL, /* default cipher for encrypting the key on disk */
//        NULL,       /* passphrase required for decrypting the key on disk */
//        0,                 /* length of the passphrase string */
//        NULL,               /* callback for requesting a password */
//        NULL                /* data to pass to the callback */
//    );
//    BIO_free(w);
//
//    BIO* f = NULL;
//    f = BIO_new_file("cert_test.pem", "wb");
//    PEM_write_bio_X509(
//        f,   /* write the certificate to the file we've opened */
//        x509 /* our certificate */
//    );
//    BIO_free(f);
//}
//
//int main(int argc, char** argv)
//{
//    /*RSA* rsa_pub_key = NULL;
//    RSA* keypair = RSA_new();
//    keypair = RSA_generate_key(2048, RSA_F4, NULL, NULL);
//    char* pub_key = generetStringPublicKey(rsa_pub_key, keypair);
//    EVP_PKEY* evp_pub_key = open_public_key((unsigned char*)pub_key);*/
//    //createCertificate();
//
//    int sock;
//    SSL_CTX* ctx;
//
//    ctx = create_context();
//
//    configure_context(ctx);
//
//    sock = create_socket(4433);
//
//    /* Handle connections */
//    while (1) {
//        struct sockaddr_in addr;
//        int len = sizeof(addr);
//        SSL* ssl;
//        const char reply[] = "test\n";
//
//        int client = accept(sock, (struct sockaddr*)&addr, &len);
//        if (client < 0) {
//            perror("Unable to accept");
//            exit(EXIT_FAILURE);
//        }
//
//        ssl = SSL_new(ctx);
//        SSL_set_fd(ssl, client);
//
//        if (SSL_accept(ssl) <= 0) {
//            ERR_print_errors_fp(stderr);
//        }
//        else {
//            char buf[1024];
//            int ret = SSL_write(ssl, reply, strlen(reply));
//
//            ret = SSL_read(ssl, buf, strlen(buf));
//            buf[ret] = '\0';
//            std::cout << buf << std::endl;
//
//        }
//
//        SSL_shutdown(ssl);
//        SSL_free(ssl);
//        closesocket(client);
//    }
//
//    closesocket(sock);
//    SSL_CTX_free(ctx);
//}

#include "mycrypto.h"
#include "Kuznyechik.h"

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <chrono>
#include <string>
#include <fstream>
#include <WinSock2.h>

using namespace std::chrono;

#pragma comment(lib, "Ws2_32.lib")
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "libssl.lib")
#pragma warning(disable : 4996)

SOCKET create_socket()
{
    SOCKET s = 0;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("WSAStartup()fail:%d\n", GetLastError());
        return -1;
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int ret = connect(s, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    return s;
}

string createAES() {
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));
    string key_str((char*)key);
    return key_str;
}

string createIV() {
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));
    string iv_str((char*)iv);
    return iv_str;
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

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main() {
    //ByteBlock key = hex_to_bytes(key_hex);
    //ByteBlock iv = hex_to_bytes(iv_hex);
    //ByteBlock msg = hex_to_bytes(msg_hex);


    for (int i = 0; i < 300; i++) {
        string keys = "jiadsjioasdjioqkpoqwekopeeasdkpo";
        string ivss = "mkjioadsdsddkjop";

        ByteBlock key((BYTE*)keys.c_str(), 32);
        ByteBlock iv((BYTE*)ivss.c_str(), 16);
        ByteBlock msg((BYTE*)"CLIENT CLIENT CLIENT CLIENT CLIENT", 35);

        ByteBlock enc_meg;
        ByteBlock dec_msg;

        CFB_Mode<Kuznyechik> encryptor(Kuznyechik(key), iv);
        encryptor.encrypt(msg, enc_meg);

        SOCKET mysocket = 0;
        mysocket = create_socket();

        send(mysocket, (const char*)enc_meg.byte_ptr(), enc_meg.size(), 0);

        char buf[10241];
        int ret = recv(mysocket, buf, sizeof(buf), 0);
        buf[ret - 1] = '\0';

        enc_meg.reset((BYTE*)buf, ret);
        encryptor.decrypt(enc_meg, dec_msg);
        dec_msg[dec_msg.size() - 1] = '\0';

        std::cout << "SOK: " << mysocket << std::endl;
        std::cout << "SER: " << dec_msg.byte_ptr() << std::endl;
        //closesocket(mysocket);
    }

    system("pause");

    /*for (int i = 0; i < 300; i++) {
        auto startt = steady_clock::now();

        string keyss = createAES();
        string ivss = createIV();

        ByteBlock key((BYTE*)keyss.c_str(), 32);
        ByteBlock iv((BYTE*)ivss.c_str(), 16);
        ByteBlock msg((BYTE*)"{data zasdq123pol}", 19);

        ByteBlock enc_meg;
        ByteBlock dec_msg;

        CFB_Mode<Kuznyechik> encryptor(Kuznyechik(key), iv);
        encryptor.encrypt(msg, enc_meg);
        encryptor.decrypt(enc_meg, dec_msg);
        dec_msg[dec_msg.size()] = '\0';

        auto finishh = steady_clock::now();
        auto qs = duration_cast<microseconds>(finishh - startt).count();
    }*/

    //auto t = hex_representation(dec_msg);
}

//#define CERTF "server-cert.pem" /* сертификат сервера (должен быть подписан CA) */
//#define KEYF "server-key.pem" /* Закрытый ключ сервера (рекомендуется зашифрованное хранилище) */
//#define CACERT "ca-cert.pem" /* сертификат CA */
//#define PORT 4433 /* Порт для привязки */
//
//#define CHK_NULL(x)if ((x)==NULL) exit (1)
//#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
//#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
//
//int main()
//{
//	int err;
//	int listen_sd;
//	int sd;
//	struct sockaddr_in sa_serv;
//	struct sockaddr_in sa_cli;
//
//	int client_len;
//	SSL_CTX* ctx;
//	SSL* ssl;
//	X509* client_cert;
//	char* str;
//	char buf[4096];
//	const SSL_METHOD* meth;
//
//	WSADATA wsaData;
//
//	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
//	{
//		printf("WSAStartup()fail:%dn", GetLastError());
//		return -1;
//	}
//
//	SSL_load_error_strings(); /*Подготовка к печати отладочной информации */
//
//	OpenSSL_add_ssl_algorithms(); /*инициализация */
//	meth = SSLv3_server_method(); /*Какой протокол(SSLv2 / SSLv3 / TLSv1) используется, укажите здесь*/
//
//	ctx = SSL_CTX_new(meth);
//	CHK_NULL(ctx);
//	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); /*Проверять или нет */
//
//
//	SSL_CTX_load_verify_locations(ctx, CACERT, NULL); /*Если подтверждено, поместите сертификат CA*/
//
//
//	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
//	{
//		ERR_print_errors_fp(stderr);
//		exit(3);
//	}
//
//	printf("here works in...\n");
//
//	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
//	{
//		ERR_print_errors_fp(stderr);
//		exit(4);
//	}
//
//	if (!SSL_CTX_check_private_key(ctx))
//	{
//		printf("Private key does not match the certificate public key\n");
//		exit(5);
//	}
//
//
//	SSL_CTX_set_cipher_list(ctx, "RC4-MD5");
//
//	/*Запуск обычного процесса сокета TCP */
//	printf("Begin TCP socket...\n");
//	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
//	CHK_ERR(listen_sd, "socket");
//	memset(&sa_serv, '\0', sizeof(sa_serv));
//	sa_serv.sin_family = AF_INET;
//	sa_serv.sin_addr.s_addr = INADDR_ANY;
//	sa_serv.sin_port = htons(PORT);
//	err = bind(listen_sd, (struct sockaddr*)&sa_serv, sizeof(sa_serv));
//	CHK_ERR(err, "bind");
//	/*Принять ссылку TCP */
//	err = listen(listen_sd, 5);
//	CHK_ERR(err, "listen");
//	client_len = sizeof(sa_cli);
//
//	sd = accept(listen_sd, (struct sockaddr*)&sa_cli, &client_len);
//
//	CHK_ERR(sd, "accept");
//	closesocket(listen_sd);
//	printf("Connection from %lx, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);
//	/*TCP - соединение установлено, и SSL - процесс сервера выполняется. */
//	printf("Begin server side SSL\n");
//	ssl = SSL_new(ctx);
//	CHK_NULL(ssl);
//	SSL_set_fd(ssl, sd);
//	err = SSL_accept(ssl);
//	std::cout << SSL_get_error(ssl, err) << std::endl;
//	printf("SSL_accept finished\n");
//	CHK_SSL(err);
//
//	/*Распечатать всю информацию об алгоритме шифрования(необязательно) */
//	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
//	/*Получить сертификат сервера и распечатать некоторую информацию(необязательно) */
//		client_cert = SSL_get_peer_certificate(ssl);
//	if (client_cert != NULL)
//	{
//		printf("Client certificate:\n");
//		str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
//		CHK_NULL(str);
//		printf("\t subject: %s\n", str);
//		//free (str);
//		str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
//		CHK_NULL(str);
//		printf("\t issuer: %s\n", str);
//
//		//free (str);
//		X509_free(client_cert); /*Если он вам больше не нужен, вам нужно выпустить сертификат*/
//	}
//	else
//		printf("Client does not have certificate.\n");
//
//	/*Начнется обмен данными, используйте SSL_write, SSL_read вместо записи, чтение*/
//	do {
//		err = SSL_read(ssl, buf, sizeof(buf) - 1);
//		CHK_SSL(err);  buf[err] = '\0';
//		printf("client:'%s'\n", buf);
//		printf("server:");  
//		std::cin >> buf;
//		err = SSL_write(ssl, buf, strlen(buf));
//		CHK_SSL(err);
//	} while (strcmp(buf, "bye"));
//
//	/*Завершающие работы */
//	shutdown(sd, 2);
//	SSL_free(ssl);
//	SSL_CTX_free(ctx);
//	system("pause");
//	return 0;
//}