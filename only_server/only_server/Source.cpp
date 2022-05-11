//#include <openssl/rsa.h>
//#include <openssl/pem.h>
//#include <openssl/err.h>
//#include <openssl/bio.h>
//#include <openssl/ssl.h>
//#include <openssl/rand.h>
//#include <iostream>
//#include <assert.h>
//#include <string>
//#include <sstream>
//#include <WinSock2.h>
//
//#pragma comment(lib, "Ws2_32.lib")
//#pragma comment (lib, "libcrypto.lib")
//#pragma comment (lib, "libssl.lib")
//#pragma warning(disable : 4996)
//
//class MyClass
//{
//public:
//    MyClass() {}
//    int test() {
//        return key;
//    }
//    ~MyClass() {}
//
//private:
//    int key = 0;
//};
//
//extern MyClass clas;
//
//int create_socket(int port)
//{
//    SOCKET s = 0;
//    //struct sockaddr_in addr;
//
//    WSADATA wsaData;
//    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
//    {
//        printf("WSAStartup()fail:%d\n", GetLastError());
//        return -1;
//    }
//
//    /*addr.sin_family = AF_INET;
//    addr.sin_port = htons(port);
//    addr.sin_addr.s_addr = htonl(INADDR_ANY);*/
//
//    s = socket(AF_INET, SOCK_STREAM, 0);
//    if (s < 0) {
//        perror("Unable to create socket");
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
//    method = TLS_client_method();
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
//    /* BIO* f = BIO_new(BIO_s_mem());
//     PEM_write_bio_X509(f, x509);
//     size_t pri_len = BIO_pending(f);
//     char* private_key_char = (char*)malloc(pri_len + 1);
//     BIO_read(f, private_key_char, pri_len);
//     private_key_char[pri_len] = '\0';*/
//
//     //BIO* bio_file = NULL;
//
//     //bio_file = BIO_new_file("AAAAAAA.pem", "w");
//     //if (bio_file == NULL) {
//     //    ret = -1;
//     //}
//     //ret = PEM_write_bio_X509(bio_file, x509);
//     //if (ret != 1) {
//     //    ret = -1;
//     //}
//     //BIO_free(bio_file);
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
//    //createCertificate();
//    int sock;
//    SSL_CTX* ctx;
//
//    ctx = create_context();
//
//    configure_context(ctx);
//
//    sock = create_socket(4433);
//
//    struct sockaddr_in addr;
//    addr.sin_family = AF_INET;
//    addr.sin_port = htons(4433);
//    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
//
//    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
//    if (ret < 0) {
//        perror("Unable to connect");
//        exit(EXIT_FAILURE);
//    }
//    
//    SSL* ssl;
//    ssl = SSL_new(ctx);
//    SSL_set_fd(ssl, sock);
//
//    if (SSL_connect(ssl) <= 0) {
//        ERR_print_errors_fp(stderr);
//    }
//    else {
//        char buf[1024];
//        ret = SSL_read(ssl, buf, strlen(buf));
//        buf[ret] = '\0';
//
//        std::cout << buf << std::endl;
//
//        SSL_write(ssl, "test2", strlen("test2"));
//    }
//}


//#define CERTF "client-cert.pem" /* Сертификат клиента (должен быть подписан CA) */
//#define KEYF "client-key.pem" /* Закрытый ключ клиента (рекомендуется зашифрованное хранилище) */
//#define CACERT "ca-cert.pem" /* сертификат CA */
//#define PORT 4433 /* Порт сервера */
//#define SERVER_ADDR "127.0.1.1" /* IP-адрес сервисного сегмента */
//#define CHK_NULL(x) if ((x)==NULL) exit (-1)
//#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(-2); }
//#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(-3); }
//
//int main()
//{
//	int err;
//	int sd;
//	struct sockaddr_in sa;
//	SSL_CTX* ctx;
//	SSL* ssl;
//	X509* server_cert;
//
//	char* str;
//	char buf[4096];
//	const SSL_METHOD* meth;
//	int seed_int[100]; /* Сохраняем случайную последовательность */
//		WSADATA wsaData;
//
//	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
//	{
//		printf("WSAStartup()fail:%d\n", GetLastError());
//		return -1;
//	}
//
//	OpenSSL_add_ssl_algorithms(); /* инициализация */
//	SSL_load_error_strings(); /* Подготовка к печати отладочной информации */
//	meth = SSLv3_client_method(); /* Какой протокол(SSLv2 / SSLv3 / TLSv1) используется, укажите здесь */
//	ctx = SSL_CTX_new(meth);
//	CHK_NULL(ctx);
//	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); /* Проверять или нет */
//	SSL_CTX_load_verify_locations(ctx, CACERT, NULL); /* Если подтверждено, поместите сертификат CA */
//	
//	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
//	{
//		ERR_print_errors_fp(stderr);
//		exit(-2);
//	}
//
//	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
//	{
//		ERR_print_errors_fp(stderr);
//		exit(-3);
//	}
//
//	if (!SSL_CTX_check_private_key(ctx))
//	{
//		printf("Private key does not match the certificate public key\n");
//		exit(-4);
//	}
//
//	/*Создаем механизм генерации случайных чисел, необходимый для платформы WIN32*/
//
//	srand((unsigned)time(NULL));
//
//	for (int i = 0; i < 100; i++)
//		seed_int[i] = rand();
//
//	RAND_seed(seed_int, sizeof(seed_int));
//
//
//	/* Далее следует обычный процесс установления сокета TCP */
//	printf("Begin tcp socket...\n");
//	sd = socket(AF_INET, SOCK_STREAM, 0);
//	CHK_ERR(sd, "socket");
//	memset(&sa, '\0', sizeof(sa));
//	sa.sin_family = AF_INET;
//	sa.sin_addr.s_addr = inet_addr(SERVER_ADDR);/* Server IP */
//	sa.sin_port = htons(PORT);/* Server Port number */
//	err = connect(sd, (struct sockaddr*)&sa, sizeof(sa));
//	CHK_ERR(err, "connect");
//
//	/*TCP - соединение установлено.Запустить процесс подтверждения SSL */
//	printf("Begin SSL negotiation \n");
//
//	ssl = SSL_new(ctx);
//	CHK_NULL(ssl);
//
//	SSL_set_fd(ssl, sd);
//	err = SSL_connect(ssl);
//	CHK_SSL(err);
//
//	/* Распечатать информацию обо всех алгоритмах шифрования(необязательно) */
//	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
//
//	/* Получить сертификат сервера и распечатать некоторую информацию(необязательно) */
//	server_cert = SSL_get_peer_certificate(ssl);
//	CHK_NULL(server_cert);
//	printf("Server certificate:\n");
//
//	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
//	CHK_NULL(str);
//	printf("\t subject: %s\n", str);
//	//free (str);
//
//	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
//	CHK_NULL(str);
//	printf("\t issuer: %s\n", str);
//	//free (str);
//
//	X509_free(server_cert); /* Если больше не нужен, сертификат необходимо выпустить */
//
//	/* Начать обмен данными, использовать SSL_write, SSL_read вместо записи, читать*/
//	printf("Begin SSL data exchange\n");
//	do {
//		printf("client:");
//		std::cin >> buf;
//		err = SSL_write(ssl, buf, strlen(buf));
//
//		CHK_SSL(err);
//		{
//			char* presult = NULL;
//			unsigned long nresult = 0;
//			err = SSL_read(ssl, buf, 4095);
//
//			buf[err] = '\0';
//			printf("server:'%s'\n", buf);
//			nresult = atoi(buf);
//
//			if ((err == 4095) && (nresult > 0))
//			{
//				presult = (char*)malloc(nresult + 1);
//				err = SSL_read(ssl, presult, nresult);
//				if (err == nresult)
//				{
//					presult[nresult] = '\0';
//				}
//				//CHK_SSL(err);
//				printf("server:'%s'\n", presult);
//				free(presult);
//			}
//			// SSL_write(ssl, "1", 1);
//		}
//	} while (strcmp(buf, "bye"));
//
//	SSL_shutdown(ssl);
//	/* send SSL/TLS close_notify */
//
//	/* Завершающие работы */
//	shutdown(sd, 2);
//	SSL_free(ssl);
//	SSL_CTX_free(ctx);
//	system("pause");
//	return 0;
//}

#include "mycrypto.h"
#include "Kuznyechik.h"

#include <chrono>
#include <string>
#include <WinSock2.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable : 4996)

using namespace std::chrono;

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

int main() {

    string keys = "jiadsjioasdjioqkpoqwekopeeasdkpo";
    string ivss = "mkjioadsdsddkjop";

    ByteBlock key((BYTE*)keys.c_str(), 32);
    ByteBlock iv((BYTE*)ivss.c_str(), 16);
    ByteBlock msg((BYTE*)"SERVER SERVER SERVER SERVER SERVER", 35);

    ByteBlock dec_msg;

    CFB_Mode<Kuznyechik> encryptor(Kuznyechik(key), iv);

    SOCKET mysocket = 0;
    mysocket = create_socket(4433);
    struct sockaddr_in addr;
    int len = sizeof(addr);
    for (int i = 0; i < 300; i++) {
        SOCKET client = accept(mysocket, (struct sockaddr*)&addr, &len);

        char buf[10241];
        int ret = recv(client, buf, sizeof(buf), 0);
        buf[ret - 1] = '\0';

        ByteBlock enc_meg((BYTE*)buf, ret);

        encryptor.decrypt(enc_meg, dec_msg);
        dec_msg[dec_msg.size() - 1] = '\0';

        std::cout << "SOK: " << client << std::endl;
        std::cout << "CLI: " << dec_msg.byte_ptr() << std::endl;

        encryptor.encrypt(msg, enc_meg);
        send(client, (const char*)enc_meg.byte_ptr(), enc_meg.size(), 0);
        //closesocket(client);
    }
}