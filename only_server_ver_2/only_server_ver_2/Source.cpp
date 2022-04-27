#include "Header.h"

int main(int argc, char** argv)
{
    SOCKET mysocket = 0;
    mysocket = create_socket(8080);
    struct sockaddr_in addr;
    int len = sizeof(addr);
    SOCKET client = accept(mysocket, (struct sockaddr*)&addr, &len);

    RSA* keypair = generate_keypair();
    size_t pub_len, pri_len = 0;
    char* pub_key = generate_rsa_public_key(keypair, pub_len);
    char* pri_key = generate_rsa_private_key(keypair, pri_len);

    ByteArray rsa_pub_key(pub_key, pub_len);
    rsa_pub_key[pub_len] = '\0';
    ByteArray rsa_pri_key(pri_key, pri_len);
    rsa_pri_key[pri_len] = '\0';

    int ret = send(client, (const char*)rsa_pub_key.begin(), (int)rsa_pub_key.length(), 0);
    char buf[10241];
    ret = recv(client, buf, sizeof(buf), 0);
    if (buf != nullptr)
        buf[ret - 1] = '\0';
    else
        return -1;

    ByteArray rsa_client_pub_key(buf, ret);
    rsa_client_pub_key[ret] = '\0';

    unsigned char key[32];
    unsigned char iv[16];
    int key_len = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha384(), nullptr, rsa_pri_key.begin(), rsa_pri_key.length(), 5, key, iv);

    ByteArray key_msg(key, key_len);
    ByteArray iv_msg(iv, 16);

    cout << (char*)key_msg.begin() << endl;

    ByteArray key_enc_msg = encrypt(key_msg, rsa_client_pub_key);
    ByteArray iv_enc_msg = encrypt(iv_msg, rsa_client_pub_key);

    ret = send(client, (const char*)key_enc_msg.begin(), key_enc_msg.length(), 0);
    memset(buf, 0, sizeof(buf));
    ret = recv(client, buf, sizeof(buf), 0);
    buf[ret - 1] = '\0';


    system("pause");
    return 0;
}