#include "Header.h"

int main()
{
    SOCKET mysocket = 0;
    mysocket = create_socket();

    RSA* keypair = generate_keypair();
    size_t pub_len, pri_len = 0;
    char* pub_key = generate_rsa_public_key(keypair, pub_len);
    char* pri_key = generate_rsa_private_key(keypair, pri_len);

    ByteArray rsa_pub_key(pub_key, pub_len);
    rsa_pub_key[pub_len] = '\0';
    ByteArray rsa_pri_key(pri_key, pri_len);
    rsa_pri_key[pri_len] = '\0';

    char buf[10241];
    int ret = recv(mysocket, buf, sizeof(buf), 0);
    if (buf != nullptr)
        buf[ret - 1] = '\0';
    else
        return -1;
    ret = send(mysocket, (const char*)rsa_pub_key.begin(), (int)rsa_pub_key.length(), 0);

    ByteArray rsa_server_pub_key(buf, ret);
    rsa_server_pub_key[ret] = '\0';
    
    memset(buf, 0, sizeof(buf));
    ret = recv(mysocket, buf, sizeof(buf), 0);
    if (buf != nullptr)
        buf[ret - 1] = '\0';
    else
        return -1;
    ByteArray key_enc_msg(buf, ret);
    ByteArray key_dec_msg = decrypt(key_enc_msg, rsa_pri_key);

    cout << (char*)key_dec_msg.begin() << endl;

    /*RSA* keypair = generate_keypair();
    size_t pub_len = 0;
    char* pub_key = generate_rsa_public_key(keypair, pub_len);
    EVP_PKEY* evp_pub_key = convert_rsa_public_key_to_evp_pkey(pub_key, pub_len);

    size_t pri_len = 0;
    char* pri_key = generate_rsa_private_key(keypair, pri_len);
    EVP_PKEY* evp_pri_key = convert_rsa_private_key_to_evp_pkey(pri_key, pri_len);

    ByteArray rsa_pub_key(pub_key, pub_len);
    ByteArray rsa_pri_key(pri_key, pri_len);

    string str = "test message";
    
    ByteArray msg((void*)str.data(), str.length() + 1);
    ByteArray msg_enc = encrypt(msg, rsa_pub_key);

    ByteArray msg_dec = decrypt(msg_enc, rsa_pri_key);*/
    system("pause");
    return 0;
}