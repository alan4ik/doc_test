#include "security.h"
#include <iostream>

int main(int argc, char* argv[]) {

    SOCKET mysocket = 0;
    mysocket = create_socket(4433);
    struct sockaddr_in addr;
    int len = sizeof(addr);

    for (int i = 0; i < 300; i++) {
        SOCKET client = accept(mysocket, (struct sockaddr*)&addr, &len);

        using namespace security;
        EVP_PKEY* server_key_pair = genKey();
        ByteArray server_peer_key = extractPublicKey(server_key_pair);

        char buf[10241];
        int ret = recv(client, buf, sizeof(buf), 0);
        buf[ret - 1] = '\0';
        ByteArray client_peer_key(buf, ret);

        ret = send(client, (const char*)server_peer_key.begin(), server_peer_key.length(), 0);

        std::cout << "Step: " << i << std::endl;

    }

    using namespace security;
    EVP_PKEY* alice_key_pair = genKey();
    ByteArray alice_peer_key = extractPublicKey(alice_key_pair);

    EVP_PKEY* bob_key_pair = genKey();
    ByteArray bob_peer_key = extractPublicKey(bob_key_pair);

    AES_t bob_aes_key = getSecret(alice_peer_key, bob_key_pair);

    AES_t alice_aes_key = getSecret(bob_peer_key, alice_key_pair);

    std::string alice_msg = "Hello, Bob";
    ByteArray alice_msg_buffer((void*)alice_msg.data(), alice_msg.length() + 1);
    ByteArray alice_enc_msg = encrypt(alice_msg_buffer, alice_aes_key);

    std::string bob_msg = "Hello, Alice";
    ByteArray bob_msg_buffer((void*)bob_msg.data(), bob_msg.length() + 1);
    ByteArray bob_enc_msg = encrypt(bob_msg_buffer, bob_aes_key);

    ByteArray alice_recived_msg = decrypt(bob_enc_msg, alice_aes_key);
    std::cout << "Bob: " << (char*)alice_recived_msg.begin() << '\n';

    ByteArray bob_recived_msg = decrypt(alice_enc_msg, bob_aes_key);
    std::cout << "Alice: " << (char*)bob_recived_msg.begin() << '\n';

    return 0;
}