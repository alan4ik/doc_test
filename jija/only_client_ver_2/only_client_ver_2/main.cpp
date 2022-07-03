#include <iostream>
#include <WinSock2.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable : 4996)

int main()
{
    //HWND hWnd = GetConsoleWindow();
    //ShowWindow(hWnd, SW_HIDE);

    SOCKET mysocket = 0;
    struct sockaddr_in addr;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("WSAStartup()fail:%d\n", GetLastError());
        return -1;
    }

    mysocket = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433); // или любой другой порт...
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    //int ret = connect(mysocket, (struct sockaddr*)&addr, sizeof(addr));

    char msg[256] = "CLIENTCLIENTCLCLIECLIENTCLIENTNTCLIENTCLIENTICLIENTCLIENTCLIENTENTCIENTCLIENTCLIENTCLIENTCLIENTCLIENT";

    for (int i = 0; i < 300; i++) {

        int ret = connect(mysocket, (struct sockaddr*)&addr, sizeof(addr));
        ret = send(mysocket, msg, sizeof(msg), 0);

        char buf[256];
        ret = recv(mysocket, buf, sizeof(buf), 0);
        buf[ret - 1] = '\0';
        //std::cout << "buf: " << buf << std::endl;
        std::cout << "Step " << i << std::endl;
        Sleep(500);
    }
    return 0;
}