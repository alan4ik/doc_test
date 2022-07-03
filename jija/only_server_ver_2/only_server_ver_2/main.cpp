#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include <vector>
#include <fstream>

#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable : 4996)

SOCKET create_socket(int port);

int main()
{
    //std::ofstream out("out.txt");
    //std::ofstream outs("outs.txt");

    //HWND hWnd = GetConsoleWindow();
    //ShowWindow(hWnd, SW_HIDE);

    SOCKET mysocket = 0;
    mysocket = create_socket(4433);
    struct sockaddr_in addr;
    int len = sizeof(addr);
    std::vector<WSAPOLLFD> fds;

    WSAPOLLFD listeningSocketFD = {};
    listeningSocketFD.fd = mysocket;
    listeningSocketFD.events = POLLRDNORM;
    listeningSocketFD.revents = 0;

    fds.push_back(listeningSocketFD);

    while (true)
    {
        if (WSAPoll(fds.data(), fds.size(), 1) > 0) {
            WSAPOLLFD& listeningSocketFD = fds[0];
            if (listeningSocketFD.revents & POLLRDNORM) {
                SOCKET sock_client = accept(mysocket, nullptr, nullptr);

                WSAPOLLFD newCoonectionFD = {};
                newCoonectionFD.fd = sock_client;
                newCoonectionFD.events = POLLRDNORM;
                newCoonectionFD.revents = 0;

                fds.push_back(newCoonectionFD);
            }
        }
        std::cout << "cliet: " << fds.size() << std::endl;
        for (int i = 1; i < fds.size(); i++) {
            if (fds[i].revents & POLLNVAL) {
                std::cerr << "Failed socket." << std::endl;
                fds.erase(fds.begin() + i);
                i += 1;
                continue;
            }
            if (fds[i].revents & POLLHUP) { // ≈сли на этом сокете произошло зависание опроса
                std::cerr << "Failed socket POLLHUB." << std::endl;
                fds.erase(fds.begin() + i);
                i += 1;
                continue;
            }
            if (fds[i].revents & POLLNVAL) { // ≈сли недопустимый сокет
                std::cerr << "Failed socket POLLNVAL." << std::endl;
                fds.erase(fds.begin() + i);
                i += 1;
                continue;
            }
            if (fds[i].revents & POLLRDNORM) {
                char buf[256];
                int ret = recv(fds[i].fd, buf, sizeof(buf), 0);
                if (ret < 0) {
                    closesocket(fds[i].fd);
                    fds.erase(fds.begin() + i);
                    continue;
                }
                buf[ret - 1] = '\0';

                char msg[256] = "serverserverserverserverserverserverserversererserverserverserverserverserverserverserverserverserverserverserver";
                ret = send(fds[i].fd, msg, sizeof(msg), 0);
                if (ret < 0) {
                    closesocket(fds[i].fd);
                    fds.erase(fds.begin() + i);
                    continue;
                }
            }
        }


        //int res = WSAPoll(fds.data(), fds.size(), 100);
        //if (res < 0)
        //    break;
        //if (!res)
        //    continue;
        //if (fds[0].revents == POLLRDNORM) {
        //    SOCKET client = accept(mysocket, nullptr, nullptr);
        //    fds.push_back({client, POLLIN, 0});
        //    std::cout << "fds size: " << fds.size() << std::endl;
        //    //out << "Client: " << accept_client << std::endl;
        //    accept_client += 1;
        //}
        //
        //for (int i = 1; res > 0 & i < fds.size();) {
        //    if (fds[i].revents == 0) {
        //        ++i;
        //        continue;
        //    }
        //    if (fds[i].revents != POLLRDNORM) {
        //        closesocket(fds[i].fd);
        //        fds.erase(fds.begin() + i);
        //        //outs << "Client: " << finish_client << std::endl;
        //        finish_client += 1;
        //    }
        //    else {
        //        char buf[256];
        //        int ret = recv(fds[i].fd, buf, sizeof(buf), 0);
        //        if (ret < 0) {
        //            closesocket(fds[i].fd);
        //            fds.erase(fds.begin() + i);
        //            continue;
        //        }
        //        buf[ret - 1] = '\0';
        //
        //
        //        char msg[256] = "SERVERSERVERSERVERSERVERSERVERSERVERSERVERSERERSERVERSERVERSERVERSERVERSERVERSERVERSERVERSERVERSERVERSERVERSERVER";
        //        ret = send(fds[i].fd, msg, sizeof(msg), 0);
        //        if (ret < 0) {
        //            closesocket(fds[i].fd);
        //            fds.erase(fds.begin() + i);
        //            continue;
        //        }
        //        ++i;
        //    }
        //}
    }


    


}

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