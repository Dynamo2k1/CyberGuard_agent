// network_scanner.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "network_scanner.h"

#pragma comment(lib, "Ws2_32.lib")

// Function to get the local IP address
char* GetLocalIPAddress() {
    WSADATA wsaData;
    char* ipAddress = malloc(INET_ADDRSTRLEN);
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return NULL;
    }

    char hostName[256];
    if (gethostname(hostName, sizeof(hostName)) == SOCKET_ERROR) {
        fprintf(stderr, "gethostname failed: %d\n", WSAGetLastError());
        WSACleanup();
        return NULL;
    }

    struct addrinfo hints = { 0 }, * info;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(hostName, NULL, &hints, &info) != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", WSAGetLastError());
        WSACleanup();
        return NULL;
    }

    struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)info->ai_addr;
    inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ipAddress, INET_ADDRSTRLEN);

    freeaddrinfo(info);
    WSACleanup();

    return ipAddress;
}

// Function to grab banner from a port
char* GrabBanner(SOCKET socket) {
    static char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    recv(socket, buffer, sizeof(buffer) - 1, 0);
    return buffer;
}

// Function to scan a range of ports on the local IP
void ScanNetwork(int startPort, int endPort) {
    char* targetIP = GetLocalIPAddress();
    if (targetIP == NULL) {
        printf("Failed to get local IP address.\n");
        return;
    }

    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    int port;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        free(targetIP);
        return;
    }

    for (port = startPort; port <= endPort; port++) {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
            continue;
        }

        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        if (inet_pton(AF_INET, targetIP, &server.sin_addr) <= 0) {
            fprintf(stderr, "Invalid address/ Address not supported\n");
            closesocket(sock);
            continue;
        }

        // Set socket timeout
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
            printf("Port %d is open\n", port);

            // Grab the banner
            char* banner = GrabBanner(sock);
            printf("Banner: %s\n", banner);

            // Optionally send the banner info to Elasticsearch
            // SendBannerToElastic(targetIP, port, banner);

            // Check if the banner indicates a vulnerability
            // CheckBannerVulnerability(banner);
        }
        else {
            printf("Port %d is closed\n", port);
        }

        closesocket(sock);
    }

    WSACleanup();
    free(targetIP); // Free allocated memory
}
