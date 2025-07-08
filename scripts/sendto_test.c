#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dest;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(9090);
    inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

    for (int i = 0; i < 50; i++) {
        sendto(sock, "hello", 5, 0, (struct sockaddr *)&dest, sizeof(dest));
    }

    close(sock);
    return 0;
}
