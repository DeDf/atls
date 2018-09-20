
#include "server_test.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"crypt32.lib")

typedef int socklen_t;

unsigned char buf[1024];
unsigned short port = 44444;
#define replay "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 23\r\nServer: mrpre\r\n\r\nWelcome to mrpre's Home"

int main(int argc, char* argv[])
{
    struct sockaddr_in server_addr;
    int listen_fd, opt;
    a_tls_cfg_t *cfg;
    a_tls_t *tls;
    struct timeval timeout={3,0};//3s
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Ì×½Ó×Ö³õÊ¼»¯Ê§°Ü!\n");
		exit(-1);
	}

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htons(INADDR_ANY);
    server_addr.sin_port = htons(port);

    listen_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("create socket error");
        exit(-1);
    }

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    printf("Bind local port:%d\n", port);
    if( bind(listen_fd, (struct sockaddr*)&server_addr,sizeof(server_addr))) {
        perror("bind socket error");
        exit(-2);
    }

    if( listen(listen_fd, 256) ) {
        perror("listen socket error");
        exit(-2);
    }

    a_tls_init_env();
    cfg = a_tls_cfg_new();
    if (cfg == NULL) {
        printf("a_tls_cfg_new error\n");
        exit(-2);
    }

    while (1)
    {
        struct sockaddr_in client_addr;
        int client_fd, ret;
        socklen_t length = sizeof(client_addr);

        printf("Waiting client's connection....\n");
        client_fd = accept(listen_fd,(struct sockaddr*)&client_addr,&length);
        if (client_fd < 0) {
            closesocket(listen_fd);
            printf("accept error\n");
            exit(-2);
        }
        printf("process New client\n");
        tls = a_tls_new(cfg);
        if (tls == NULL) {
            closesocket(listen_fd);
            printf("a_tls_new error\n");
            exit(-2);
        }

        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        a_tls_set_fd(tls, client_fd);
        if (a_tls_handshake(tls) != 0)
        {
            printf("a_tls_handshake error\n");
            goto next;
        }

        memset(buf, 0 ,sizeof(buf));
        printf("Try to read %zu bytes from client.....\n", sizeof(buf));
        ret = a_tls_read(tls ,buf, sizeof(buf));
        if (ret <= 0)
        {
            printf("ret:%d\n",ret);
            if (ret == A_TLS_READ_FIN)
            {
                printf("a_tls_read fin\n");
            }
            else
            {
                printf("a_tls_read error\n");
            }
            goto next;
        }
        printf("Recv %d bytes from client %s\n", ret, buf);
        ret = a_tls_write(tls, (unsigned char*)replay, sizeof(replay) - 1);
        printf("reply to client :%d\n",ret);
next:
        closesocket(client_fd);
        a_tls_free_tls(tls);
    }

    a_tls_cfg_free(cfg);
    if (listen_fd) {
        closesocket(listen_fd);
    }

    return 0;
}