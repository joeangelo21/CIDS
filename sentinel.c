#winsock2.h>
#ws2tcpip.h>
#stdio.h>
#stdlib.h>
#string.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 65536

// Estrutura do Cabeçalho IP (camada de rede)
struct iphdr {
    unsigned char ihl:4;
    unsigned char version:4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned char check;
    unsigned int saddr;
    unsigned int daddr;
};

void print_ip_header(char* Buffer, int Size) {
    struct iphdr *iph = (struct iphdr *)Buffer;
    struct sockaddr_in source, dest;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("[SENTINEL-C] Pacote Capturado |\n");
    printf("   |- Versao IP   : %d\n", (unsigned int)iph->version);
    printf("   |- TTL         : %d\n", (unsigned int)iph->ttl);
    printf("   |- Protocolo   : %d\n", (unsigned int)iph->protocol);
    printf("   |- Origem      : %s\n", inet_ntoa(source.sin_addr));
    printf("   |- Destino     : %s\n", inet_ntoa(dest.sin_addr));
    printf("---------------------------------------------------\n");
}

int main() {
    WSADATA wsa;
    SOCKET snk;
    char *buffer;
    char ac[80];
    struct sockaddr_in local;
    int data_size;

    buffer = (char *)malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        fprintf(stderr, "Erro ao alocar memoria para o buffer!\n");
        return 1;
    }

    printf("[*] Inicializando o Winsock para o Sentinel C...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Falha no WSAStartup. Codigo: %d\n", WSAGetLastError());
        free(buffer);
        return 1;
    }

    // Criando o socket bruto (Raw Socket)
    snk = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (snk == INVALID_SOCKET) {
        fprintf(stderr, "Erro ao criar Raw Socket. Execute como Administrador! Codigo: %d\n", WSAGetLastError());
        WSACleanup();
        free(buffer);
        return 1;
    }

    // Obtendo o nome da máquina local para bind do socket
    if (gethostname(ac, sizeof(ac)) == SOCKET_ERROR) {
        fprintf(stderr, "Erro ao obter hostname. Codigo: %d\n", WSAGetLastError());
        closesocket(snk);
        WSACleanup();
        free(buffer);
        return 1;
    }

    struct hostent *phe = gethostbyname(ac);
    if (phe == 0) {
        fprintf(stderr, "Erro ao resolver host local.\n");
        closesocket(snk);
        WSACleanup();
        free(buffer);
        return 1;
    }

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    memcpy(&local.sin_addr.s_addr, phe->h_addr_list[0], phe->h_length);

    if (bind(snk, (struct sockaddr *)&local, sizeof(local)) == SOCKET_ERROR) {
        fprintf(stderr, "Erro no bind do socket. Codigo: %d\n", WSAGetLastError());
        closesocket(snk);
        WSACleanup();
        free(buffer);
        return 1;
    }

    // Habilitando o modo promiscuo/IOCTL para capturar todo o tráfego da interface
    DWORD sio_val = 1;
    DWORD bytes_returned = 0;
    if (WSAIoctl(snk, SIO_RCVALL, &sio_val, sizeof(sio_val), NULL, 0, &bytes_returned, NULL, NULL) == SOCKET_ERROR) {
        fprintf(stderr, "Aviso: Nao foi possivel ativar o modo promiscuo (SIO_RCVALL). Codigo: %d\n", WSAGetLastError());
    } else {
        printf("[+] Modo promiscuo ativado com sucesso. Escutando o barramento...\n");
    }

    // Loop principal de captura de telemetria
    while (1) {
        data_size = recv(snk, buffer, BUFFER_SIZE, 0);
        if (data_size < 0) {
            fprintf(stderr, "Erro na leitura do socket.\n");
            break;
        }
        print_ip_header(buffer, data_size);
    }

    closesocket(snk);
    WSACleanup();
    free(buffer);
    return 0;
}