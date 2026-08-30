# CIDS (Cognitive Intrusion Detection System)

Sistema de monitoramento de rede e triagem de pacotes em baixo nível desenvolvido em **C puro**, focado em soberania arquitetural, zero dependências externas de alto nível e integração direta com inteligência artificial local via API.

## Arquitetura e Funcionamento

- **Captura de Baixo Nível**: Utiliza *Raw Sockets* (`SOCK_RAW`) e a API do Windows (`Winsock2`) para interceptação de tráfego direto na pilha IP.
- **Filtragem Local (Pré-triagem)**: Processamento e análise preliminar de pacotes diretamente em C, descartando ruídos estruturais e pacotes irrelevantes antes de qualquer despacho.
- **Rate Limiting Inteligente**: Acumula lotes de pacotes e gerencia uma janela de tempo de 15 segundos para otimizar o fluxo de processamento.
- **Soberania Local com IA**: Conexão assíncrona com o **Qwen 2.5** rodando localmente via Ollama, utilizando `WinHttp` nativo do Windows para analises comportamentais de tráfego sem depender de nuvens externas.

## Como Compilar e Executar

Certifique-se de ter um compilador GCC compatível instalado no sistema (como o MinGW) e o Ollama rodando localmente na porta padrão.

1. Abra o PowerShell ou Prompt de Comando **como Administrador** (necessário para a criação de Raw Sockets).
2. Compile o código-fonte linkando as bibliotecas nativas de rede e HTTP do Windows:
   ```cmd
   gcc sentinel.c -o sentinel.exe -lws2_32 -lwinhttp
