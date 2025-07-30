// File contributed by #Francisco Wallison, #megafuji, #gaaradodesertoo, originally by #__codeplay
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <fstream>
#include <unordered_map>
#include <algorithm>
#include <cstring>
#include <queue>
#include <vector>
#include <memory>
#include <atomic>

// Constantes
#define BUF_SIZE 1024 * 32
#define TIMEOUT 600000
#define RECONNECT_INTERVAL 1000
#define PING_INTERVAL 5000
#define SLEEP_TIME 10
#define SF_CLOSED -1
#define MAX_PACKET_SIZE 65535 // Tamanho máximo de pacote para validação

#pragma comment(lib, "ws2_32.lib")

using namespace std;

// Enum para tipo de pacote
enum e_PacketType
{
    RECEIVED = 0,
    SENT = 1
};

// Ponteiro para a função recv original
typedef int(WINAPI *recv_func_t)(SOCKET s, char *buf, int len, int flags);
recv_func_t original_recv = nullptr;

// Ponteiro para a função send original
typedef int(WINAPI *send_func_t)(SOCKET, const char *, int, int);
send_func_t original_send = nullptr;

// Variáveis globais de configuração (serão lidas de config_recv.txt)
DWORD clientSubAddress;
DWORD CRagConnection_instanceR_address;
DWORD recvPtrAddress;
DWORD sendAddress;

// IP e porta do servidor xKore
std::string koreServerIP;
DWORD koreServerPort;

// Configurações de hotkeys
std::string applyHookKey;
std::string removeHookKey;
bool applyHookRequiresCtrl = false;
bool applyHookRequiresShift = false;
bool removeHookRequiresCtrl = false;
bool removeHookRequiresShift = false;
int applyHookVK = VK_F1;
int removeHookVK = VK_F2;

// Configuração para múltiplos clientes
bool allowMultiClient = false;

// Configuração para debug detalhado
bool enableDebugLogs = false;

// Variáveis globais de estado
std::atomic<bool> hook_applied = false;
std::atomic<bool> koreClientIsAlive = false;
std::atomic<bool> imalive = false;
std::atomic<bool> keepMainThread = true;

// Threads
static HANDLE hThread = NULL;    // Thread principal
static HANDLE hKeyThread = NULL; // Thread do teclado
static HANDLE hSendThread = NULL;

// Critical sections
static CRITICAL_SECTION xkoreSendBuf_cs;
static CRITICAL_SECTION sendFunc_cs;

// Estrutura de pacote
struct Packet
{
    char ID;
    unsigned short len;
    std::unique_ptr<char[]> data;
};

// Constantes para janelas seguras
#define WINDOW_GAMEGUARD 1
#define WINDOW_SYNC 2
#define WINDOW_PING 3

// Intervalos naturais dos pacotes do jogo
#define SYNC_INTERVAL 12000       // 12s entre syncs
#define GAMEGUARD_INTERVAL 180000 // 180s entre gameguards
#define PING_INTERVAL_MIN 25000   // 25s mínimo entre pings
#define PING_INTERVAL_MAX 35000   // 35s máximo entre pings

// Margens de segurança
#define SYNC_SAFETY_MARGIN 1000      // 1s de margem
#define GAMEGUARD_SAFETY_MARGIN 5000 // 5s de margem
#define PING_SAFETY_MARGIN 3000      // 3s de margem

#define MAX_PACKETS_PER_WINDOW 5

// Nova estrutura para controlar janelas seguras de envio
struct SafeSendWindow
{
    bool gameGuardReceived = false;
    bool syncReceived = false;
    bool canSendPackets = false;
    DWORD lastGameGuard = 0;
    DWORD lastSync = 0;
    int packetsInQueue = 0;
    DWORD windowOpenTime = 0; // Quando janela abriu
    int windowType = 0;       // Tipo da janela atual
    int packetsProcessed = 0; // Pacotes processados na janela atual
};
static SafeSendWindow sendWindow;

// Typedef para a função de envio internamente no cliente
typedef int(__thiscall *SendToClientFunc)(void *CragConnection, size_t size, char *buffer);
SendToClientFunc sendFunc;

typedef void *(__stdcall *originalInstanceR)(void);
originalInstanceR instanceR;

// Sockets
static SOCKET koreClient = INVALID_SOCKET;
static SOCKET roServer = INVALID_SOCKET;

// Filas
static std::queue<std::vector<char>> xkorePacketQueue;
static std::queue<std::unique_ptr<Packet>> sendFuncQueue;
static std::atomic<bool> keepSendThread = true;

// Protótipos das funções
int WINAPI hooked_send(SOCKET s, const char *buf, int len, int flags);
DWORD WINAPI KeyboardMonitorThread(LPVOID lpParam);
DWORD WINAPI koreConnectionMain(LPVOID lpParam);
DWORD WINAPI SendFuncThread(LPVOID lpParam);
SOCKET createSocket(const std::string &ip, int port);
int readSocket(SOCKET s, char *buf, int len);
std::unique_ptr<Packet> unpackPacket(const char *buf, size_t buflen, int &next);
void processPacket(const Packet &packet);
bool isConnected(SOCKET s);
bool isWindowExpired();
void closeSafeWindow(const char *reason);
DWORD calculateRemainingWindow();

// Manipulador para exceções não tratadas
LONG WINAPI UnhandledExceptionHandler(EXCEPTION_POINTERS *exInfo)
{
    const char *exceptionType;
    switch (exInfo->ExceptionRecord->ExceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION:
        exceptionType = "ACESSO INVÁLIDO";
        break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        exceptionType = "ARRAY FORA DOS LIMITES";
        break;
    case EXCEPTION_BREAKPOINT:
        exceptionType = "BREAKPOINT";
        break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        exceptionType = "DESALINHAMENTO DE DADOS";
        break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:
        exceptionType = "OPERANDO FLOAT DENORMAL";
        break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        exceptionType = "DIVISÃO POR ZERO (FLOAT)";
        break;
    case EXCEPTION_FLT_INEXACT_RESULT:
        exceptionType = "RESULTADO FLOAT INEXATO";
        break;
    case EXCEPTION_FLT_INVALID_OPERATION:
        exceptionType = "OPERAÇÃO FLOAT INVÁLIDA";
        break;
    case EXCEPTION_FLT_OVERFLOW:
        exceptionType = "OVERFLOW FLOAT";
        break;
    case EXCEPTION_FLT_STACK_CHECK:
        exceptionType = "VERIFICAÇÃO DE STACK FLOAT";
        break;
    case EXCEPTION_FLT_UNDERFLOW:
        exceptionType = "UNDERFLOW FLOAT";
        break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
        exceptionType = "INSTRUÇÃO ILEGAL";
        break;
    case EXCEPTION_IN_PAGE_ERROR:
        exceptionType = "ERRO DE PAGINAÇÃO";
        break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
        exceptionType = "DIVISÃO POR ZERO (INT)";
        break;
    case EXCEPTION_INT_OVERFLOW:
        exceptionType = "OVERFLOW INT";
        break;
    case EXCEPTION_INVALID_DISPOSITION:
        exceptionType = "DISPOSIÇÃO INVÁLIDA";
        break;
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        exceptionType = "EXCEÇÃO NÃO CONTINUÁVEL";
        break;
    case EXCEPTION_PRIV_INSTRUCTION:
        exceptionType = "INSTRUÇÃO PRIVILEGIADA";
        break;
    case EXCEPTION_SINGLE_STEP:
        exceptionType = "PASSO ÚNICO";
        break;
    case EXCEPTION_STACK_OVERFLOW:
        exceptionType = "OVERFLOW DE STACK";
        break;
    default:
        exceptionType = "DESCONHECIDO";
    }

    // Exibir informações da exceção no console
    std::cerr << "\n\n=== ERRO FATAL OCORREU! ===" << std::endl;
    std::cerr << "Tipo de exceção: " << exceptionType << std::endl;
    std::cerr << "Código da exceção: 0x" << std::hex << exInfo->ExceptionRecord->ExceptionCode << std::endl;
    std::cerr << "Endereço: 0x" << std::hex << (DWORD)exInfo->ExceptionRecord->ExceptionAddress << std::endl;

    // Pausar para o usuário ver a mensagem
    std::cerr << "\nPressione ENTER para encerrar..." << std::endl;
    std::cin.get();

    return EXCEPTION_EXECUTE_HANDLER; // Permite ao programa encerrar normalmente após mostrar a mensagem
}


bool ApplySendHook()
{
    DWORD send_ptr_address = sendAddress; // endereço da função send

    std::cout << "Tentando aplicar hook no endereco: 0x" << std::hex << send_ptr_address << std::dec << std::endl;

    if (IsBadReadPtr((void *)send_ptr_address, sizeof(DWORD)))
    {
        std::cout << "ERRO: Endereco invalido para leitura!" << std::endl;
        return false;
    }

    original_send = *(send_func_t *)send_ptr_address;
    std::cout << "Ponteiro send original: 0x" << std::hex << (DWORD)original_send << std::dec << std::endl;

    if (original_send == nullptr)
    {
        std::cout << "ERRO: Ponteiro original eh nulo!" << std::endl;
        return false;
    }

    *(send_func_t *)send_ptr_address = hooked_send;
    std::cout << "Novo ponteiro (hook): 0x" << std::hex << (DWORD)hooked_send << std::dec << std::endl;

    send_func_t current_ptr = *(send_func_t *)send_ptr_address;
    if (current_ptr == hooked_send)
    {
        std::cout << "Hook aplicado com sucesso!" << std::endl;
        return true;
    }
    else
    {
        std::cout << "ERRO: Hook nao foi aplicado corretamente!" << std::endl;
        return false;
    }
}

// Console para depuração
void AllocateConsole()
{
    AllocConsole();
    freopen_s((FILE **)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE **)stderr, "CONOUT$", "w", stderr);
    freopen_s((FILE **)stdin, "CONIN$", "r", stdin);
#ifdef UNICODE
    SetConsoleTitle(L"Console de Debug");
#else
    SetConsoleTitle("Console de Debug");
#endif
}

// Função para depuração
void debug(const char *msg)
{
    std::cout << "[DEBUG] " << msg << std::endl;
}

// Função para converter bytes para hex
std::string BytesToHex(const char *data, int length)
{
    std::stringstream ss;
    int maxBytes = (length > 32) ? 32 : length; // Limita a 32 bytes para não poluir console

    for (int i = 0; i < maxBytes; ++i)
    {
        if (i > 0)
            ss << " ";
        unsigned char byte = static_cast<unsigned char>(data[i]);
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }

    if (length > 32)
    {
        ss << " ... (+" << (length - 32) << " bytes)";
    }

    return ss.str();
}

// Função para enviar dados para Kore
void sendDataToKore(char *buffer, int len, e_PacketType type)
{
    if (koreClientIsAlive)
    {
        // Cria um std::vector para o pacote completo
        std::vector<char> newbuf(len + 3);
        unsigned short sLen = static_cast<unsigned short>(len);

        // Verificação adicional de overflow
        if (len + 3 > MAX_PACKET_SIZE + 3)
        {
            return;
        }

        // Prefixo "R" ou "S"
        newbuf[0] = (type == e_PacketType::RECEIVED) ? 'R' : 'S';

        // Copia o comprimento e os dados do pacote de forma segura
        memcpy(newbuf.data() + 1, &sLen, sizeof(sLen));
        memcpy(newbuf.data() + 3, buffer, len);

        // Adiciona o pacote à fila de forma thread-safe
        EnterCriticalSection(&xkoreSendBuf_cs);
        xkorePacketQueue.push(newbuf);
        LeaveCriticalSection(&xkoreSendBuf_cs);
    }
}

// Nossa função recv hookada
int WINAPI hooked_recv(SOCKET s, char *buf, int len, int flags)
{
    // Chama a função original
    int result = original_recv(s, buf, len, flags);

    if (result > 0)
    {
        // Salva o socket do servidor RO
        roServer = s;

        // Detecta pacotes críticos interceptados
        if (result >= 2)
        {
            unsigned short packetID = *(unsigned short *)buf;
            DWORD currentTime = GetTickCount();

            switch (packetID)
            {
            case 0x09CF: // Gameguard request - 180s em 180s
            {            // jogo espera que o client envie o pacote 09D0 como resposta
            }
            break;

            case 0x007F: // Received Sync - 12s em 12s
            {
            }
            break;
            }
        }

        // Envia dados para Kore
        sendDataToKore(buf, result, e_PacketType::RECEIVED);
    }

    return result;
}

// Nossa função send hookada
int WINAPI hooked_send(SOCKET s, const char *buf, int len, int flags)
{
    // Chama a função original
    int result = original_send(s, buf, len, flags);

    if (result > 0)
    {
        // Detecta pacotes enviados pelo cliente
        if (len >= 2)
        {
            unsigned short packetID = *(unsigned short *)buf;
            DWORD currentTime = GetTickCount();

            switch (packetID)
            {
            case 0x0360: // Sync
            {
                std::cout << "[SEND] Sync enviado pelo cliente (0x0360)" << std::endl;
                sendWindow.canSendPackets = true;
                sendWindow.windowOpenTime = currentTime;
                sendWindow.windowType = WINDOW_SYNC;
                sendWindow.packetsProcessed = 0;
                sendWindow.lastSync = currentTime;
                DWORD remainingTime = calculateRemainingWindow();
                std::cout << "[JANELA] Sync → Janela de " << (remainingTime / 1000) << "s disponível" << std::endl;
            }
            break;
            case 0x0B1C: // Ping - alterna entre 25s e 35s
            {
                std::cout << "[SEND] Ping enviado pelo cliente (0x0B1C)" << std::endl;
                sendWindow.canSendPackets = true;
                sendWindow.windowOpenTime = currentTime;
                sendWindow.windowType = WINDOW_PING;
                sendWindow.packetsProcessed = 0;
                DWORD remainingTime = calculateRemainingWindow();
                std::cout << "[JANELA] Ping → Janela de " << (remainingTime / 1000) << "s disponível" << std::endl;
            }
            break;
            case 0x09D0: // Gameguard reply - 180s em 180s
            {
                std::cout << "[SEND] GameGuard Reply enviado pelo cliente (0x09D0)" << std::endl;
                // Força fechamento de janela anterior se houver
                if (sendWindow.canSendPackets)
                {
                    sendWindow.canSendPackets = false;
                    std::cout << "[PROTEÇÃO] Janela anterior fechada por GameGuard Reply" << std::endl;
                    Sleep(50); // Aguarda fila processar
                }
                sendWindow.gameGuardReceived = true;
                sendWindow.lastGameGuard = currentTime;
                sendWindow.canSendPackets = true;
                sendWindow.windowOpenTime = currentTime;
                sendWindow.windowType = WINDOW_GAMEGUARD;
                sendWindow.packetsProcessed = 0;
                DWORD remainingTime = calculateRemainingWindow();
                std::cout << "[JANELA] GameGuard Reply → Janela de " << (remainingTime / 1000) << "s disponível" << std::endl;
            }
            break;
            }
        }

        // Envia dados para Kore no formato: [S][2 bytes length][dados originais]
        sendDataToKore((char*)buf, result, e_PacketType::SENT);
    }

    return result;
}

// Função para converter string de tecla em código VK
int ParseKeyString(const std::string &keyStr, bool &requiresCtrl, bool &requiresShift)
{
    std::string key = keyStr;
    requiresCtrl = false;
    requiresShift = false;

    // Converte para maiúscula para facilitar comparação
    std::transform(key.begin(), key.end(), key.begin(), ::toupper);

    // Verifica modificadores
    if (key.find("CTRL+") == 0)
    {
        requiresCtrl = true;
        key = key.substr(5); // Remove "CTRL+"
    }
    if (key.find("SHIFT+") == 0)
    {
        requiresShift = true;
        key = key.substr(6); // Remove "SHIFT+"
    }
    if (key.find("CTRL+SHIFT+") == 0)
    {
        requiresCtrl = true;
        requiresShift = true;
        key = key.substr(11); // Remove "CTRL+SHIFT+"
    }
    if (key.find("SHIFT+CTRL+") == 0)
    {
        requiresCtrl = true;
        requiresShift = true;
        key = key.substr(11); // Remove "SHIFT+CTRL+"
    }

    // Mapeamento de teclas F1-F12
    if (key == "F1")
        return VK_F1;
    if (key == "F2")
        return VK_F2;
    if (key == "F3")
        return VK_F3;
    if (key == "F4")
        return VK_F4;
    if (key == "F5")
        return VK_F5;
    if (key == "F6")
        return VK_F6;
    if (key == "F7")
        return VK_F7;
    if (key == "F8")
        return VK_F8;
    if (key == "F9")
        return VK_F9;
    if (key == "F10")
        return VK_F10;
    if (key == "F11")
        return VK_F11;
    if (key == "F12")
        return VK_F12;

    // Teclas especiais adicionais
    if (key == "ESC" || key == "ESCAPE")
        return VK_ESCAPE;
    if (key == "SPACE")
        return VK_SPACE;
    if (key == "ENTER")
        return VK_RETURN;
    if (key == "TAB")
        return VK_TAB;
    if (key == "INSERT")
        return VK_INSERT;
    if (key == "DELETE")
        return VK_DELETE;
    if (key == "HOME")
        return VK_HOME;
    if (key == "END")
        return VK_END;
    if (key == "PAGEUP")
        return VK_PRIOR;
    if (key == "PAGEDOWN")
        return VK_NEXT;
    if (key == "LEFT")
        return VK_LEFT;
    if (key == "RIGHT")
        return VK_RIGHT;
    if (key == "UP")
        return VK_UP;
    if (key == "DOWN")
        return VK_DOWN;

    // Teclas alfanuméricas (A-Z, 0-9)
    if (key.length() == 1)
    {
        char c = key[0];
        if (c >= 'A' && c <= 'Z')
        {
            return c; // VK codes para A-Z são os mesmos que ASCII
        }
        if (c >= '0' && c <= '9')
        {
            return c; // VK codes para 0-9 são os mesmos que ASCII
        }
    }

    // Se não encontrou, retorna F11 como padrão
    return VK_F11;
}

// Função para criar arquivo de configuração padrão
bool CreateDefaultConfig(const std::string &filename)
{
    std::ofstream fout(filename);
    if (!fout.is_open())
    {
        std::cout << "[ERRO] Nao foi possivel criar o arquivo de configuracao: " << filename << std::endl;
        return false;
    }

    fout << "# ================================================\n";
    fout << "# Arquivo de configuração para recv.cpp\n";
    fout << "# ================================================\n";
    fout << "# IMPORTANTE: Configure os endereços corretos antes de usar!\n";
    fout << "# Os valores abaixo são apenas exemplos/padrão\n";
    fout << "#\n";
    fout << "# Endereços de memória do cliente RO (valores em hexadecimal)\n";
    fout << "# Estes valores devem ser obtidos através de análise do cliente\n";
    fout << "clientSubAddress=B7EF50\n";
    fout << "instanceRAddress=B7F4B0\n";
    fout << "recvPtrAddress=1455BB8\n";
    fout << "sendAddress=1455BBC\n";
    fout << "\n";
    fout << "# Configurações do servidor xKore\n";
    fout << "koreServerIP=127.0.0.1\n";
    fout << "koreServerPort=2350\n";
    fout << "\n";
    fout << "# Configurações de hotkeys (opcional)\n";
    fout << "# Formato: [Ctrl+][Shift+]TECLA\n";
    fout << "# Teclas disponíveis: F1-F12, A-Z, 0-9, ESC, SPACE, ENTER, TAB, INSERT, DELETE, HOME, END, PAGEUP, PAGEDOWN, LEFT, RIGHT, UP, DOWN\n";
    fout << "# Exemplos: F1, Ctrl+F5, Shift+F2, Ctrl+Shift+F9, Ctrl+A, Alt+Tab (não suportado), etc.\n";
    fout << "applyHookKey=Ctrl+F11\n";
    fout << "removeHookKey=Ctrl+F12\n";
    fout << "\n";
    fout << "# Configuração para múltiplos clientes\n";
    fout << "# Se true, pergunta a porta no terminal a cada execução\n";
    fout << "# Se false, usa sempre a porta padrão do koreServerPort\n";
    fout << "allowMultiClient=true\n";

    fout.close();

    std::cout << "[SUCESSO] Arquivo de configuracao padrao criado: " << filename << std::endl;
    return true;
}

// Função para ler o arquivo de configuração
bool LoadConfig(const std::string &filename)
{
    std::ifstream fin(filename);
    if (!fin.is_open())
    {
        std::cout << "\n=== AVISO IMPORTANTE ===" << std::endl;
        std::cout << "[AVISO] Arquivo de configuracao '" << filename << "' nao encontrado!" << std::endl;
        std::cout << "[INFO] Criando arquivo de configuracao padrao..." << std::endl;

        if (!CreateDefaultConfig(filename))
        {
            return false;
        }

        std::cout << "\n*** ATENCAO: CONFIGURE O ARQUIVO ANTES DE USAR! ***" << std::endl;
        std::cout << "1. Abra o arquivo '" << filename << "' que foi criado" << std::endl;
        std::cout << "2. Configure os enderecos de memoria corretos:" << std::endl;
        std::cout << "   - clientSubAddress" << std::endl;
        std::cout << "   - instanceRAddress" << std::endl;
        std::cout << "   - recvPtrAddress" << std::endl;
        std::cout << "3. Configure o IP e porta do servidor xKore se necessario" << std::endl;
        std::cout << "4. Reinicie o programa apos configurar" << std::endl;
        std::cout << "========================\n"
                  << std::endl;

        // Tenta abrir novamente após criar
        fin.open(filename);
        if (!fin.is_open())
        {
            std::cout << "[ERRO] Nao foi possivel abrir o arquivo de configuracao criado: " << filename << std::endl;
            return false;
        }
    }

    std::string line;
    // Usamos um map temporário para achar cada chave
    std::unordered_map<std::string, std::string> mapa;
    while (std::getline(fin, line))
    {
        // Ignora linhas vazias ou que comecem com '#' ou ';'
        if (line.empty())
            continue;
        if (line[0] == '#' || line[0] == ';')
            continue;

        // Encontra o '='
        size_t pos = line.find('=');
        if (pos == std::string::npos)
            continue;

        std::string chave = line.substr(0, pos);
        std::string valor = line.substr(pos + 1);

        // Remove espaços em excesso (caso haja)
        while (!chave.empty() && isspace(chave.back()))
            chave.pop_back();
        while (!valor.empty() && isspace(valor.front()))
            valor.erase(0, 1);
        while (!valor.empty() && isspace(valor.back()))
            valor.pop_back();

        mapa[chave] = valor;
    }
    fin.close();

    // Verifica existência das chaves obrigatórias
    if (mapa.count("clientSubAddress") == 0 ||
        mapa.count("instanceRAddress") == 0 ||
        mapa.count("recvPtrAddress") == 0 ||
        mapa.count("sendAddress") == 0 ||
        mapa.count("koreServerIP") == 0 ||
        mapa.count("koreServerPort") == 0)
    {
        std::cout << "[ERRO] Chaves faltando em config_recv.txt. Precisamos de:\n"
                  << "  clientSubAddress\n"
                  << "  instanceRAddress\n"
                  << "  recvPtrAddress\n"
                  << "  sendAddress\n"
                  << "  koreServerIP\n"
                  << "  koreServerPort\n";
        return false;
    }

    // Agora converte cada valor
    try
    {
        // Conversão dos hex para DWORD
        clientSubAddress = static_cast<DWORD>(std::stoul(mapa.at("clientSubAddress"), nullptr, 16));
        CRagConnection_instanceR_address = static_cast<DWORD>(std::stoul(mapa.at("instanceRAddress"), nullptr, 16));
        recvPtrAddress = static_cast<DWORD>(std::stoul(mapa.at("recvPtrAddress"), nullptr, 16));
        sendAddress = static_cast<DWORD>(std::stoul(mapa.at("sendAddress"), nullptr, 16));

        // Novos valores: IP e porta
        koreServerIP = mapa.at("koreServerIP");
        koreServerPort = static_cast<DWORD>(std::stoul(mapa.at("koreServerPort"), nullptr, 10));

        // Configurações de hotkeys (opcional, com valores padrão)
        applyHookKey = mapa.count("applyHookKey") > 0 ? mapa.at("applyHookKey") : "Ctrl+F11";
        removeHookKey = mapa.count("removeHookKey") > 0 ? mapa.at("removeHookKey") : "Ctrl+F12";

        // Processa as strings das teclas
        applyHookVK = ParseKeyString(applyHookKey, applyHookRequiresCtrl, applyHookRequiresShift);
        removeHookVK = ParseKeyString(removeHookKey, removeHookRequiresCtrl, removeHookRequiresShift);

        // Configuração de múltiplos clientes (opcional, padrão false)
        if (mapa.count("allowMultiClient") > 0)
        {
            std::string allowMultiStr = mapa.at("allowMultiClient");
            std::transform(allowMultiStr.begin(), allowMultiStr.end(), allowMultiStr.begin(), ::tolower);
            allowMultiClient = (allowMultiStr == "true" || allowMultiStr == "1" || allowMultiStr == "yes");
        }

        // Configuração de debug detalhado (opcional, padrão false)
        if (mapa.count("enableDebugLogs") > 0)
        {
            std::string debugStr = mapa.at("enableDebugLogs");
            std::transform(debugStr.begin(), debugStr.end(), debugStr.begin(), ::tolower);
            enableDebugLogs = (debugStr == "true" || debugStr == "1" || debugStr == "yes");
        }
    }
    catch (std::exception &e)
    {
        std::cout << "[ERRO] Excecao ao converter valor: " << e.what() << std::endl;
        return false;
    }

    std::cout << "[INFO] Configuracao carregada com sucesso:\n\n"
              << "  clientSubAddress = 0x" << std::hex << clientSubAddress << "\n"
              << "  instanceRAddress = 0x" << std::hex << CRagConnection_instanceR_address << "\n"
              << "  recvPtrAddress   = 0x" << std::hex << recvPtrAddress << "\n"
              << "  sendAddress      = 0x" << std::hex << sendAddress << std::dec << "\n"
              << "  koreServerIP     = " << koreServerIP << "\n"
              << "  koreServerPort   = " << koreServerPort << "\n"
              << "  applyHookKey     = " << applyHookKey << "\n"
              << "  removeHookKey    = " << removeHookKey << "\n"
              << "  allowMultiClient = " << (allowMultiClient ? "true" : "false") << std::endl;

    return true;
}

// Função para aplicar o hook (agora usa recvPtrAddress em vez de valor fixo)
bool ApplyHook()
{
    DWORD recv_ptr_address = recvPtrAddress; // lido do config

    std::cout << "Tentando aplicar hook no endereco: 0x" << std::hex << recv_ptr_address << std::dec << std::endl;

    if (IsBadReadPtr((void *)recv_ptr_address, sizeof(DWORD)))
    {
        std::cout << "ERRO: Endereco invalido para leitura!" << std::endl;
        return false;
    }

    original_recv = *(recv_func_t *)recv_ptr_address;
    std::cout << "Ponteiro recv original: 0x" << std::hex << (DWORD)original_recv << std::dec << std::endl;

    if (original_recv == nullptr)
    {
        std::cout << "ERRO: Ponteiro original eh nulo!" << std::endl;
        return false;
    }

    *(recv_func_t *)recv_ptr_address = hooked_recv;
    std::cout << "Novo ponteiro (hook): 0x" << std::hex << (DWORD)hooked_recv << std::dec << std::endl;

    recv_func_t current_ptr = *(recv_func_t *)recv_ptr_address;
    if (current_ptr == hooked_recv)
    {
        std::cout << "Hook aplicado com sucesso!" << std::endl;
        return true;
    }
    else
    {
        std::cout << "ERRO: Hook nao foi aplicado corretamente!" << std::endl;
        return false;
    }
}

// Função para remover o hook (usa também recvPtrAddress)
void RemoveHook()
{
    if (original_recv)
    {
        DWORD recv_ptr_address = recvPtrAddress;
        *(recv_func_t *)recv_ptr_address = original_recv;
        std::cout << "Hook removido!" << std::endl;
    }
}

// Verificar se socket está conectado
bool isConnected(SOCKET s)
{
    if (s == INVALID_SOCKET)
        return false;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(s, &readfds);

    timeval timeout = {0, 0};
    int result = select(0, &readfds, NULL, NULL, &timeout);

    if (result == SOCKET_ERROR)
        return false;
    return true;
}

// Criar socket usando IP e porta passados como parâmetros
SOCKET createSocket(const std::string &ip, int port)
{
    sockaddr_in addr;
    SOCKET sock;
    DWORD arg = 1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
        return INVALID_SOCKET;

    ioctlsocket(sock, FIONBIO, &arg);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    while (connect(sock, (struct sockaddr *)&addr, sizeof(sockaddr_in)) == SOCKET_ERROR)
    {
        if (WSAGetLastError() == WSAEISCONN)
            break;
        else if (WSAGetLastError() != WSAEWOULDBLOCK)
        {
            closesocket(sock);
            return INVALID_SOCKET;
        }
        else
            Sleep(10);
    }

    // Volta para modo bloqueante
    arg = 0;
    ioctlsocket(sock, FIONBIO, &arg);

    return sock;
}

// Ler dados do socket
int readSocket(SOCKET s, char *buf, int len)
{
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(s, &readfds);

    timeval timeout = {0, 0};
    int result = select(0, &readfds, NULL, NULL, &timeout);

    if (result == SOCKET_ERROR)
        return SF_CLOSED;
    if (result == 0)
        return 0; // Timeout

    int bytes = recv(s, buf, len, 0);
    if (bytes == 0 || bytes == SOCKET_ERROR)
        return SF_CLOSED;

    return bytes;
}

// Função para desempacotar pacotes
std::unique_ptr<Packet> unpackPacket(const char *buf, size_t buflen, int &next)
{
    // O tipo de buflen agora é size_t para corresponder a std::string::size()
    if (buflen < 3)
        return nullptr; // Pacote muito curto

    char id = buf[0];
    unsigned short len;
    memcpy(&len, buf + 1, sizeof(len)); // Cópia segura

    // Verifica se o buffer contém o pacote inteiro
    if (buflen < 3 + len)
        return nullptr; // Pacote incompleto

    // Aloca a estrutura do pacote usando std::unique_ptr para segurança de memória.
    auto packet = std::make_unique<Packet>();

    packet->ID = id;
    packet->len = len;

    // Aloca memória para os dados do pacote usando std::unique_ptr<char[]>
    if (len > 0)
    {
        // Usamos new (nothrow) para evitar exceções e retornar nullptr em caso de falha,
        // mantendo o comportamento original do código.
        packet->data.reset(new (std::nothrow) char[len]);
        if (!packet->data)
        {
            return nullptr; // Falha na alocação de memória para os dados
        }
        memcpy(packet->data.get(), buf + 3, len);
    }
    // Se len for 0, packet->data já é nullptr por padrão, então não é necessário 'else'.

    next = 3 + len;
    return packet;
}

// Funções auxiliares para janelas seguras
DWORD calculateRemainingWindow()
{
    DWORD currentTime = GetTickCount();

    switch (sendWindow.windowType)
    {
    case WINDOW_SYNC:
    {
        DWORD timeSinceLastSync = currentTime - sendWindow.lastSync;
        if (timeSinceLastSync >= SYNC_INTERVAL - SYNC_SAFETY_MARGIN)
        {
            return 0; // Janela expirada
        }
        return (SYNC_INTERVAL - SYNC_SAFETY_MARGIN) - timeSinceLastSync;
    }
    case WINDOW_GAMEGUARD:
    {
        DWORD timeSinceLastGG = currentTime - sendWindow.lastGameGuard;
        if (timeSinceLastGG >= GAMEGUARD_INTERVAL - GAMEGUARD_SAFETY_MARGIN)
        {
            return 0; // Janela expirada
        }
        return (GAMEGUARD_INTERVAL - GAMEGUARD_SAFETY_MARGIN) - timeSinceLastGG;
    }
    case WINDOW_PING:
    {
        DWORD timeSinceWindow = currentTime - sendWindow.windowOpenTime;
        if (timeSinceWindow >= PING_INTERVAL_MIN - PING_SAFETY_MARGIN)
        {
            return 0; // Janela expirada
        }
        return (PING_INTERVAL_MIN - PING_SAFETY_MARGIN) - timeSinceWindow;
    }
    }
    return 0; // Padrão seguro
}

bool isWindowExpired()
{
    if (!sendWindow.canSendPackets || sendWindow.windowOpenTime == 0)
    {
        return false;
    }

    return calculateRemainingWindow() == 0;
}

void closeSafeWindow(const char *reason)
{
    if (sendWindow.canSendPackets)
    {
        sendWindow.canSendPackets = false;
        sendWindow.packetsProcessed = 0;
        std::cout << "[PROTEÇÃO] Janela fechada → " << reason << std::endl;
    }
}

// Processar pacote recebido do Kore
void processPacket(const Packet &packet)
{
    switch (packet.ID)
    {
    case 'S': // Enviar pacote para o servidor RO - agora usa fila segura
    {
        // Cria cópia do pacote para a fila
        auto packetCopy = std::make_unique<Packet>();
        packetCopy->ID = packet.ID;
        packetCopy->len = packet.len;
        if (packet.len > 0)
        {
            packetCopy->data.reset(new (std::nothrow) char[packet.len]);
            if (packetCopy->data)
            {
                memcpy(packetCopy->data.get(), packet.data.get(), packet.len);
            }
            else
            {
                std::cout << "[ERROR] Falha ao alocar memoria para pacote S" << std::endl;
                break;
            }
        }

        // Adiciona à fila thread-safe
        EnterCriticalSection(&sendFunc_cs);
        sendFuncQueue.push(std::move(packetCopy));
        sendWindow.packetsInQueue++;
        LeaveCriticalSection(&sendFunc_cs);
    }
    break;

    case 'R': // Injetar pacote no cliente RO usando função interna
        // (Opcional: implementar lógica de injeção, se necessário)
        break;

    case 'K': // Keep-alive
        std::cout << "[KEEPALIVE] Pacote keep-alive recebido \n"
                  << std::endl;
        break;
    }
}

// Thread dedicada para processar pacotes 'S' em janelas seguras
DWORD WINAPI SendFuncThread(LPVOID lpParam)
{
    debug("Thread SendFuncThread iniciada");

    while (keepSendThread)
    {
        // Verifica timeout e limite de pacotes primeiro
        if (sendWindow.canSendPackets)
        {
            if (isWindowExpired())
            {
                closeSafeWindow("timeout");
                continue;
            }

            if (sendWindow.packetsProcessed >= MAX_PACKETS_PER_WINDOW)
            {
                closeSafeWindow("limite de pacotes");
                continue;
            }
        }

        // Só processa se estiver em janela segura
        if (sendWindow.canSendPackets && (roServer != INVALID_SOCKET && isConnected(roServer)))
        {
            std::unique_ptr<Packet> packet = nullptr;

            // Pega um pacote da fila
            EnterCriticalSection(&sendFunc_cs);
            if (!sendFuncQueue.empty())
            {
                packet = std::move(sendFuncQueue.front());
                sendFuncQueue.pop();
                sendWindow.packetsInQueue--;
            }
            LeaveCriticalSection(&sendFunc_cs);

            // Se tem pacote, processa
            if (packet)
            {
                try
                {
                    // Incrementa contador de pacotes processados
                    sendWindow.packetsProcessed++;

                    // Chama sendFunc de forma segura
                    int result = sendFunc(instanceR(), packet->len, packet->data.get());

                    // Pequeno delay entre pacotes para evitar spam
                    Sleep(50);
                }
                catch (...)
                {
                    std::cout << "[ERROR] Exceção ao chamar sendFunc!" << std::endl;
                }
            }
            else
            {
                // Sem pacotes, fecha janela segura
                closeSafeWindow("fila vazia");
            }
        }
        else
        {
            // Verifica se há pacotes aguardando e informa status
            EnterCriticalSection(&sendFunc_cs);
            int queueSize = sendFuncQueue.size();
            LeaveCriticalSection(&sendFunc_cs);

            if (queueSize > 0)
            {
                static DWORD lastWarning = 0;
                DWORD currentTime = GetTickCount();

                // Avisa sobre pacotes aguardando a cada 5 segundos
                if (currentTime - lastWarning > 5000)
                {
                    std::cout << "\n[AGUARDANDO] " << queueSize << " pacotes aguardando janela segura... \n"
                              << std::endl;
                    lastWarning = currentTime;
                }
            }

            // Aguarda próxima janela segura ou pacotes
            Sleep(100);
        }
    }

    debug("Thread SendFuncThread finalizada");
    return 0;
}

// Thread principal de conexão com Kore (ajustada para usar koreServerIP e koreServerPort)
DWORD WINAPI koreConnectionMain(LPVOID lpParam)
{
    char buf[BUF_SIZE + 1];
    char pingPacket[3];
    unsigned short pingPacketLength = 0;
    DWORD koreClientTimeout, koreClientPingTimeout, reconnectTimeout;
    string koreClientRecvBuf;

    debug("Thread koreConnectionMain iniciada");
    koreClientTimeout = GetTickCount();
    koreClientPingTimeout = GetTickCount();
    reconnectTimeout = 0;

    // Monta o pacote de ping
    memcpy(pingPacket, "K", 1);
    memcpy(pingPacket + 1, &pingPacketLength, 2);

    // NOVO: controla se já imprimimos "Aguardando Openkore"
    bool waitingPrinted = false;

    while (keepMainThread)
    {
        bool isAlive = koreClientIsAlive;
        bool isAliveChanged = false;

        // Se ainda não conectado e não marcamos a mensagem, imprimimos "Aplique o Hook e abra o Openkore" UMA ÚNICA VEZ
        if ((!isAlive || !isConnected(koreClient)) && !waitingPrinted)
        {
            std::cout << "\n- Se voce ja aplicou o hook (" << applyHookKey << "), abra o Openkore." << std::endl;
            waitingPrinted = true;
        }

        // Tentar conectar ao servidor xKore se necessário
        koreClientIsAlive = koreClient != INVALID_SOCKET;

        if ((!isAlive || !isConnected(koreClient) || GetTickCount() - koreClientTimeout > TIMEOUT) && GetTickCount() - reconnectTimeout > RECONNECT_INTERVAL)
        {

            // Ao entrar aqui, já temos impresso "Aguardando Openkore" (se ainda não estivesse conectado)

            std::cout << "[INFO] Tentando conectar ao servidor X-Kore ("
                      << koreServerIP << ":" << koreServerPort << ")..." << std::endl;

            if (koreClient != INVALID_SOCKET)
            {
                closesocket(koreClient);
            }

            // Usa IP e porta lidos do config
            koreClient = createSocket(koreServerIP, koreServerPort);

            isAlive = koreClient != INVALID_SOCKET;
            isAliveChanged = true;
            if (isAlive)
            {
                // Conectou com sucesso: resetamos o timeout e liberamos a flag de aguardando
                koreClientTimeout = GetTickCount();
                waitingPrinted = false;
                std::cout << "[SUCCESS] Conectado ao servidor X-Kore!" << std::endl;
            }
            else
            {
                std::cout << "[FAILED] Falha na conexao com X-Kore" << std::endl;
            }
            reconnectTimeout = GetTickCount();
        }

        // Receber dados do servidor xKore
        if (isAlive)
        {
            if (!imalive)
            {
                imalive = true;
            }

            int ret = readSocket(koreClient, buf, BUF_SIZE);
            if (ret == SF_CLOSED)
            {
                closesocket(koreClient);
                koreClient = INVALID_SOCKET;
                isAlive = false;
                isAliveChanged = true;
                imalive = false;
            }
            else if (ret > 0)
            {
                koreClientTimeout = GetTickCount(); // Reseta o timeout ao receber dados

                // Adiciona os dados recebidos ao buffer local da thread
                koreClientRecvBuf.append(buf, ret);

                // Agora, processa os pacotes do buffer e os adiciona à fila
                if (!koreClientRecvBuf.empty())
                {
                    std::unique_ptr<Packet> packet;
                    int next = 0;

                    // Processa os pacotes do buffer diretamente
                    while ((packet = unpackPacket(koreClientRecvBuf.c_str(), koreClientRecvBuf.size(), next)))
                    {
                        processPacket(*packet);
                        koreClientRecvBuf.erase(0, next);
                    }

                    // Os dados restantes (pacote incompleto) já permanecem em koreClientRecvBuf para a próxima iteração
                }
            }
        }

        // Enviar dados para o servidor xKore usando fila de pacotes
        EnterCriticalSection(&xkoreSendBuf_cs);
        if (!xkorePacketQueue.empty())
        {
            // Retira um pacote da fila
            std::vector<char> currentPacket = xkorePacketQueue.front();
            xkorePacketQueue.pop();
            LeaveCriticalSection(&xkoreSendBuf_cs);

            if (isAlive)
            {
                // Garante que o pacote inteiro seja enviado
                int totalSent = 0;
                int packetSize = currentPacket.size();

                while (totalSent < packetSize)
                {
                    int bytesSent = send(koreClient, currentPacket.data() + totalSent, packetSize - totalSent, 0);
                    if (bytesSent == SOCKET_ERROR)
                    {
                        int error = WSAGetLastError();
                        std::cout << "[ERROR] Falha ao enviar dados para xKore: " << error << std::endl;

                        // Se erro é não-recoverable, quebra o loop
                        if (error == WSAECONNRESET || error == WSAECONNABORTED || error == WSAENOTCONN)
                        {
                            std::cout << "[ERROR] Conexão com xKore perdida, erro irrecuperável: " << error << std::endl;
                            break;
                        }
                        // Para outros erros, tenta novamente após pequena pausa
                        Sleep(10);
                        continue;
                    }
                    else if (bytesSent == 0)
                    {
                        std::cout << "[ERROR] Conexão com xKore foi fechada durante envio" << std::endl;
                        break;
                    }
                    else
                    {
                        totalSent += bytesSent;
                    }
                }
            }
            else
            {
                // Pacotes na fila são formatados para Kore, não para RO server diretamente
                // Quando xKore está offline, apenas descartamos os pacotes da fila
                // Nota: Para envio direto ao RO seria necessário reformatar os pacotes,
                // removendo o cabeçalho do Kore. Por simplicidade, descartamos.
            }
        }
        else
        {
            // Não há pacotes para enviar, apenas sai da seção crítica
            LeaveCriticalSection(&xkoreSendBuf_cs);
        }

        // Ping para manter conexão viva
        if (koreClientIsAlive && GetTickCount() - koreClientPingTimeout > PING_INTERVAL)
        {
            send(koreClient, pingPacket, 3, 0);
            koreClientPingTimeout = GetTickCount();
        }

        if (isAliveChanged)
        {
            koreClientIsAlive = isAlive;
        }

        Sleep(SLEEP_TIME);
    }
    return 0;
}

// Thread para monitorar teclado (hotkeys customizáveis via config)
DWORD WINAPI KeyboardMonitorThread(LPVOID lpParam)
{
    static bool send_hook_applied = false;

    while (keepMainThread)
    {
        // Verifica a tecla de aplicar hook
        bool applyKeyPressed = (GetAsyncKeyState(applyHookVK) & 0x8000) != 0;
        bool applyCtrlOk = !applyHookRequiresCtrl || (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        bool applyShiftOk = !applyHookRequiresShift || (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;

        if (applyKeyPressed && applyCtrlOk && applyShiftOk)
        {
            if (!hook_applied)
            {
                std::cout << "\n"
                          << applyHookKey << " pressionado! Aplicando hook..." << std::endl;
                if (ApplyHook())
                {
                    hook_applied = true;
                    std::cout << "Hook aplicado! Pressione " << removeHookKey << " para remover hook." << std::endl;
                }
            }
            Sleep(500); // Evita múltiplas ativações
        }

        // Verifica a tecla de remover hook
        bool removeKeyPressed = (GetAsyncKeyState(removeHookVK) & 0x8000) != 0;
        bool removeCtrlOk = !removeHookRequiresCtrl || (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        bool removeShiftOk = !removeHookRequiresShift || (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;

        if (removeKeyPressed && removeCtrlOk && removeShiftOk)
        {
            if (hook_applied)
            {
                std::cout << "\n"
                          << removeHookKey << " pressionado! Removendo hook..." << std::endl;
                RemoveHook();
                hook_applied = false;
                std::cout << "Hook removido! Pressione " << applyHookKey << " para aplicar novamente." << std::endl;
            }
            Sleep(500); // Evita múltiplas ativações
        }

        // Verifica a tecla F3 para aplicar hook de send
        bool f3KeyPressed = (GetAsyncKeyState(VK_F3) & 0x8000) != 0;

        if (f3KeyPressed)
        {
            if (!send_hook_applied)
            {
                std::cout << "\nF3 pressionado! Aplicando hook de send..." << std::endl;
                if (ApplySendHook())
                {
                    send_hook_applied = true;
                    std::cout << "Hook de send aplicado com sucesso!" << std::endl;
                }
            }
            Sleep(500); // Evita múltiplas ativações
        }

        Sleep(100);
    }
    return 0;
}

// Função para solicitar porta do usuário (para allowMultiClient=true)
DWORD GetUserPort()
{
    char input[256];
    std::cout << "\n[MODO MULTI-CLIENTE]" << std::endl;
    std::cout << "Digite a porta do servidor xKore (padrao: " << koreServerPort << "): ";

    if (fgets(input, sizeof(input), stdin))
    {
        // Remove quebra de linha
        input[strcspn(input, "\r\n")] = 0;

        // Se string vazia (só Enter), usa porta padrão
        if (strlen(input) == 0)
        {
            std::cout << "Usando porta padrao: " << koreServerPort << std::endl;
            return koreServerPort;
        }

        // Tenta converter para número
        int inputPort = atoi(input);
        if (inputPort > 0 && inputPort <= 65535)
        {
            std::cout << "Usando porta customizada: " << inputPort << std::endl;
            return static_cast<DWORD>(inputPort);
        }
        else
        {
            std::cout << "Porta invalida! Usando porta padrao: " << koreServerPort << std::endl;
            return koreServerPort;
        }
    }

    std::cout << "Erro na leitura! Usando porta padrao: " << koreServerPort << std::endl;
    return koreServerPort;
}

// Função init (agora cria primeiro a KeyboardMonitorThread, depois a koreConnectionMain)
void init()
{
    SetUnhandledExceptionFilter(UnhandledExceptionHandler);
    InitializeCriticalSection(&xkoreSendBuf_cs);
    InitializeCriticalSection(&sendFunc_cs);

    AllocateConsole();
    std::cout << "=== RECV HOOK DLL ===" << std::endl;
    std::cout << "Arquitetura: x86 (32-bit)" << std::endl;

    // Tenta carregar arquivo de configuração (incluindo IP e porta)
    if (!LoadConfig("config_recv.txt"))
    {
        std::cout << "[FATAL] Falha ao carregar config_recv.txt. Abortando." << std::endl;
        keepMainThread = false;
        keepSendThread = false;
        return;
    }

    // Se allowMultiClient estiver habilitado, pergunta a porta ao usuário
    if (allowMultiClient)
    {
        koreServerPort = GetUserPort();
    }

    std::cout << "\n[INFO] Controles:\n"
              << std::endl;
    std::cout << "  " << applyHookKey << " - Aplicar hook" << std::endl;
    std::cout << "  " << removeHookKey << " - Remover hook" << std::endl;
    std::cout << "  F3 - Aplicar send hook" << std::endl;
    std::cout << "====================\n"
              << std::endl;

    // Inicializa Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Inicializa ponteiros das funções
    sendFunc = (SendToClientFunc)(clientSubAddress);
    instanceR = (originalInstanceR)(CRagConnection_instanceR_address);

    // Cria thread para monitorar teclado primeiro
    hKeyThread = CreateThread(NULL, 0, KeyboardMonitorThread, NULL, 0, NULL);
    if (hKeyThread == NULL)
    {
        std::cout << "Erro ao criar thread de monitoramento!" << std::endl;
    }

    // Cria thread para processar pacotes 'S' em janelas seguras
    debug("Criando thread SendFunc...");
    hSendThread = CreateThread(NULL, 0, SendFuncThread, NULL, 0, NULL);
    if (hSendThread)
    {
        debug("Thread SendFunc criada...");
    }
    else
    {
        debug("Falha ao criar thread SendFunc...");
    }

    // Agora cria a thread principal de conexão com Kore
    debug("Criando thread principal...");
    hThread = CreateThread(NULL, 0, koreConnectionMain, NULL, 0, NULL);
    if (hThread)
    {
        debug("Thread principal criada...");
    }
    else
    {
        debug("Falha ao criar thread...");
    }
}

// Função finish (igual, RemoveHook se necessário)
void finish()
{
    debug("Fechando threads...");
    keepMainThread = false;
    keepSendThread = false;

    // Aguarda as threads terminarem antes de prosseguir
    if (hThread)
    {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        hThread = NULL;
        debug("Thread principal fechada");
    }
    if (hKeyThread)
    {
        WaitForSingleObject(hKeyThread, INFINITE);
        CloseHandle(hKeyThread);
        hKeyThread = NULL;
        debug("Thread do teclado fechada");
    }
    if (hSendThread)
    {
        WaitForSingleObject(hSendThread, INFINITE);
        CloseHandle(hSendThread);
        hSendThread = NULL;
        debug("Thread SendFunc fechada");
    }

    if (hook_applied)
    {
        RemoveHook();
    }

    if (koreClient != INVALID_SOCKET)
    {
        closesocket(koreClient);
    }

    WSACleanup();
    DeleteCriticalSection(&xkoreSendBuf_cs);
    DeleteCriticalSection(&sendFunc_cs);
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        init();
        break;
    case DLL_PROCESS_DETACH:
        finish();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

// --- ATENÇÃO ---
// A função interna sendFunc NÃO é thread-safe. O client RO pode chamar sendFunc em threads próprias sem usar nenhum lock.
// Se a DLL tentar sincronizar usando critical section, pode causar deadlock ou starvation.
// Não há solução 100% segura sem modificar o client RO para usar o mesmo lock.
// Alternativas possíveis:
// 1. Só envie pacotes do OpenKore em momentos "seguros" (ex: quando o client está ocioso, ou via fila e polling em thread do client)
// 2. Intercepte a thread principal do client e injete os pacotes lá (hook em função de update principal)
// 3. Use um buffer intermediário: a DLL só coloca o pacote em uma fila, e um hook no client consome da fila e chama sendFunc
// 4. Aceite o risco de race condition, mas monitore e trate possíveis falhas
// 5. Se possível, peça para o client expor uma API de envio thread-safe
//
// O método mais seguro é a opção 3: hookar um ponto do client que já chama sendFunc e processar a fila da DLL nesse contexto.
