// File contributed by #Francisco Wallison, #megafuji, #gaaradodesertoo, originally by #__codeplay
// Send Hook - Proof of Concept
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
#include <atomic>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

// Ponteiro para a função send original
typedef int(WINAPI *send_func_t)(SOCKET, const char *, int, int);
send_func_t original_send = nullptr;

// Variáveis globais de configuração (serão lidas de config_send.txt)
DWORD sendAddress;

// Configurações de hotkeys
std::string applyHookKey;
std::string removeHookKey;
bool applyHookRequiresCtrl = false;
bool applyHookRequiresShift = false;
bool removeHookRequiresCtrl = false;
bool removeHookRequiresShift = false;
int applyHookVK = VK_F3;
int removeHookVK = VK_F4;

// Variáveis globais de estado
std::atomic<bool> hook_applied = false;
std::atomic<bool> keepMainThread = true;

// Thread do teclado
static HANDLE hKeyThread = NULL;

// Constantes para janelas seguras
#define WINDOW_GAMEGUARD 1
#define WINDOW_SYNC 2
#define WINDOW_PING 3

// Intervalos naturais dos pacotes do jogo
#define SYNC_INTERVAL 12000       // 12s entre syncs
#define GAMEGUARD_INTERVAL 180000 // 180s entre gameguards
#define PING_INTERVAL_MIN 25000   // 25s mínimo entre pings

// Margens de segurança
#define SYNC_SAFETY_MARGIN 1000      // 1s de margem
#define GAMEGUARD_SAFETY_MARGIN 5000 // 5s de margem
#define PING_SAFETY_MARGIN 3000      // 3s de margem

// Estrutura para controlar janelas seguras de envio
struct SafeSendWindow
{
    bool canSendPackets = false;
    DWORD lastGameGuard = 0;
    DWORD lastSync = 0;
    DWORD windowOpenTime = 0; // Quando janela abriu
    int windowType = 0;       // Tipo da janela atual
};
static SafeSendWindow sendWindow;

// Protótipos das funções
int WINAPI hooked_send(SOCKET s, const char *buf, int len, int flags);
DWORD WINAPI KeyboardMonitorThread(LPVOID lpParam);
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

// Console para depuração
void AllocateConsole()
{
    AllocConsole();
    freopen_s((FILE **)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE **)stderr, "CONOUT$", "w", stderr);
    freopen_s((FILE **)stdin, "CONIN$", "r", stdin);
#ifdef UNICODE
    SetConsoleTitle(L"Send Hook - Proof of Concept");
#else
    SetConsoleTitle("Send Hook - Proof of Concept");
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
    int maxBytes = (length > 16) ? 16 : length; // Limita a 16 bytes para não poluir console

    for (int i = 0; i < maxBytes; ++i)
    {
        if (i > 0)
            ss << " ";
        unsigned char byte = static_cast<unsigned char>(data[i]);
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }

    if (length > 16)
    {
        ss << " ... (+" << (length - 16) << " bytes)";
    }

    return ss.str();
}

// Nossa função send hookada - Proof of Concept
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
                std::cout << "  Dados: " << BytesToHex(buf, len) << std::endl;
                sendWindow.canSendPackets = true;
                sendWindow.windowOpenTime = currentTime;
                sendWindow.windowType = WINDOW_SYNC;
                sendWindow.lastSync = currentTime;
                DWORD remainingTime = calculateRemainingWindow();
                std::cout << "  [JANELA] Sync → Janela de " << (remainingTime / 1000) << "s disponível" << std::endl;
            }
            break;
            case 0x0B1C: // Ping - alterna entre 25s e 35s
            {
                std::cout << "[SEND] Ping enviado pelo cliente (0x0B1C)" << std::endl;
                std::cout << "  Dados: " << BytesToHex(buf, len) << std::endl;
                sendWindow.canSendPackets = true;
                sendWindow.windowOpenTime = currentTime;
                sendWindow.windowType = WINDOW_PING;
                DWORD remainingTime = calculateRemainingWindow();
                std::cout << "  [JANELA] Ping → Janela de " << (remainingTime / 1000) << "s disponível" << std::endl;
            }
            break;
            case 0x09D0: // Gameguard reply - 180s em 180s
            {
                std::cout << "[SEND] GameGuard Reply enviado pelo cliente (0x09D0)" << std::endl;
                std::cout << "  Dados: " << BytesToHex(buf, len) << std::endl;
                // Força fechamento de janela anterior se houver
                if (sendWindow.canSendPackets)
                {
                    sendWindow.canSendPackets = false;
                    std::cout << "  [PROTEÇÃO] Janela anterior fechada por GameGuard Reply" << std::endl;
                }
                sendWindow.lastGameGuard = currentTime;
                sendWindow.canSendPackets = true;
                sendWindow.windowOpenTime = currentTime;
                sendWindow.windowType = WINDOW_GAMEGUARD;
                DWORD remainingTime = calculateRemainingWindow();
                std::cout << "  [JANELA] GameGuard Reply → Janela de " << (remainingTime / 1000) << "s disponível" << std::endl;
            }
            break;
            default:
                // Mostra outros pacotes enviados (opcional, para debug)
                if (len <= 32) // Só mostra pacotes pequenos para não poluir
                {
                    std::cout << "[SEND] Pacote 0x" << std::hex << std::uppercase << packetID 
                              << std::dec << " (" << len << " bytes): " << BytesToHex(buf, len) << std::endl;
                }
                break;
            }
        }
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

    // Se não encontrou, retorna F3 como padrão
    return VK_F3;
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
    fout << "# Arquivo de configuração para send.cpp\n";
    fout << "# ================================================\n";
    fout << "# IMPORTANTE: Configure os endereços corretos antes de usar!\n";
    fout << "# Os valores abaixo são apenas exemplos/padrão\n";
    fout << "#\n";
    fout << "# Endereços de memória do cliente RO (valores em hexadecimal)\n";
    fout << "# Estes valores devem ser obtidos através de análise do cliente\n";
    fout << "sendAddress=1455BBC\n";
    fout << "\n";
    fout << "# Configurações de hotkeys (opcional)\n";
    fout << "# Formato: [Ctrl+][Shift+]TECLA\n";
    fout << "# Teclas disponíveis: F1-F12, A-Z, 0-9, ESC, SPACE, ENTER, TAB, INSERT, DELETE, HOME, END, PAGEUP, PAGEDOWN, LEFT, RIGHT, UP, DOWN\n";
    fout << "# Exemplos: F1, Ctrl+F5, Shift+F2, Ctrl+Shift+F9, Ctrl+A, Alt+Tab (não suportado), etc.\n";
    fout << "applyHookKey=F3\n";
    fout << "removeHookKey=F4\n";

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
        std::cout << "2. Configure o endereco de memoria correto:" << std::endl;
        std::cout << "   - sendAddress" << std::endl;
        std::cout << "3. Reinicie o programa apos configurar" << std::endl;
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
    if (mapa.count("sendAddress") == 0)
    {
        std::cout << "[ERRO] Chave faltando em config_send.txt. Precisamos de:\n"
                  << "  sendAddress\n";
        return false;
    }

    // Agora converte cada valor
    try
    {
        // Conversão dos hex para DWORD
        sendAddress = static_cast<DWORD>(std::stoul(mapa.at("sendAddress"), nullptr, 16));

        // Configurações de hotkeys (opcional, com valores padrão)
        applyHookKey = mapa.count("applyHookKey") > 0 ? mapa.at("applyHookKey") : "F3";
        removeHookKey = mapa.count("removeHookKey") > 0 ? mapa.at("removeHookKey") : "F4";

        // Processa as strings das teclas
        applyHookVK = ParseKeyString(applyHookKey, applyHookRequiresCtrl, applyHookRequiresShift);
        removeHookVK = ParseKeyString(removeHookKey, removeHookRequiresCtrl, removeHookRequiresShift);
    }
    catch (std::exception &e)
    {
        std::cout << "[ERRO] Excecao ao converter valor: " << e.what() << std::endl;
        return false;
    }

    std::cout << "[INFO] Configuracao carregada com sucesso:\n\n"
              << "  sendAddress      = 0x" << std::hex << sendAddress << std::dec << "\n"
              << "  applyHookKey     = " << applyHookKey << "\n"
              << "  removeHookKey    = " << removeHookKey << std::endl;

    return true;
}

// Função para aplicar o hook de send
bool ApplyHook()
{
    DWORD send_ptr_address = sendAddress; // lido do config

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

// Função para remover o hook
void RemoveHook()
{
    if (original_send)
    {
        DWORD send_ptr_address = sendAddress;
        *(send_func_t *)send_ptr_address = original_send;
        std::cout << "Hook removido!" << std::endl;
    }
}

// Thread para monitorar teclado
DWORD WINAPI KeyboardMonitorThread(LPVOID lpParam)
{
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

        Sleep(100);
    }
    return 0;
}

// Implementação das funções auxiliares necessárias
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

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        SetUnhandledExceptionFilter(UnhandledExceptionHandler);
        AllocateConsole();
        std::cout << "=== SEND HOOK - PROOF OF CONCEPT ===" << std::endl;
        std::cout << "Arquitetura: x86 (32-bit)" << std::endl;
        
        // Tenta carregar arquivo de configuração
        if (!LoadConfig("config_send.txt"))
        {
            std::cout << "[FATAL] Falha ao carregar config_send.txt. Abortando." << std::endl;
            return FALSE;
        }
        
        std::cout << "\n[INFO] Controles:\n" << std::endl;
        std::cout << "  " << applyHookKey << " - Aplicar hook de send" << std::endl;
        std::cout << "  " << removeHookKey << " - Remover hook de send" << std::endl;
        std::cout << "\n[INFO] Este é um proof of concept para detectar pacotes críticos" << std::endl;
        std::cout << "====================\n" << std::endl;
        
        // Cria thread para monitorar teclado
        hKeyThread = CreateThread(NULL, 0, KeyboardMonitorThread, NULL, 0, NULL);
        if (hKeyThread == NULL)
        {
            std::cout << "Erro ao criar thread de monitoramento!" << std::endl;
        }
        
        // Aplica o hook automaticamente
        if (ApplyHook())
        {
            hook_applied = true;
            std::cout << "Hook de send aplicado automaticamente!" << std::endl;
        }
        break;
        
    case DLL_PROCESS_DETACH:
        keepMainThread = false;
        
        if (hKeyThread)
        {
            WaitForSingleObject(hKeyThread, INFINITE);
            CloseHandle(hKeyThread);
            hKeyThread = NULL;
        }
        
        if (hook_applied)
        {
            RemoveHook();
        }
        break;
        
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
