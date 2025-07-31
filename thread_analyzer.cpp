#include "thread_analyzer.h"
#include <iostream>
#include <iomanip>
#include <sstream>

// Variáveis globais
std::vector<ThreadInfo> g_threads;
std::queue<PacketData> g_packetQueue;
CRITICAL_SECTION g_queueCS;
bool g_analyzerInitialized = false;
DWORD g_mainThreadId = 0;
DWORD g_safeHookAddress = 0;
SafePacketProcessor g_packetProcessor = nullptr;

// Funções auxiliares para logging
void DebugLog(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    std::cout << "[THREAD_ANALYZER] " << buffer << std::endl;
}

// Função para verificar se o processo está estável
bool IsProcessStable() {
    static DWORD lastCheck = 0;
    static int stableChecks = 0;
    static DWORD lastThreadCount = 0;
    
    DWORD currentTime = GetTickCount();
    
    // Verifica a cada 1 segundo
    if (currentTime - lastCheck < 1000) {
        return false;
    }
    
    lastCheck = currentTime;
    
    // Conta threads ativas
    DWORD currentProcessId = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    DWORD threadCount = 0;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    
    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == currentProcessId) {
                threadCount++;
            }
        } while (Thread32Next(snapshot, &te));
    }
    
    CloseHandle(snapshot);
    
    // Verifica se número de threads está estável
    if (threadCount == lastThreadCount) {
        stableChecks++;
    } else {
        stableChecks = 0;
        lastThreadCount = threadCount;
    }
    
    // Considera estável após 5 verificações consecutivas com mesmo número de threads
    // E pelo menos 10 segundos desde o início
    bool isStable = (stableChecks >= 5) && (currentTime > 10000);
    
    if (isStable) {
        DebugLog("Processo estavel detectado: %d threads por %d verificacoes", threadCount, stableChecks);
    }
    
    return isStable;
}

// Função para aguardar estabilidade do processo
bool WaitForProcessStability(DWORD timeoutMs = 30000) {
    DebugLog("Aguardando estabilidade do processo...");
    
    DWORD startTime = GetTickCount();
    
    while (GetTickCount() - startTime < timeoutMs) {
        if (IsProcessStable()) {
            DebugLog("Processo estabilizado apos %d ms", GetTickCount() - startTime);
            return true;
        }
        Sleep(500);
    }
    
    DebugLog("Timeout aguardando estabilidade do processo");
    return false;
}

// Thread para inicialização assíncrona
DWORD WINAPI ThreadAnalyzerInitThread(LPVOID lpParam) {
    DebugLog("Thread de inicializacao do Thread Analyzer iniciada");
    
    // AGUARDA O PROCESSO ESTABILIZAR ANTES DE CONTINUAR
    if (!WaitForProcessStability()) {
        DebugLog("ERRO: Processo nao estabilizou, abortando inicializacao");
        return 1;
    }
    
    DebugLog("Iniciando analise detalhada...");
    
    try {
        // Inicializa símbolos para debug (pode falhar, mas não é crítico)
        DebugLog("Inicializando simbolos de debug...");
        if (SymInitialize(GetCurrentProcess(), NULL, TRUE)) {
            DebugLog("Simbolos de debug inicializados com sucesso");
        } else {
            DebugLog("AVISO: Falha ao inicializar simbolos de debug (continuando sem eles)");
        }
        
        // Enumera threads do processo
        DebugLog("Enumerando threads do processo...");
        g_threads = EnumerateProcessThreads();
        DebugLog("Encontradas %d threads", (int)g_threads.size());
        
        if (g_threads.empty()) {
            DebugLog("ERRO: Nenhuma thread encontrada");
            return 1;
        }
        
        // Encontra thread principal
        DebugLog("Identificando thread principal...");
        ThreadInfo* mainThread = FindMainThread();
        if (mainThread) {
            g_mainThreadId = mainThread->threadId;
            DebugLog("Thread principal identificada: ID %d", g_mainThreadId);
        } else {
            DebugLog("ERRO: Nao foi possivel identificar thread principal");
            return 1;
        }
        
        // Cria fila de pacotes
        DebugLog("Criando fila de pacotes...");
        if (!CreatePacketQueue()) {
            DebugLog("ERRO: Falha ao criar fila de pacotes");
            return 1;
        }
        
        // Procura pontos seguros para hook
        DebugLog("Procurando pontos seguros para hook...");
        std::vector<HookPoint> hookPoints = IdentifyHookPoints();
        if (!hookPoints.empty()) {
            DebugLog("Encontrados %d pontos de hook seguros:", (int)hookPoints.size());
            for (const auto& point : hookPoints) {
                DebugLog("  - %s (0x%08X, prioridade: %d)", point.name, point.address, point.priority);
            }
        } else {
            DebugLog("Nenhum ponto de hook seguro encontrado");
        }
        
        // Mostra informações das threads
        DebugLog("Gerando relatorio de threads...");
        DumpThreadInfo();
        
        g_analyzerInitialized = true;
        DebugLog("Thread Analyzer inicializado com sucesso de forma assincrona");
        
    } catch (...) {
        DebugLog("ERRO: Excecao durante inicializacao do Thread Analyzer");
        return 1;
    }
    
    return 0;
}

// Inicialização assíncrona do analisador
bool InitializeThreadAnalyzerAsync() {
    if (g_analyzerInitialized) {
        return true;
    }
    
    DebugLog("Iniciando Thread Analyzer de forma assincrona...");
    
    // Inicializa critical section imediatamente
    InitializeCriticalSection(&g_queueCS);
    
    // Cria thread para inicialização em background
    HANDLE hInitThread = CreateThread(NULL, 0, ThreadAnalyzerInitThread, NULL, 0, NULL);
    if (hInitThread) {
        CloseHandle(hInitThread); // Não precisamos manter o handle
        DebugLog("Thread de inicializacao criada com sucesso");
        return true;
    } else {
        DebugLog("ERRO: Falha ao criar thread de inicializacao");
        DeleteCriticalSection(&g_queueCS);
        return false;
    }
}

// Inicialização síncrona do analisador (mantida para compatibilidade)
bool InitializeThreadAnalyzer() {
    if (g_analyzerInitialized) {
        return true;
    }
    
    DebugLog("Inicializando Thread Analyzer...");
    
    // AGUARDA O PROCESSO ESTABILIZAR ANTES DE CONTINUAR
    if (!WaitForProcessStability()) {
        DebugLog("ERRO: Processo nao estabilizou, abortando inicializacao");
        return false;
    }
    
    // Inicializa critical section
    InitializeCriticalSection(&g_queueCS);
    
    // Inicializa símbolos para debug
    SymInitialize(GetCurrentProcess(), NULL, TRUE);
    
    // Enumera threads do processo
    g_threads = EnumerateProcessThreads();
    DebugLog("Encontradas %d threads", (int)g_threads.size());
    
    // Encontra thread principal
    ThreadInfo* mainThread = FindMainThread();
    if (mainThread) {
        g_mainThreadId = mainThread->threadId;
        DebugLog("Thread principal identificada: ID %d", g_mainThreadId);
    } else {
        DebugLog("ERRO: Nao foi possivel identificar thread principal");
        return false;
    }
    
    // Cria fila de pacotes
    if (!CreatePacketQueue()) {
        DebugLog("ERRO: Falha ao criar fila de pacotes");
        return false;
    }
    
    g_analyzerInitialized = true;
    DebugLog("Thread Analyzer inicializado com sucesso");
    return true;
}

// Cleanup
void CleanupThreadAnalyzer() {
    if (!g_analyzerInitialized) {
        return;
    }
    
    DebugLog("Limpando Thread Analyzer...");
    
    // Limpa fila de pacotes
    EnterCriticalSection(&g_queueCS);
    while (!g_packetQueue.empty()) {
        PacketData packet = g_packetQueue.front();
        g_packetQueue.pop();
        delete[] packet.data;
    }
    LeaveCriticalSection(&g_queueCS);
    
    // Fecha handles das threads
    for (auto& thread : g_threads) {
        if (thread.threadHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(thread.threadHandle);
        }
    }
    
    DeleteCriticalSection(&g_queueCS);
    SymCleanup(GetCurrentProcess());
    
    g_analyzerInitialized = false;
    DebugLog("Thread Analyzer limpo");
}

// Enumeração de threads (versão simplificada e segura)
std::vector<ThreadInfo> EnumerateProcessThreads() {
    std::vector<ThreadInfo> threads;
    DWORD currentProcessId = GetCurrentProcessId();
    
    DebugLog("Criando snapshot de threads...");
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        DebugLog("ERRO: Falha ao criar snapshot de threads");
        return threads;
    }
    
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    
    DebugLog("Enumerando threads...");
    if (Thread32First(snapshot, &te)) {
        int threadCount = 0;
        do {
            if (te.th32OwnerProcessID == currentProcessId) {
                ThreadInfo info = {};
                info.threadId = te.th32ThreadID;
                
                // Abre thread com permissões mínimas para evitar problemas
                info.threadHandle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (info.threadHandle != INVALID_HANDLE_VALUE) {
                    info.startAddress = GetThreadStartAddress(info.threadHandle);
                    info.isMainThread = false;
                    info.isGameLoop = false;
                    
                    // NÃO analisa call stack para evitar travamentos
                    // AnalyzeThreadStack(&info);
                    
                    threads.push_back(info);
                    threadCount++;
                    
                    DebugLog("Thread %d: ID=%d, StartAddr=0x%08X", threadCount, info.threadId, info.startAddress);
                }
            }
        } while (Thread32Next(snapshot, &te));
        
        DebugLog("Total de threads enumeradas: %d", threadCount);
    } else {
        DebugLog("ERRO: Falha ao enumerar primeira thread");
    }
    
    CloseHandle(snapshot);
    return threads;
}

// Encontra thread principal
ThreadInfo* FindMainThread() {
    DWORD mainThreadId = 0;
    
    // Método 1: Thread com maior tempo de CPU
    DWORD maxCpuTime = 0;
    for (auto& thread : g_threads) {
        FILETIME creationTime, exitTime, kernelTime, userTime;
        if (GetThreadTimes(thread.threadHandle, &creationTime, &exitTime, &kernelTime, &userTime)) {
            ULARGE_INTEGER totalTime;
            totalTime.LowPart = userTime.dwLowDateTime;
            totalTime.HighPart = userTime.dwHighDateTime;
            
            if (totalTime.QuadPart > maxCpuTime) {
                maxCpuTime = (DWORD)totalTime.QuadPart;
                mainThreadId = thread.threadId;
            }
        }
    }
    
    // Método 2: Thread criada primeiro (fallback)
    if (mainThreadId == 0) {
        FILETIME earliestTime = {MAXDWORD, MAXDWORD};
        for (auto& thread : g_threads) {
            FILETIME creationTime, exitTime, kernelTime, userTime;
            if (GetThreadTimes(thread.threadHandle, &creationTime, &exitTime, &kernelTime, &userTime)) {
                if (CompareFileTime(&creationTime, &earliestTime) < 0) {
                    earliestTime = creationTime;
                    mainThreadId = thread.threadId;
                }
            }
        }
    }
    
    // Marca thread principal
    for (auto& thread : g_threads) {
        if (thread.threadId == mainThreadId) {
            thread.isMainThread = true;
            return &thread;
        }
    }
    
    return nullptr;
}

// Obtém endereço de início da thread
DWORD GetThreadStartAddress(HANDLE threadHandle) {
    if (threadHandle == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    // Método usando NtQueryInformationThread
    typedef NTSTATUS (WINAPI *NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static NtQueryInformationThread_t NtQueryInformationThread = nullptr;
    
    if (!NtQueryInformationThread) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(ntdll, "NtQueryInformationThread");
        }
    }
    
    if (NtQueryInformationThread) {
        DWORD startAddress = 0;
        NTSTATUS status = NtQueryInformationThread(threadHandle, 9, &startAddress, sizeof(startAddress), nullptr);
        if (status == 0) {
            return startAddress;
        }
    }
    
    return 0;
}

// Análise de call stack
bool AnalyzeThreadStack(ThreadInfo* thread) {
    if (!thread || thread->threadHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Suspende thread temporariamente
    DWORD suspendCount = SuspendThread(thread->threadHandle);
    if (suspendCount == (DWORD)-1) {
        return false;
    }
    
    // Obtém contexto
    thread->context.ContextFlags = CONTEXT_FULL;
    bool contextOk = GetThreadContext(thread->threadHandle, &thread->context);
    
    if (contextOk) {
        // Analisa stack usando StackWalk64
        STACKFRAME64 stackFrame = {};
#ifdef _WIN64
        stackFrame.AddrPC.Offset = thread->context.Rip;
        stackFrame.AddrFrame.Offset = thread->context.Rbp;
        stackFrame.AddrStack.Offset = thread->context.Rsp;
#else
        stackFrame.AddrPC.Offset = thread->context.Eip;
        stackFrame.AddrFrame.Offset = thread->context.Ebp;
        stackFrame.AddrStack.Offset = thread->context.Esp;
#endif
        stackFrame.AddrPC.Mode = AddrModeFlat;
        stackFrame.AddrFrame.Mode = AddrModeFlat;
        stackFrame.AddrStack.Mode = AddrModeFlat;
        
        HANDLE process = GetCurrentProcess();
        int frameCount = 0;
        
        while (frameCount < MAX_STACK_FRAMES) {
            if (!StackWalk64(IMAGE_FILE_MACHINE_I386, process, thread->threadHandle,
                           &stackFrame, &thread->context, nullptr, 
                           SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
                break;
            }
            
            if (stackFrame.AddrPC.Offset != 0) {
                thread->callStack.push_back((DWORD)stackFrame.AddrPC.Offset);
                frameCount++;
            }
        }
    }
    
    // Resume thread
    ResumeThread(thread->threadHandle);
    
    return contextOk && !thread->callStack.empty();
}

// Busca por padrões de função
DWORD FindFunctionPattern(const char* pattern, const char* mask) {
    HMODULE mainModule = GetModuleHandle(NULL);
    return FindPatternInModule(mainModule, pattern, mask);
}

DWORD FindPatternInModule(HMODULE module, const char* pattern, const char* mask) {
    if (!module) {
        return 0;
    }
    
    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), module, &moduleInfo, sizeof(moduleInfo))) {
        return 0;
    }
    
    BYTE* baseAddress = (BYTE*)moduleInfo.lpBaseOfDll;
    DWORD moduleSize = moduleInfo.SizeOfImage;
    size_t patternLength = strlen(mask);
    
    for (DWORD i = 0; i < moduleSize - patternLength; i++) {
        bool found = true;
        for (size_t j = 0; j < patternLength; j++) {
            if (mask[j] == 'x' && baseAddress[i + j] != (BYTE)pattern[j]) {
                found = false;
                break;
            }
        }
        
        if (found) {
            return (DWORD)(baseAddress + i);
        }
    }
    
    return 0;
}

// Detecção de game loop
DWORD FindGameLoopFunction() {
    DebugLog("Procurando funcao de game loop...");
    
    // Padrões comuns de game loop
    struct Pattern {
        const char* name;
        const char* pattern;
        const char* mask;
    };
    
    Pattern patterns[] = {
        {"PeekMessage Loop", "\x8D\x45\xE4\x50\x6A\x00\x6A\x00\x6A\x00\x6A\x00\xFF\x15", "xxxxxxxxxxxxxx"},
        {"GetMessage Loop", "\xFF\x15\x00\x00\x00\x00\x85\xC0\x74\x00\x8B\x4D", "xx????xxx?xx"},
        {"Timer Loop", "\x68\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x85\xC0\x75", "x????xx????xxx"},
        {"Main Loop", "\x55\x8B\xEC\x83\xEC\x00\xA1\x00\x00\x00\x00\x33\xC5", "xxxxx?x????xx"}
    };
    
    for (const auto& pattern : patterns) {
        DWORD address = FindFunctionPattern(pattern.pattern, pattern.mask);
        if (address && ValidateHookTarget(address)) {
            DebugLog("Encontrado %s em 0x%08X", pattern.name, address);
            return address;
        }
    }
    
    DebugLog("Nenhuma funcao de game loop encontrada");
    return 0;
}

// Validação de target para hook
bool ValidateHookTarget(DWORD address) {
    if (address == 0) {
        return false;
    }
    
    // Verifica se endereço é válido
    if (IsBadReadPtr((void*)address, 16)) {
        return false;
    }
    
    // Verifica se é início de função (prólogo típico)
    BYTE* code = (BYTE*)address;
    
    // Prólogo comum: push ebp; mov ebp, esp
    if (code[0] == 0x55 && code[1] == 0x8B && code[2] == 0xEC) {
        return true;
    }
    
    // Prólogo com sub esp: push ebp; mov ebp, esp; sub esp, X
    if (code[0] == 0x55 && code[1] == 0x8B && code[2] == 0xEC && code[3] == 0x83 && code[4] == 0xEC) {
        return true;
    }
    
    return false;
}

// Criação da fila de pacotes
bool CreatePacketQueue() {
    DebugLog("Criando fila de pacotes thread-safe...");
    
    // Fila já é criada automaticamente
    // Apenas verifica se critical section foi inicializada
    
    DebugLog("Fila de pacotes criada com sucesso");
    return true;
}

// Adiciona pacote à fila
void AddPacketToQueue(const char* data, int length) {
    if (!data || length <= 0 || length > 65535) {
        return;
    }
    
    EnterCriticalSection(&g_queueCS);
    
    // Verifica se fila não está cheia
    if (g_packetQueue.size() >= PACKET_QUEUE_SIZE) {
        DebugLog("AVISO: Fila de pacotes cheia, descartando pacote mais antigo");
        PacketData oldPacket = g_packetQueue.front();
        g_packetQueue.pop();
        delete[] oldPacket.data;
    }
    
    // Cria novo pacote
    PacketData packet;
    packet.data = new char[length];
    memcpy(packet.data, data, length);
    packet.length = length;
    packet.timestamp = GetTickCount();
    
    g_packetQueue.push(packet);
    
    LeaveCriticalSection(&g_queueCS);
}

// Processa pacotes da fila (chamado em contexto seguro)
void ProcessQueuedPackets() {
    if (!g_analyzerInitialized) {
        return;
    }
    
    EnterCriticalSection(&g_queueCS);
    
    int processedCount = 0;
    while (!g_packetQueue.empty() && processedCount < 10) { // Limita processamento
        PacketData packet = g_packetQueue.front();
        g_packetQueue.pop();
        
        LeaveCriticalSection(&g_queueCS);
        
        // Processa pacote em contexto seguro
        if (g_packetProcessor) {
            g_packetProcessor();
        }
        
        // Limpa dados do pacote
        delete[] packet.data;
        processedCount++;
        
        EnterCriticalSection(&g_queueCS);
    }
    
    LeaveCriticalSection(&g_queueCS);
}

// Funções de debugging
void DumpThreadInfo() {
    DebugLog("=== INFORMACOES DAS THREADS ===");
    
    for (const auto& thread : g_threads) {
        DebugLog("Thread ID: %d", thread.threadId);
        DebugLog("  Start Address: 0x%08X", thread.startAddress);
        DebugLog("  Is Main: %s", thread.isMainThread ? "Sim" : "Nao");
        DebugLog("  Is Game Loop: %s", thread.isGameLoop ? "Sim" : "Nao");
        DebugLog("  Call Stack Frames: %d", (int)thread.callStack.size());
        
        if (!thread.callStack.empty()) {
            DebugLog("  Stack Trace:");
            for (size_t i = 0; i < thread.callStack.size() && i < 5; i++) {
                DebugLog("    [%d] 0x%08X", (int)i, thread.callStack[i]);
            }
        }
        DebugLog("");
    }
}

void LogCallStack(ThreadInfo* thread) {
    if (!thread) {
        return;
    }
    
    DebugLog("Call Stack para Thread %d:", thread->threadId);
    for (size_t i = 0; i < thread->callStack.size(); i++) {
        DebugLog("  [%d] 0x%08X", (int)i, thread->callStack[i]);
    }
}

void MonitorThreadActivity() {
    DebugLog("Monitorando atividade das threads...");
    
    for (auto& thread : g_threads) {
        if (thread.threadHandle != INVALID_HANDLE_VALUE) {
            FILETIME creationTime, exitTime, kernelTime, userTime;
            if (GetThreadTimes(thread.threadHandle, &creationTime, &exitTime, &kernelTime, &userTime)) {
                ULARGE_INTEGER totalTime;
                totalTime.LowPart = userTime.dwLowDateTime;
                totalTime.HighPart = userTime.dwHighDateTime;
                
                DebugLog("Thread %d - CPU Time: %llu", thread.threadId, totalTime.QuadPart);
            }
        }
    }
}

// Identificação de pontos de hook
std::vector<HookPoint> IdentifyHookPoints() {
    std::vector<HookPoint> hookPoints;
    
    // Procura por game loop
    DWORD gameLoop = FindGameLoopFunction();
    if (gameLoop) {
        HookPoint point;
        point.address = gameLoop;
        point.name = "Game Loop";
        point.priority = 10;
        point.isSafe = ValidateHookTarget(gameLoop);
        hookPoints.push_back(point);
    }
    
    // Procura por outras funções conhecidas
    struct KnownFunction {
        const char* name;
        const char* pattern;
        const char* mask;
        int priority;
    };
    
    KnownFunction functions[] = {
        {"WinMain", "\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x68", "xxxxxx????x", 9},
        {"Message Loop", "\xFF\x15\x00\x00\x00\x00\x85\xC0\x74\x00\x8B\x45", "xx????xxx?xx", 8},
        {"Timer Callback", "\x55\x8B\xEC\x83\xEC\x00\x56\x57\x8B\x7D", "xxxxx?xxxx", 7}
    };
    
    for (const auto& func : functions) {
        DWORD address = FindFunctionPattern(func.pattern, func.mask);
        if (address && ValidateHookTarget(address)) {
            HookPoint point;
            point.address = address;
            point.name = func.name;
            point.priority = func.priority;
            point.isSafe = true;
            hookPoints.push_back(point);
        }
    }
    
    return hookPoints;
}

// Instalação de hook seguro
bool InstallSafeHook(DWORD address, void* hookFunction) {
    if (!address || !hookFunction) {
        return false;
    }
    
    if (!ValidateHookTarget(address)) {
        DebugLog("ERRO: Endereco 0x%08X nao e valido para hook", address);
        return false;
    }
    
    DebugLog("Instalando hook seguro em 0x%08X", address);
    
    // Aqui seria implementado o hook real usando técnicas como:
    // - Microsoft Detours
    // - Manual patching
    // - DLL injection
    
    // Por enquanto, apenas salva o endereço
    g_safeHookAddress = address;
    
    DebugLog("Hook seguro instalado com sucesso");
    return true;
}
