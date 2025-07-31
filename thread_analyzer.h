#ifndef THREAD_ANALYZER_H
#define THREAD_ANALYZER_H

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <vector>
#include <queue>
#include <memory>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

// Estruturas para dados de thread
struct ThreadInfo {
    DWORD threadId;
    HANDLE threadHandle;
    DWORD startAddress;
    CONTEXT context;
    std::vector<DWORD> callStack;
    bool isMainThread;
    bool isGameLoop;
};

struct HookPoint {
    DWORD address;
    const char* name;
    int priority;
    bool isSafe;
};

struct PacketData {
    char* data;
    int length;
    DWORD timestamp;
};

// Constantes
#define MAX_STACK_FRAMES 64
#define MAX_THREADS 32
#define PACKET_QUEUE_SIZE 1000

// Protótipos das funções principais
bool InitializeThreadAnalyzer();
bool InitializeThreadAnalyzerAsync();
DWORD WINAPI ThreadAnalyzerInitThread(LPVOID lpParam);
void CleanupThreadAnalyzer();

// Enumeração e análise de threads
std::vector<ThreadInfo> EnumerateProcessThreads();
ThreadInfo* FindMainThread();
bool AnalyzeThreadStack(ThreadInfo* thread);
DWORD GetThreadStartAddress(HANDLE threadHandle);

// Detecção de função principal
DWORD FindGameLoopFunction();
std::vector<HookPoint> IdentifyHookPoints();
bool ValidateHookTarget(DWORD address);

// Pattern matching
DWORD FindFunctionPattern(const char* pattern, const char* mask);
bool AnalyzeFunctionPrologue(DWORD address);
DWORD FindPatternInModule(HMODULE module, const char* pattern, const char* mask);

// Hook management
bool InstallSafeHook(DWORD address, void* hookFunction);
bool CreatePacketQueue();
void ProcessQueuedPackets();
void AddPacketToQueue(const char* data, int length);

// Debugging e logging
void DumpThreadInfo();
void LogCallStack(ThreadInfo* thread);
void MonitorThreadActivity();
void DebugLog(const char* format, ...);

// Variáveis globais
extern std::vector<ThreadInfo> g_threads;
extern std::queue<PacketData> g_packetQueue;
extern CRITICAL_SECTION g_queueCS;
extern bool g_analyzerInitialized;
extern DWORD g_mainThreadId;
extern DWORD g_safeHookAddress;

// Callbacks para hooks seguros
typedef void (*SafePacketProcessor)(void);
extern SafePacketProcessor g_packetProcessor;

#endif // THREAD_ANALYZER_H
