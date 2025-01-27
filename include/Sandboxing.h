#ifndef UAC_BYPASS_SANDBOXING_H
#define UAC_BYPASS_SANDBOXING_H

#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"
#include "Config.h"

namespace uac_bypass {

// Struttura per le policy di sandbox
struct SandboxPolicy {
    bool allowFileAccess;
    bool allowRegistryAccess;
    bool allowNetworkAccess;
    bool allowProcessCreation;
    bool allowThreadCreation;
    bool allowMemoryAllocation;
    std::vector<std::wstring> allowedPaths;
    std::vector<std::wstring> allowedKeys;
    std::vector<std::wstring> allowedProcesses;
};

// Struttura per il contesto di esecuzione sandbox
struct SandboxContext {
    HANDLE jobObject;
    HANDLE restrictedToken;
    SECURITY_ATTRIBUTES securityAttributes;
    std::vector<HANDLE> handles;
    std::vector<void*> allocatedMemory;
};

class Sandboxing {
public:
    static Sandboxing& getInstance();
    
    // Metodi principali
    bool initialize();
    bool createSandbox(const SandboxPolicy& policy);
    bool executeSandboxed(void* function, void* params);
    bool cleanup();
    
    // Gestione policy
    bool updatePolicy(const SandboxPolicy& policy);
    bool verifyPolicy();
    SandboxPolicy getCurrentPolicy();
    
    // Controlli runtime
    bool checkAccess(const std::wstring& resource, DWORD access);
    bool monitorActivity();
    bool handleViolation(DWORD violationType);

private:
    Sandboxing();  // Singleton
    ~Sandboxing();
    
    Sandboxing(const Sandboxing&) = delete;
    Sandboxing& operator=(const Sandboxing&) = delete;

    // Inizializzazione sandbox
    bool setupJobObject();
    bool createRestrictedToken();
    bool setupSecurityDescriptor();
    bool configurePolicy();
    
    // Gestione risorse
    bool restrictFileSystem();
    bool restrictRegistry();
    bool restrictNetwork();
    bool restrictProcesses();
    
    // Monitoraggio
    bool initializeMonitoring();
    bool logActivity(const std::wstring& activity);
    bool detectViolations();
    
    // Protezione
    bool enforcePolicy();
    bool validateContext();
    bool protectSandbox();
    
    // Utility
    bool isAllowedPath(const std::wstring& path);
    bool isAllowedKey(const std::wstring& key);
    bool isAllowedProcess(const std::wstring& process);
    
    // Membri
    Logger& logger;
    bool initialized;
    SandboxPolicy policy;
    SandboxContext context;
    
    // Costanti
    static const DWORD SANDBOX_TIMEOUT = 30000;  // 30 secondi
    static const size_t MAX_HANDLES = 1000;
    static const size_t MAX_MEMORY = 100 * 1024 * 1024;  // 100 MB
};

// Macro per esecuzione in sandbox
#define EXECUTE_SANDBOXED(func, params) \
    Sandboxing::getInstance().executeSandboxed((void*)func, (void*)params)

// Macro per verifica accesso
#define CHECK_SANDBOX_ACCESS(resource, access) \
    Sandboxing::getInstance().checkAccess(resource, access)

} // namespace uac_bypass

#endif // UAC_BYPASS_SANDBOXING_H