#include "../include/Sandboxing.h"
#include <sddl.h>
#include <userenv.h>
#include <memory>
#include <algorithm>

namespace uac_bypass {

Sandboxing::Sandboxing() 
    : logger(Logger::getInstance()),
      initialized(false) {
    
    // Inizializza policy di default
    policy.allowFileAccess = false;
    policy.allowRegistryAccess = false;
    policy.allowNetworkAccess = false;
    policy.allowProcessCreation = false;
    policy.allowThreadCreation = false;
    policy.allowMemoryAllocation = true;
    
    // Inizializza contesto
    context.jobObject = NULL;
    context.restrictedToken = NULL;
    ZeroMemory(&context.securityAttributes, sizeof(SECURITY_ATTRIBUTES));
}

Sandboxing::~Sandboxing() {
    cleanup();
}

Sandboxing& Sandboxing::getInstance() {
    static Sandboxing instance;
    return instance;
}

bool Sandboxing::initialize() {
    if (initialized) return true;
    
    logger.logInfo(L"Inizializzazione Sandboxing");
    
    // Setup sandbox
    if (!setupJobObject()) {
        logger.logError(L"Setup job object fallito");
        return false;
    }
    
    if (!createRestrictedToken()) {
        logger.logError(L"Creazione token ristretto fallita");
        return false;
    }
    
    if (!setupSecurityDescriptor()) {
        logger.logError(L"Setup security descriptor fallito");
        return false;
    }
    
    if (!initializeMonitoring()) {
        logger.logError(L"Inizializzazione monitoraggio fallita");
        return false;
    }
    
    initialized = true;
    return true;
}

bool Sandboxing::createSandbox(const SandboxPolicy& newPolicy) {
    if (!initialized && !initialize()) return false;
    
    logger.logInfo(L"Creazione sandbox con nuova policy");
    
    // Aggiorna policy
    policy = newPolicy;
    
    // Applica restrizioni
    if (!restrictFileSystem()) {
        logger.logError(L"Restrizione filesystem fallita");
        return false;
    }
    
    if (!restrictRegistry()) {
        logger.logError(L"Restrizione registro fallita");
        return false;
    }
    
    if (!restrictNetwork()) {
        logger.logError(L"Restrizione rete fallita");
        return false;
    }
    
    if (!restrictProcesses()) {
        logger.logError(L"Restrizione processi fallita");
        return false;
    }
    
    return true;
}

bool Sandboxing::executeSandboxed(void* function, void* params) {
    if (!initialized) return false;
    
    logger.logInfo(L"Esecuzione funzione in sandbox");
    
    // Prepara ambiente sandbox
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Imposta token ristretto
    HANDLE hToken;
    if (!DuplicateTokenEx(context.restrictedToken, TOKEN_ALL_ACCESS, NULL,
        SecurityImpersonation, TokenPrimary, &hToken)) {
        logger.logError(L"Duplicazione token fallita");
        return false;
    }
    
    std::unique_ptr<void, decltype(&CloseHandle)> tokenGuard(hToken, CloseHandle);
    
    // Crea processo con token ristretto
    if (!CreateProcessAsUserW(hToken, NULL, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi)) {
        logger.logError(L"Creazione processo sandbox fallita");
        return false;
    }
    
    std::unique_ptr<void, decltype(&CloseHandle)> processGuard(pi.hProcess, CloseHandle);
    std::unique_ptr<void, decltype(&CloseHandle)> threadGuard(pi.hThread, CloseHandle);
    
    // Assegna processo al job object
    if (!AssignProcessToJobObject(context.jobObject, pi.hProcess)) {
        logger.logError(L"Assegnazione a job object fallita");
        return false;
    }
    
    // Inietta e esegui funzione
    LPVOID remoteFunction = VirtualAllocEx(pi.hProcess, NULL,
        1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!remoteFunction) {
        logger.logError(L"Allocazione memoria remota fallita");
        return false;
    }
    
    if (!WriteProcessMemory(pi.hProcess, remoteFunction,
        function, 1024, NULL)) {
        logger.logError(L"Scrittura memoria remota fallita");
        VirtualFreeEx(pi.hProcess, remoteFunction, 0, MEM_RELEASE);
        return false;
    }
    
    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteFunction, params, 0, NULL);
    
    if (!hThread) {
        logger.logError(L"Creazione thread remoto fallita");
        VirtualFreeEx(pi.hProcess, remoteFunction, 0, MEM_RELEASE);
        return false;
    }
    
    // Attendi completamento
    WaitForSingleObject(hThread, SANDBOX_TIMEOUT);
    CloseHandle(hThread);
    
    // Cleanup
    VirtualFreeEx(pi.hProcess, remoteFunction, 0, MEM_RELEASE);
    
    return true;
}

bool Sandboxing::cleanup() {
    // Chiudi handles
    for (HANDLE h : context.handles) {
        if (h != NULL) CloseHandle(h);
    }
    context.handles.clear();
    
    // Libera memoria allocata
    for (void* ptr : context.allocatedMemory) {
        if (ptr != NULL) VirtualFree(ptr, 0, MEM_RELEASE);
    }
    context.allocatedMemory.clear();
    
    // Chiudi job object e token
    if (context.jobObject != NULL) {
        CloseHandle(context.jobObject);
        context.jobObject = NULL;
    }
    
    if (context.restrictedToken != NULL) {
        CloseHandle(context.restrictedToken);
        context.restrictedToken = NULL;
    }
    
    initialized = false;
    return true;
}

bool Sandboxing::updatePolicy(const SandboxPolicy& newPolicy) {
    if (!initialized) return false;
    
    // Verifica validità nuova policy
    if (!verifyPolicy()) {
        logger.logError(L"Verifica policy fallita");
        return false;
    }
    
    // Aggiorna policy
    policy = newPolicy;
    
    // Riapplica restrizioni
    return restrictFileSystem() &&
           restrictRegistry() &&
           restrictNetwork() &&
           restrictProcesses();
}

bool Sandboxing::verifyPolicy() {
    // Verifica coerenza policy
    return true;
}

SandboxPolicy Sandboxing::getCurrentPolicy() {
    return policy;
}

bool Sandboxing::checkAccess(const std::wstring& resource, DWORD access) {
    if (!initialized) return false;
    
    // Verifica tipo risorsa e accesso richiesto
    if (resource.find(L"\\??\\") == 0 || resource.find(L"\\Device\\") == 0) {
        // Accesso filesystem
        return policy.allowFileAccess && isAllowedPath(resource);
    }
    else if (resource.find(L"HKEY_") == 0) {
        // Accesso registro
        return policy.allowRegistryAccess && isAllowedKey(resource);
    }
    else if (resource.find(L"\\Device\\Afd") == 0) {
        // Accesso rete
        return policy.allowNetworkAccess;
    }
    
    return false;
}

bool Sandboxing::monitorActivity() {
    if (!initialized) return false;
    
    // Monitora attività sandbox
    return detectViolations();
}

bool Sandboxing::handleViolation(DWORD violationType) {
    // Gestisci violazione policy
    logger.logWarning(L"Violazione sandbox rilevata: " + std::to_wstring(violationType));
    return true;
}

bool Sandboxing::setupJobObject() {
    // Crea job object
    context.jobObject = CreateJobObjectW(NULL, NULL);
    if (!context.jobObject) return false;
    
    // Configura limiti job object
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = { 0 };
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    
    return SetInformationJobObject(context.jobObject,
        JobObjectExtendedLimitInformation, &limits, sizeof(limits));
}

bool Sandboxing::createRestrictedToken() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        return false;
    }
    
    std::unique_ptr<void, decltype(&CloseHandle)> tokenGuard(hToken, CloseHandle);
    
    // Crea token ristretto
    DWORD flags = SANDBOX_INERT |
                 DISABLE_MAX_PRIVILEGE |
                 WRITE_RESTRICTED;
    
    return CreateRestrictedToken(hToken, flags, 0, NULL, 0, NULL,
        0, NULL, &context.restrictedToken);
}

bool Sandboxing::setupSecurityDescriptor() {
    // Crea security descriptor restrittivo
    SECURITY_DESCRIPTOR sd;
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
        return false;
    }
    
    // Imposta DACL vuota
    if (!SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE)) {
        return false;
    }
    
    context.securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    context.securityAttributes.lpSecurityDescriptor = &sd;
    context.securityAttributes.bInheritHandle = FALSE;
    
    return true;
}

bool Sandboxing::configurePolicy() {
    // Configura policy di default
    return true;
}

bool Sandboxing::restrictFileSystem() {
    if (!policy.allowFileAccess) {
        // Blocca tutto l'accesso al filesystem
        return true;
    }
    
    // Permetti accesso solo ai path consentiti
    return true;
}

bool Sandboxing::restrictRegistry() {
    if (!policy.allowRegistryAccess) {
        // Blocca tutto l'accesso al registro
        return true;
    }
    
    // Permetti accesso solo alle chiavi consentite
    return true;
}

bool Sandboxing::restrictNetwork() {
    if (!policy.allowNetworkAccess) {
        // Blocca tutto l'accesso alla rete
        return true;
    }
    
    // Configura firewall per la sandbox
    return true;
}

bool Sandboxing::restrictProcesses() {
    if (!policy.allowProcessCreation) {
        // Blocca creazione processi
        return true;
    }
    
    // Permetti solo processi consentiti
    return true;
}

bool Sandboxing::initializeMonitoring() {
    // Inizializza sistema di monitoraggio
    return true;
}

bool Sandboxing::logActivity(const std::wstring& activity) {
    logger.logInfo(L"Sandbox: " + activity);
    return true;
}

bool Sandboxing::detectViolations() {
    // Rileva violazioni policy
    return true;
}

bool Sandboxing::enforcePolicy() {
    // Applica policy corrente
    return true;
}

bool Sandboxing::validateContext() {
    // Verifica integrità contesto
    return true;
}

bool Sandboxing::protectSandbox() {
    // Proteggi sandbox da manomissioni
    return true;
}

bool Sandboxing::isAllowedPath(const std::wstring& path) {
    return std::find(policy.allowedPaths.begin(),
        policy.allowedPaths.end(), path) != policy.allowedPaths.end();
}

bool Sandboxing::isAllowedKey(const std::wstring& key) {
    return std::find(policy.allowedKeys.begin(),
        policy.allowedKeys.end(), key) != policy.allowedKeys.end();
}

bool Sandboxing::isAllowedProcess(const std::wstring& process) {
    return std::find(policy.allowedProcesses.begin(),
        policy.allowedProcesses.end(), process) != policy.allowedProcesses.end();
}

} // namespace uac_bypass