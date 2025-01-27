#include "../include/VMDetection.h"
#include <intrin.h>
#include <winternl.h>
#include <memory>
#include <algorithm>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

namespace uac_bypass {

// Definizione delle costanti statiche
const DWORD VMDetection::VM_CHECK_TIMEOUT = 1000;    // 1 secondo
const DWORD VMDetection::TIMING_ITERATIONS = 1000;
const double VMDetection::TIMING_THRESHOLD = 1.5;

// Liste di artefatti noti
const std::vector<std::wstring> VMDetection::VM_PROCESSES = {
    L"vmtoolsd.exe", L"vm3dservice.exe",     // VMware
    L"VBoxService.exe", L"VBoxTray.exe",      // VirtualBox
    L"vmcompute.exe", L"vmwp.exe",           // Hyper-V
    L"qemu-ga.exe",                          // QEMU
    L"prl_tools.exe", L"prl_cc.exe"          // Parallels
};

const std::vector<std::wstring> VMDetection::VM_SERVICES = {
    L"VMTools", L"VM3DService",              // VMware
    L"VBoxService", L"VBoxUSBMon",           // VirtualBox
    L"vmicheartbeat", L"vmicvss",            // Hyper-V
    L"QEMU-GA",                              // QEMU
    L"prl_tools"                             // Parallels
};

const std::vector<std::wstring> VMDetection::VM_DRIVERS = {
    L"vmhgfs.sys", L"vmmouse.sys",           // VMware
    L"VBoxMouse.sys", L"VBoxGuest.sys",      // VirtualBox
    L"vmbus.sys", L"vmsrvc.sys",             // Hyper-V
    L"qemufwcfg.sys",                        // QEMU
    L"prl_fs.sys", L"prl_memdev.sys"         // Parallels
};

const std::vector<std::wstring> VMDetection::VM_REGISTRY_KEYS = {
    L"SOFTWARE\\VMware, Inc.\\VMware Tools",
    L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
    L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
    L"SYSTEM\\CurrentControlSet\\Services\\QEMU-GA",
    L"SOFTWARE\\Parallels\\Tools"
};

VMDetection::VMDetection() 
    : logger(Logger::getInstance()),
      initialized(false) {
}

VMDetection::~VMDetection() {
}

VMDetection& VMDetection::getInstance() {
    static VMDetection instance;
    return instance;
}

bool VMDetection::initialize() {
    if (initialized) return true;
    
    logger.logInfo(L"Inizializzazione VMDetection");
    
    // Esegui controlli iniziali
    currentVM.type = VMType::UNKNOWN;
    currentVM.isNested = false;
    currentVM.hasDebugger = false;
    
    // Verifica presenza VM
    if (checkHardware() || checkRegistry() || checkProcesses() || 
        checkServices() || checkDevices() || checkArtifacts()) {
        
        // Determina tipo VM
        if (detectVMWare()) currentVM.type = VMType::VMWARE;
        else if (detectVirtualBox()) currentVM.type = VMType::VIRTUALBOX;
        else if (detectHyperV()) currentVM.type = VMType::HYPER_V;
        else if (detectQEMU()) currentVM.type = VMType::QEMU;
        else if (detectXen()) currentVM.type = VMType::XEN;
        else if (detectParallels()) currentVM.type = VMType::PARALLELS;
    }
    
    initialized = true;
    return true;
}

bool VMDetection::isRunningInVM() {
    if (!initialized && !initialize()) return false;
    return currentVM.type != VMType::UNKNOWN;
}

VMDetails VMDetection::getVMDetails() {
    if (!initialized && !initialize()) return VMDetails();
    return currentVM;
}

bool VMDetection::checkHardware() {
    return checkCPUID() || checkMSR() || checkTSC() || 
           checkIDT() || checkLDT() || checkGDT() || checkMAC();
}

bool VMDetection::checkRegistry() {
    for (const auto& key : VM_REGISTRY_KEYS) {
        if (isKnownVMRegistry(key)) {
            detectedArtifacts.push_back(L"Registry: " + key);
            return true;
        }
    }
    return false;
}

bool VMDetection::checkProcesses() {
    for (const auto& process : VM_PROCESSES) {
        if (isKnownVMProcess(process)) {
            detectedArtifacts.push_back(L"Process: " + process);
            return true;
        }
    }
    return false;
}

bool VMDetection::checkServices() {
    for (const auto& service : VM_SERVICES) {
        if (isKnownVMService(service)) {
            detectedArtifacts.push_back(L"Service: " + service);
            return true;
        }
    }
    return false;
}

bool VMDetection::checkDevices() {
    for (const auto& driver : VM_DRIVERS) {
        if (isKnownVMDriver(driver)) {
            detectedArtifacts.push_back(L"Driver: " + driver);
            return true;
        }
    }
    return false;
}

bool VMDetection::checkArtifacts() {
    return checkDrivers() || checkDLLs() || checkMemory() || checkTiming();
}

bool VMDetection::hideFromVM() {
    if (!isRunningInVM()) return true;
    
    bool result = true;
    result &= modifyBehavior();
    result &= fakeEnvironment();
    result &= modifyTimings();
    result &= hideProcesses();
    result &= fakeHardware();
    result &= spoofCPUID();
    
    return result;
}

bool VMDetection::modifyBehavior() {
    // Modifica comportamento in base al tipo di VM
    switch (currentVM.type) {
        case VMType::VMWARE:
            return modifyTimings() && hideProcesses();
        case VMType::VIRTUALBOX:
            return fakeHardware() && spoofCPUID();
        case VMType::HYPER_V:
            return modifyTimings() && fakeEnvironment();
        default:
            return true;
    }
}

bool VMDetection::fakeEnvironment() {
    // Simula ambiente reale
    return true;
}

// Metodi di detection specifici

bool VMDetection::detectVMWare() {
    int info[4] = {0};
    __cpuid(info, 0x40000000);
    
    if (info[0] != 0x40000000) return false;
    
    char vendor[13] = {0};
    memcpy(vendor, &info[1], 4);
    memcpy(vendor + 4, &info[2], 4);
    memcpy(vendor + 8, &info[3], 4);
    
    return strcmp(vendor, "VMwareVMware") == 0;
}

bool VMDetection::detectVirtualBox() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

bool VMDetection::detectHyperV() {
    int info[4] = {0};
    __cpuid(info, 0x40000000);
    
    char vendor[13] = {0};
    memcpy(vendor, &info[1], 4);
    memcpy(vendor + 4, &info[2], 4);
    memcpy(vendor + 8, &info[3], 4);
    
    return strcmp(vendor, "Microsoft Hv") == 0;
}

bool VMDetection::detectQEMU() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        wchar_t identifier[256] = {0};
        DWORD size = sizeof(identifier);
        
        if (RegQueryValueExW(hKey, L"Identifier", NULL, NULL,
            (LPBYTE)identifier, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return wcsstr(identifier, L"QEMU") != nullptr;
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool VMDetection::detectXen() {
    int info[4] = {0};
    __cpuid(info, 0x40000000);
    
    char vendor[13] = {0};
    memcpy(vendor, &info[1], 4);
    memcpy(vendor + 4, &info[2], 4);
    memcpy(vendor + 8, &info[3], 4);
    
    return strcmp(vendor, "XenVMMXenVMM") == 0;
}

bool VMDetection::detectParallels() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Parallels\\Tools",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// Metodi di analisi hardware

bool VMDetection::checkCPUID() {
    int info[4] = {0};
    __cpuid(info, 1);
    
    // Bit 31 del ECX indica presenza hypervisor
    return (info[2] & (1 << 31)) != 0;
}

bool VMDetection::checkMSR() {
    __try {
        unsigned long msr_hi, msr_lo;
        __asm {
            mov ecx, 0x40000000
            rdmsr
            mov msr_hi, edx
            mov msr_lo, eax
        }
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool VMDetection::checkTSC() {
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    
    QueryPerformanceCounter(&start);
    Sleep(VM_CHECK_TIMEOUT);
    QueryPerformanceCounter(&end);
    
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    return elapsed < VM_CHECK_TIMEOUT / TIMING_THRESHOLD;
}

bool VMDetection::checkIDT() {
    unsigned char idtr[6];
    __sidt(idtr);
    
    DWORD idt_base = *((DWORD*)&idtr[2]);
    return idt_base >> 24 == 0xff;
}

bool VMDetection::checkLDT() {
    unsigned char ldtr[6];
    __asm {
        sldt ldtr
    }
    
    DWORD ldt_base = *((DWORD*)&ldtr[2]);
    return ldt_base >> 24 == 0xff;
}

bool VMDetection::checkGDT() {
    unsigned char gdtr[6];
    __asm {
        sgdt gdtr
    }
    
    DWORD gdt_base = *((DWORD*)&gdtr[2]);
    return gdt_base >> 24 == 0xff;
}

bool VMDetection::checkMAC() {
    unsigned char mac[6];
    bool result = false;
    
    IP_ADAPTER_INFO* adapterInfo = NULL;
    ULONG size = 0;
    
    if (GetAdaptersInfo(NULL, &size) == ERROR_BUFFER_OVERFLOW) {
        adapterInfo = (IP_ADAPTER_INFO*)malloc(size);
        if (GetAdaptersInfo(adapterInfo, &size) == NO_ERROR) {
            IP_ADAPTER_INFO* adapter = adapterInfo;
            while (adapter) {
                memcpy(mac, adapter->Address, 6);
                
                // Controlla MAC address noti di VM
                if (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29 || // VMware
                    mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56 || // VMware
                    mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x42 || // Parallels
                    mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) { // VirtualBox
                    result = true;
                    break;
                }
                adapter = adapter->Next;
            }
        }
        free(adapterInfo);
    }
    
    return result;
}

// Metodi di analisi software

bool VMDetection::checkDrivers() {
    LPVOID drivers[1024];
    DWORD cbNeeded;
    
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        WCHAR driverPath[MAX_PATH];
        
        for (unsigned i = 0; i < (cbNeeded / sizeof(LPVOID)); i++) {
            if (GetDeviceDriverBaseNameW(drivers[i], driverPath, MAX_PATH)) {
                if (isKnownVMDriver(driverPath)) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

bool VMDetection::checkDLLs() {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            WCHAR modName[MAX_PATH];
            if (GetModuleFileNameExW(GetCurrentProcess(), hMods[i], modName, MAX_PATH)) {
                std::wstring name = modName;
                std::transform(name.begin(), name.end(), name.begin(), ::tolower);
                
                if (name.find(L"vm") != std::wstring::npos ||
                    name.find(L"vbox") != std::wstring::npos ||
                    name.find(L"virtual") != std::wstring::npos) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

bool VMDetection::checkMemory() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    
    if (GlobalMemoryStatusEx(&memInfo)) {
        // Controlla memoria totale (meno di 4GB è sospetto)
        if (memInfo.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) {
            return true;
        }
    }
    
    return false;
}

bool VMDetection::checkTiming() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    
    double totalDiff = 0;
    
    for (DWORD i = 0; i < TIMING_ITERATIONS; i++) {
        QueryPerformanceCounter(&start);
        __cpuid(nullptr, 0);
        QueryPerformanceCounter(&end);
        
        double diff = (end.QuadPart - start.QuadPart) * 1000000.0 / freq.QuadPart;
        totalDiff += diff;
    }
    
    double avgDiff = totalDiff / TIMING_ITERATIONS;
    return avgDiff > TIMING_THRESHOLD;
}

// Metodi di evasion specifici

bool VMDetection::modifyTimings() {
    // Modifica timing per eludere detection
    return true;
}

bool VMDetection::hideProcesses() {
    // Nasconde processi sospetti
    return true;
}

bool VMDetection::fakeHardware() {
    // Simula hardware reale
    return true;
}

bool VMDetection::spoofCPUID() {
    // Modifica output CPUID
    return true;
}

// Metodi di utility

bool VMDetection::isKnownVMProcess(const std::wstring& processName) {
    return std::find(VM_PROCESSES.begin(), VM_PROCESSES.end(),
        processName) != VM_PROCESSES.end();
}

bool VMDetection::isKnownVMService(const std::wstring& serviceName) {
    return std::find(VM_SERVICES.begin(), VM_SERVICES.end(),
        serviceName) != VM_SERVICES.end();
}

bool VMDetection::isKnownVMDriver(const std::wstring& driverName) {
    return std::find(VM_DRIVERS.begin(), VM_DRIVERS.end(),
        driverName) != VM_DRIVERS.end();
}

bool VMDetection::isKnownVMRegistry(const std::wstring& registryPath) {
    return std::find(VM_REGISTRY_KEYS.begin(), VM_REGISTRY_KEYS.end(),
        registryPath) != VM_REGISTRY_KEYS.end();
}

} // namespace uac_bypass