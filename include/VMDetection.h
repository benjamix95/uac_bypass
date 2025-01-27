#ifndef UAC_BYPASS_VM_DETECTION_H
#define UAC_BYPASS_VM_DETECTION_H

#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"
#include "Config.h"

namespace uac_bypass {

// Enumerazione dei tipi di VM supportati
enum class VMType {
    VMWARE,
    VIRTUALBOX,
    HYPER_V,
    QEMU,
    XEN,
    PARALLELS,
    UNKNOWN
};

// Struttura per i dettagli della VM
struct VMDetails {
    VMType type;
    std::wstring vendor;
    std::wstring version;
    bool isNested;
    bool hasDebugger;
};

class VMDetection {
public:
    static VMDetection& getInstance();
    
    // Metodi principali
    bool initialize();
    bool isRunningInVM();
    VMDetails getVMDetails();
    
    // Metodi di detection
    bool checkHardware();
    bool checkRegistry();
    bool checkProcesses();
    bool checkServices();
    bool checkDevices();
    bool checkArtifacts();
    
    // Metodi di evasion
    bool hideFromVM();
    bool modifyBehavior();
    bool fakeEnvironment();
    
private:
    VMDetection();  // Singleton
    ~VMDetection();
    
    VMDetection(const VMDetection&) = delete;
    VMDetection& operator=(const VMDetection&) = delete;

    // Metodi di detection specifici
    bool detectVMWare();
    bool detectVirtualBox();
    bool detectHyperV();
    bool detectQEMU();
    bool detectXen();
    bool detectParallels();
    
    // Metodi di analisi hardware
    bool checkCPUID();
    bool checkMSR();
    bool checkTSC();
    bool checkIDT();
    bool checkLDT();
    bool checkGDT();
    bool checkMAC();
    
    // Metodi di analisi software
    bool checkDrivers();
    bool checkDLLs();
    bool checkMemory();
    bool checkTiming();
    
    // Metodi di evasion specifici
    bool modifyTimings();
    bool hideProcesses();
    bool fakeHardware();
    bool spoofCPUID();
    
    // Metodi di utility
    bool isKnownVMProcess(const std::wstring& processName);
    bool isKnownVMService(const std::wstring& serviceName);
    bool isKnownVMDriver(const std::wstring& driverName);
    bool isKnownVMRegistry(const std::wstring& registryPath);
    
    // Membri
    Logger& logger;
    bool initialized;
    VMDetails currentVM;
    std::vector<std::wstring> detectedArtifacts;
    
    // Costanti per detection
    static const DWORD VM_CHECK_TIMEOUT;
    static const DWORD TIMING_ITERATIONS;
    static const double TIMING_THRESHOLD;
    
    // Liste di artefatti noti
    static const std::vector<std::wstring> VM_PROCESSES;
    static const std::vector<std::wstring> VM_SERVICES;
    static const std::vector<std::wstring> VM_DRIVERS;
    static const std::vector<std::wstring> VM_REGISTRY_KEYS;
};

// Macro per controlli VM
#define CHECK_VM() \
    VMDetection::getInstance().isRunningInVM()

// Macro per evasion
#define EVADE_VM() \
    VMDetection::getInstance().hideFromVM()

} // namespace uac_bypass

#endif // UAC_BYPASS_VM_DETECTION_H