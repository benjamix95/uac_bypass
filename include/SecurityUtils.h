#ifndef UAC_BYPASS_SECURITY_UTILS_H
#define UAC_BYPASS_SECURITY_UTILS_H

#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"
#include "Config.h"

namespace uac_bypass {

class SecurityUtils {
public:
    static SecurityUtils& getInstance();
    
    // Verifica firma e integrità
    bool verifyFileSignature(const std::wstring& filePath);
    bool verifyFileHash(const std::wstring& filePath, const std::wstring& expectedHash);
    
    // Anti-Debug e Detection Evasion
    bool isBeingDebugged();
    bool isRunningInVM();
    bool isSandboxDetected();
    
    // Memory Protection
    bool protectMemoryRegion(LPVOID address, SIZE_T size);
    bool hideFromMemoryScanners();
    
    // Process Protection
    bool preventProcessDump();
    bool enableDynamicCodePolicy();
    
    // Evasion Techniques
    bool implementProcessHollowing(const std::wstring& targetProcess);
    bool implementThreadManipulation();
    bool hideThreads();
    
    // System Checks
    bool checkSystemSecurity();
    bool verifySystemIntegrity();
    
private:
    SecurityUtils();  // Singleton
    ~SecurityUtils();
    
    SecurityUtils(const SecurityUtils&) = delete;
    SecurityUtils& operator=(const SecurityUtils&) = delete;
    
    // Metodi interni
    bool calculateFileHash(const std::wstring& filePath, std::vector<BYTE>& hash);
    bool verifyCertificateChain(PCCERT_CONTEXT pCertContext);
    bool checkSecurityProducts();
    bool checkEmulationArtifacts();
    
    // Anti-Analysis
    bool detectTimingAnomalies();
    bool checkHardwareBreakpoints();
    bool checkSoftwareBreakpoints();
    
    // Memory Management
    bool protectSensitiveData();
    bool implementMemoryEncryption();
    bool secureMemoryPages();
    
    // Evasion Helpers
    bool modifyPEB();
    bool hideProcessInformation();
    bool manipulateTimers();
    
    // Membri
    Logger& logger;
    bool initialized;
    std::vector<LPVOID> protectedRegions;
    
    // Costanti
    static const DWORD TIMING_THRESHOLD = 1000; // millisecondi
    static const SIZE_T MIN_MEMORY_REGION = 4096; // bytes
};

// Struttura per informazioni di sicurezza
struct SecurityInfo {
    bool isDebuggerPresent;
    bool isVirtualMachine;
    bool isSandboxed;
    bool isMemoryScanned;
    bool isBeingAnalyzed;
    std::vector<std::wstring> detectedThreats;
};

// Macro per controlli di sicurezza
#define SECURITY_CHECK(condition, message) \
    if (!(condition)) { \
        logger.logSecurityEvent(message, false); \
        return false; \
    }

// Macro per protezione memoria
#define PROTECT_MEMORY(address, size) \
    SecurityUtils::getInstance().protectMemoryRegion((LPVOID)(address), (SIZE_T)(size))

// Macro per verifica integrità
#define VERIFY_INTEGRITY(file, hash) \
    SecurityUtils::getInstance().verifyFileHash(file, hash)

} // namespace uac_bypass

#endif // UAC_BYPASS_SECURITY_UTILS_H