#ifndef UAC_BYPASS_LOGGER_H
#define UAC_BYPASS_LOGGER_H

#include <string>
#include <fstream>
#include <windows.h>
#include "Config.h"

namespace uac_bypass {

class Logger {
public:
    static Logger& getInstance();
    
    void logInfo(const std::wstring& message);
    void logWarning(const std::wstring& message);
    void logError(const std::wstring& message);
    void logDebug(const std::wstring& message);
    
    // Logging specifico per operazioni sensibili
    void logSecurityEvent(const std::wstring& event, bool success);
    void logProcessOperation(DWORD processId, const std::wstring& operation);
    void logRegistryAccess(const std::wstring& regPath, const std::wstring& operation);

private:
    Logger();  // Singleton
    ~Logger();
    
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    void writeToLog(const std::wstring& level, const std::wstring& message);
    std::wstring getCurrentTimestamp();
    
    std::wofstream logFile;
    CRITICAL_SECTION logMutex;  // Thread safety
    bool initialized;
};

} // namespace uac_bypass

#endif // UAC_BYPASS_LOGGER_H