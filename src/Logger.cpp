#include "../include/Logger.h"
#include <iomanip>
#include <sstream>
#include <ctime>

namespace uac_bypass {

Logger::Logger() : initialized(false) {
    InitializeCriticalSection(&logMutex);
    
    logFile.open(LOG_FILE, std::ios::app | std::ios::out);
    if (logFile.is_open()) {
        initialized = true;
        logInfo(L"=== Logger inizializzato ===");
    }
}

Logger::~Logger() {
    if (initialized) {
        logInfo(L"=== Logger terminato ===");
        logFile.close();
    }
    DeleteCriticalSection(&logMutex);
}

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::logInfo(const std::wstring& message) {
    writeToLog(L"INFO", message);
}

void Logger::logWarning(const std::wstring& message) {
    writeToLog(L"WARNING", message);
}

void Logger::logError(const std::wstring& message) {
    writeToLog(L"ERROR", message);
}

void Logger::logDebug(const std::wstring& message) {
#if ENABLE_LOGGING
    writeToLog(L"DEBUG", message);
#endif
}

void Logger::logSecurityEvent(const std::wstring& event, bool success) {
    std::wstringstream ss;
    ss << L"Security Event: " << event << L" - Status: " 
       << (success ? L"Success" : L"Failed");
    writeToLog(L"SECURITY", ss.str());
}

void Logger::logProcessOperation(DWORD processId, const std::wstring& operation) {
    std::wstringstream ss;
    ss << L"Process Operation [PID: " << processId << L"]: " << operation;
    writeToLog(L"PROCESS", ss.str());
}

void Logger::logRegistryAccess(const std::wstring& regPath, const std::wstring& operation) {
    std::wstringstream ss;
    ss << L"Registry Access [" << regPath << L"]: " << operation;
    writeToLog(L"REGISTRY", ss.str());
}

void Logger::writeToLog(const std::wstring& level, const std::wstring& message) {
    if (!initialized) return;

    EnterCriticalSection(&logMutex);
    
    try {
        logFile << getCurrentTimestamp() << L" ["
                << std::setw(8) << std::left << level << L"] "
                << message << std::endl;
        logFile.flush();
    }
    catch (...) {
        // Gestione minima degli errori per evitare crash
    }
    
    LeaveCriticalSection(&logMutex);
}

std::wstring Logger::getCurrentTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    std::wstringstream ss;
    ss << std::setfill(L'0')
       << std::setw(4) << st.wYear << L"-"
       << std::setw(2) << st.wMonth << L"-"
       << std::setw(2) << st.wDay << L" "
       << std::setw(2) << st.wHour << L":"
       << std::setw(2) << st.wMinute << L":"
       << std::setw(2) << st.wSecond << L"."
       << std::setw(3) << st.wMilliseconds;
    
    return ss.str();
}

} // namespace uac_bypass