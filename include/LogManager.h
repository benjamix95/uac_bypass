#ifndef UAC_BYPASS_LOG_MANAGER_H
#define UAC_BYPASS_LOG_MANAGER_H

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <fstream>
#include <memory>
#include "Logger.h"

namespace uac_bypass {

// Livelli di log
enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARNING,
    ERR,
    CRITICAL
};

// Struttura per le entry di log
struct LogEntry {
    LogLevel level;
    std::wstring message;
    std::wstring component;
    std::wstring function;
    std::wstring timestamp;
    DWORD threadId;
    DWORD processId;
};

// Configurazione logger
struct LogConfig {
    std::wstring logFile;
    LogLevel minLevel;
    size_t maxFileSize;
    size_t maxFiles;
    bool enableConsole;
    bool enableFileLogging;
    bool enableRotation;
    bool enableCompression;
};

class LogManager {
public:
    static LogManager& getInstance();
    
    // Configurazione
    bool initialize(const LogConfig& config);
    void setLogLevel(LogLevel level);
    void setLogFile(const std::wstring& path);
    void enableConsoleOutput(bool enable);
    
    // Logging
    void log(LogLevel level, const std::wstring& message);
    void logWithContext(LogLevel level, 
                       const std::wstring& message,
                       const std::wstring& component,
                       const std::wstring& function);
    
    // Utility
    void flush();
    void rotate();
    void compress();
    void cleanup();
    
    // Analisi
    std::vector<LogEntry> getRecentEntries(size_t count);
    std::vector<LogEntry> getEntriesByLevel(LogLevel level);
    std::vector<LogEntry> getEntriesByComponent(const std::wstring& component);
    
    // Filtri
    void addFilter(const std::wstring& pattern);
    void removeFilter(const std::wstring& pattern);
    void clearFilters();

private:
    LogManager();  // Singleton
    ~LogManager();
    
    LogManager(const LogManager&) = delete;
    LogManager& operator=(const LogManager&) = delete;

    // Funzioni interne
    bool openLogFile();
    void closeLogFile();
    bool writeToFile(const std::wstring& message);
    bool writeToConsole(const std::wstring& message);
    std::wstring formatLogMessage(const LogEntry& entry);
    bool shouldLog(const LogEntry& entry);
    void rotateIfNeeded();
    
    // Gestione file
    bool archiveCurrentLog();
    void pruneOldLogs();
    size_t getCurrentFileSize();
    std::wstring generateTimestamp();
    
    // Thread safety
    void lockLog();
    void unlockLog();
    
    // Membri
    LogConfig config;
    std::wofstream logFile;
    std::vector<std::wstring> filters;
    std::vector<LogEntry> recentEntries;
    std::mutex logMutex;
    bool initialized;
    
    // Cache
    std::map<LogLevel, std::wstring> levelStrings;
    std::wstring processName;
    
    // Costanti
    static const size_t MAX_RECENT_ENTRIES = 1000;
    static const size_t DEFAULT_BUFFER_SIZE = 8192;
    static const size_t MAX_MESSAGE_LENGTH = 4096;
    
    // Formattazione
    static const wchar_t* LEVEL_STRINGS[];
    static const wchar_t* DATE_FORMAT;
    static const wchar_t* LOG_EXTENSION;
};

// Macro per logging
#define LOG_TRACE(msg) \
    LogManager::getInstance().log(LogLevel::TRACE, msg)

#define LOG_DEBUG(msg) \
    LogManager::getInstance().log(LogLevel::DEBUG, msg)

#define LOG_INFO(msg) \
    LogManager::getInstance().log(LogLevel::INFO, msg)

#define LOG_WARNING(msg) \
    LogManager::getInstance().log(LogLevel::WARNING, msg)

#define LOG_ERROR(msg) \
    LogManager::getInstance().log(LogLevel::ERR, msg)

#define LOG_CRITICAL(msg) \
    LogManager::getInstance().log(LogLevel::CRITICAL, msg)

#define LOG_WITH_CONTEXT(level, msg, component, function) \
    LogManager::getInstance().logWithContext(level, msg, component, function)

} // namespace uac_bypass

#endif // UAC_BYPASS_LOG_MANAGER_H