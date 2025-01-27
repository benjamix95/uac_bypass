#include "../include/LogManager.h"
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <algorithm>

namespace uac_bypass {

const wchar_t* LogManager::LEVEL_STRINGS[] = {
    L"TRACE",
    L"DEBUG",
    L"INFO",
    L"WARNING",
    L"ERR",
    L"CRITICAL"
};

const wchar_t* LogManager::DATE_FORMAT = L"%Y-%m-%d %H:%M:%S";
const wchar_t* LogManager::LOG_EXTENSION = L".log";

LogManager::LogManager() : initialized(false) {
    // Inizializza cache level strings
    levelStrings[LogLevel::TRACE] = L"TRACE";
    levelStrings[LogLevel::DEBUG] = L"DEBUG";
    levelStrings[LogLevel::INFO] = L"INFO";
    levelStrings[LogLevel::WARNING] = L"WARNING";
    levelStrings[LogLevel::ERR] = L"ERROR";
    levelStrings[LogLevel::CRITICAL] = L"CRITICAL";
    
    // Ottieni nome processo
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    processName = std::filesystem::path(buffer).filename().wstring();
}

LogManager::~LogManager() {
    cleanup();
}

LogManager& LogManager::getInstance() {
    static LogManager instance;
    return instance;
}

bool LogManager::initialize(const LogConfig& config) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    this->config = config;
    
    if (config.enableFileLogging) {
        if (!openLogFile()) {
            return false;
        }
    }
    
    initialized = true;
    
    LOG_INFO(L"Log Manager initialized");
    return true;
}

void LogManager::setLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(logMutex);
    config.minLevel = level;
}

void LogManager::setLogFile(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    closeLogFile();
    config.logFile = path;
    
    if (config.enableFileLogging) {
        openLogFile();
    }
}

void LogManager::enableConsoleOutput(bool enable) {
    std::lock_guard<std::mutex> lock(logMutex);
    config.enableConsole = enable;
}

void LogManager::log(LogLevel level, const std::wstring& message) {
    logWithContext(level, message, L"", L"");
}

void LogManager::logWithContext(LogLevel level,
                              const std::wstring& message,
                              const std::wstring& component,
                              const std::wstring& function) {
    if (!initialized || level < config.minLevel) {
        return;
    }
    
    LogEntry entry{
        level,
        message,
        component,
        function,
        generateTimestamp(),
        GetCurrentThreadId(),
        GetCurrentProcessId()
    };
    
    if (!shouldLog(entry)) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(logMutex);
    
    // Aggiungi a entries recenti
    if (recentEntries.size() >= MAX_RECENT_ENTRIES) {
        recentEntries.erase(recentEntries.begin());
    }
    recentEntries.push_back(entry);
    
    // Formatta messaggio
    std::wstring formattedMessage = formatLogMessage(entry);
    
    // Scrivi su file
    if (config.enableFileLogging) {
        writeToFile(formattedMessage);
    }
    
    // Scrivi su console
    if (config.enableConsole) {
        writeToConsole(formattedMessage);
    }
    
    // Ruota log se necessario
    rotateIfNeeded();
}

void LogManager::flush() {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (logFile.is_open()) {
        logFile.flush();
    }
}

void LogManager::rotate() {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (!config.enableRotation || !logFile.is_open()) {
        return;
    }
    
    closeLogFile();
    archiveCurrentLog();
    openLogFile();
    pruneOldLogs();
}

void LogManager::compress() {
    // TODO: Implementa compressione log
}

void LogManager::cleanup() {
    std::lock_guard<std::mutex> lock(logMutex);
    
    closeLogFile();
    recentEntries.clear();
    filters.clear();
}

std::vector<LogEntry> LogManager::getRecentEntries(size_t count) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (count >= recentEntries.size()) {
        return recentEntries;
    }
    
    return std::vector<LogEntry>(
        recentEntries.end() - count,
        recentEntries.end()
    );
}

std::vector<LogEntry> LogManager::getEntriesByLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::vector<LogEntry> result;
    std::copy_if(recentEntries.begin(), recentEntries.end(),
        std::back_inserter(result),
        [level](const LogEntry& entry) {
            return entry.level == level;
        });
    
    return result;
}

std::vector<LogEntry> LogManager::getEntriesByComponent(
    const std::wstring& component) {
    
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::vector<LogEntry> result;
    std::copy_if(recentEntries.begin(), recentEntries.end(),
        std::back_inserter(result),
        [&component](const LogEntry& entry) {
            return entry.component == component;
        });
    
    return result;
}

void LogManager::addFilter(const std::wstring& pattern) {
    std::lock_guard<std::mutex> lock(logMutex);
    filters.push_back(pattern);
}

void LogManager::removeFilter(const std::wstring& pattern) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    filters.erase(
        std::remove(filters.begin(), filters.end(), pattern),
        filters.end()
    );
}

void LogManager::clearFilters() {
    std::lock_guard<std::mutex> lock(logMutex);
    filters.clear();
}

bool LogManager::openLogFile() {
    logFile.open(config.logFile,
        std::ios::out | std::ios::app | std::ios::binary);
    
    return logFile.is_open();
}

void LogManager::closeLogFile() {
    if (logFile.is_open()) {
        logFile.close();
    }
}

bool LogManager::writeToFile(const std::wstring& message) {
    if (!logFile.is_open()) {
        return false;
    }
    
    logFile << message << std::endl;
    return !logFile.fail();
}

bool LogManager::writeToConsole(const std::wstring& message) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    DWORD written;
    return WriteConsoleW(hConsole, message.c_str(),
        static_cast<DWORD>(message.length()), &written, NULL) != 0;
}

std::wstring LogManager::formatLogMessage(const LogEntry& entry) {
    std::wstringstream ss;
    
    // Timestamp
    ss << L"[" << entry.timestamp << L"] ";
    
    // Level
    ss << L"[" << levelStrings[entry.level] << L"] ";
    
    // Process/Thread
    ss << L"[" << processName << L":" 
       << entry.processId << L":" 
       << entry.threadId << L"] ";
    
    // Component/Function
    if (!entry.component.empty()) {
        ss << L"[" << entry.component;
        if (!entry.function.empty()) {
            ss << L"::" << entry.function;
        }
        ss << L"] ";
    }
    
    // Message
    ss << entry.message;
    
    return ss.str();
}

bool LogManager::shouldLog(const LogEntry& entry) {
    if (filters.empty()) {
        return true;
    }
    
    std::wstring fullMessage = formatLogMessage(entry);
    
    return std::none_of(filters.begin(), filters.end(),
        [&fullMessage](const std::wstring& pattern) {
            return fullMessage.find(pattern) != std::wstring::npos;
        });
}

void LogManager::rotateIfNeeded() {
    if (!config.enableRotation) {
        return;
    }
    
    if (getCurrentFileSize() >= config.maxFileSize) {
        rotate();
    }
}

bool LogManager::archiveCurrentLog() {
    if (!std::filesystem::exists(config.logFile)) {
        return true;
    }
    
    std::wstring timestamp = generateTimestamp();
    std::wstring archivePath = config.logFile + L"." + timestamp;
    
    try {
        std::filesystem::rename(config.logFile, archivePath);
        
        if (config.enableCompression) {
            compress();
        }
        
        return true;
    }
    catch (const std::filesystem::filesystem_error&) {
        return false;
    }
}

void LogManager::pruneOldLogs() {
    if (config.maxFiles == 0) {
        return;
    }
    
    std::wstring logDir = std::filesystem::path(config.logFile)
        .parent_path().wstring();
    std::wstring logName = std::filesystem::path(config.logFile)
        .filename().wstring();
    
    std::vector<std::filesystem::path> logFiles;
    
    for (const auto& entry :
         std::filesystem::directory_iterator(logDir)) {
        if (entry.path().filename().wstring().find(logName) == 0) {
            logFiles.push_back(entry.path());
        }
    }
    
    if (logFiles.size() <= config.maxFiles) {
        return;
    }
    
    std::sort(logFiles.begin(), logFiles.end());
    
    for (size_t i = 0; i < logFiles.size() - config.maxFiles; ++i) {
        std::filesystem::remove(logFiles[i]);
    }
}

size_t LogManager::getCurrentFileSize() {
    if (!logFile.is_open()) {
        return 0;
    }
    
    return static_cast<size_t>(logFile.tellp());
}

std::wstring LogManager::generateTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::wstringstream ss;
    ss << std::put_time(std::localtime(&time), DATE_FORMAT);
    
    return ss.str();
}

void LogManager::lockLog() {
    logMutex.lock();
}

void LogManager::unlockLog() {
    logMutex.unlock();
}

} // namespace uac_bypass
