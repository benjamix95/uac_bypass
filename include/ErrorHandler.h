#ifndef UAC_BYPASS_ERROR_HANDLER_H
#define UAC_BYPASS_ERROR_HANDLER_H

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include "Logger.h"

namespace uac_bypass {

// Codici di errore personalizzati
enum class ErrorCode {
    SUCCESS = 0,
    INITIALIZATION_FAILED,
    VIRTUALIZATION_ERROR,
    BYPASS_FAILED,
    TOKEN_ERROR,
    PIPE_ERROR,
    RPC_ERROR,
    SERVICE_ERROR,
    SECURITY_ERROR,
    MEMORY_ERROR,
    PERMISSION_DENIED,
    INVALID_PARAMETER,
    SYSTEM_ERROR,
    UNKNOWN_ERROR
};

// Struttura per i dettagli dell'errore
struct ErrorDetails {
    ErrorCode code;
    DWORD windowsError;
    std::wstring message;
    std::wstring component;
    std::wstring function;
    bool isCritical;
    bool requiresCleanup;
};

// Struttura per il contesto dell'errore
struct ErrorContext {
    std::vector<ErrorDetails> errorStack;
    std::map<ErrorCode, unsigned int> errorCounts;
    bool hasRecoveryPlan;
    bool isHandled;
};

class ErrorHandler {
public:
    static ErrorHandler& getInstance();

    // Gestione errori
    void handleError(const ErrorDetails& error);
    void pushError(ErrorCode code, const std::wstring& message);
    void logError(const ErrorDetails& error);
    bool hasErrors() const;
    void clearErrors();

    // Recovery
    bool attemptRecovery(ErrorCode code);
    bool rollback();
    void setRecoveryHandler(ErrorCode code, std::function<bool()> handler);

    // Analisi
    std::vector<ErrorDetails> getErrorStack() const;
    ErrorDetails getLastError() const;
    bool isCriticalError(ErrorCode code) const;
    
    // Utility
    std::wstring getErrorMessage(ErrorCode code) const;
    DWORD getWindowsError() const;
    void setErrorCallback(std::function<void(const ErrorDetails&)> callback);

private:
    ErrorHandler();  // Singleton
    ~ErrorHandler();
    
    ErrorHandler(const ErrorHandler&) = delete;
    ErrorHandler& operator=(const ErrorHandler&) = delete;

    // Gestione interna
    bool initializeHandler();
    void updateErrorStats(const ErrorDetails& error);
    bool shouldAttemptRecovery(ErrorCode code) const;
    void cleanupAfterError();

    // Recovery handlers
    bool handleInitializationError();
    bool handleVirtualizationError();
    bool handleBypassError();
    bool handleSecurityError();
    bool handleSystemError();

    // Analisi errori
    void analyzeErrorPattern();
    void detectRecurringErrors();
    void updateErrorThresholds();

    // Membri
    Logger& logger;
    ErrorContext context;
    std::map<ErrorCode, std::function<bool()>> recoveryHandlers;
    std::function<void(const ErrorDetails&)> errorCallback;
    
    // Costanti
    static const unsigned int MAX_ERROR_STACK = 100;
    static const unsigned int ERROR_THRESHOLD = 5;
    static const DWORD ERROR_CLEANUP_TIMEOUT = 5000;  // 5 secondi
};

// Macro per gestione errori
#define HANDLE_ERROR(code, message) \
    ErrorHandler::getInstance().pushError(code, message)

#define CHECK_ERROR(condition, code, message) \
    if (!(condition)) { \
        ErrorHandler::getInstance().pushError(code, message); \
        return false; \
    }

#define TRY_OPERATION(operation, code, message) \
    try { \
        if (!(operation)) { \
            ErrorHandler::getInstance().pushError(code, message); \
            return false; \
        } \
    } catch (const std::exception& e) { \
        ErrorHandler::getInstance().pushError(code, \
            message + L": " + std::wstring(e.what())); \
        return false; \
    }

} // namespace uac_bypass

#endif // UAC_BYPASS_ERROR_HANDLER_H