#include "../include/ErrorHandler.h"
#include <sstream>
#include <algorithm>

namespace uac_bypass {

ErrorHandler::ErrorHandler() 
    : logger(Logger::getInstance()) {
    initializeHandler();
}

ErrorHandler::~ErrorHandler() {
    clearErrors();
}

ErrorHandler& ErrorHandler::getInstance() {
    static ErrorHandler instance;
    return instance;
}

bool ErrorHandler::initializeHandler() {
    // Inizializza handlers di recovery
    recoveryHandlers[ErrorCode::INITIALIZATION_FAILED] = 
        std::bind(&ErrorHandler::handleInitializationError, this);
    recoveryHandlers[ErrorCode::VIRTUALIZATION_ERROR] = 
        std::bind(&ErrorHandler::handleVirtualizationError, this);
    recoveryHandlers[ErrorCode::BYPASS_FAILED] = 
        std::bind(&ErrorHandler::handleBypassError, this);
    recoveryHandlers[ErrorCode::SECURITY_ERROR] = 
        std::bind(&ErrorHandler::handleSecurityError, this);
    recoveryHandlers[ErrorCode::SYSTEM_ERROR] = 
        std::bind(&ErrorHandler::handleSystemError, this);

    context.hasRecoveryPlan = true;
    context.isHandled = false;
    return true;
}

void ErrorHandler::handleError(const ErrorDetails& error) {
    // Log errore
    logError(error);
    
    // Aggiorna statistiche
    updateErrorStats(error);
    
    // Aggiungi allo stack
    if (context.errorStack.size() >= MAX_ERROR_STACK) {
        context.errorStack.erase(context.errorStack.begin());
    }
    context.errorStack.push_back(error);
    
    // Analizza pattern errori
    analyzeErrorPattern();
    
    // Notifica callback se presente
    if (errorCallback) {
        errorCallback(error);
    }
    
    // Tenta recovery se necessario
    if (error.isCritical && shouldAttemptRecovery(error.code)) {
        attemptRecovery(error.code);
    }
    
    // Cleanup se necessario
    if (error.requiresCleanup) {
        cleanupAfterError();
    }
}

void ErrorHandler::pushError(ErrorCode code, const std::wstring& message) {
    ErrorDetails error;
    error.code = code;
    error.windowsError = GetLastError();
    error.message = message;
    error.isCritical = isCriticalError(code);
    error.requiresCleanup = true;
    
    handleError(error);
}

void ErrorHandler::logError(const ErrorDetails& error) {
    std::wstringstream ss;
    ss << L"Error [" << static_cast<int>(error.code) << L"]: "
       << error.message;
    
    if (error.windowsError != 0) {
        LPWSTR windowsMessage = nullptr;
        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error.windowsError,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR)&windowsMessage,
            0, NULL
        );
        
        if (windowsMessage) {
            ss << L" (Windows Error: " << windowsMessage << L")";
            LocalFree(windowsMessage);
        }
    }
    
    logger.logError(ss.str());
}

bool ErrorHandler::hasErrors() const {
    return !context.errorStack.empty();
}

void ErrorHandler::clearErrors() {
    context.errorStack.clear();
    context.errorCounts.clear();
    context.isHandled = false;
}

bool ErrorHandler::attemptRecovery(ErrorCode code) {
    auto it = recoveryHandlers.find(code);
    if (it != recoveryHandlers.end()) {
        logger.logInfo(L"Attempting recovery for error " + 
            std::to_wstring(static_cast<int>(code)));
        return it->second();
    }
    return false;
}

bool ErrorHandler::rollback() {
    logger.logInfo(L"Rolling back changes");
    
    // Esegui rollback in ordine inverso
    for (auto it = context.errorStack.rbegin(); 
         it != context.errorStack.rend(); ++it) {
        if (it->requiresCleanup) {
            cleanupAfterError();
        }
    }
    
    clearErrors();
    return true;
}

void ErrorHandler::setRecoveryHandler(ErrorCode code, 
    std::function<bool()> handler) {
    recoveryHandlers[code] = handler;
}

std::vector<ErrorDetails> ErrorHandler::getErrorStack() const {
    return context.errorStack;
}

ErrorDetails ErrorHandler::getLastError() const {
    if (context.errorStack.empty()) {
        return ErrorDetails{
            ErrorCode::SUCCESS,
            0,
            L"No errors",
            L"",
            L"",
            false,
            false
        };
    }
    return context.errorStack.back();
}

bool ErrorHandler::isCriticalError(ErrorCode code) const {
    switch (code) {
        case ErrorCode::INITIALIZATION_FAILED:
        case ErrorCode::VIRTUALIZATION_ERROR:
        case ErrorCode::SECURITY_ERROR:
        case ErrorCode::MEMORY_ERROR:
            return true;
        default:
            return false;
    }
}

std::wstring ErrorHandler::getErrorMessage(ErrorCode code) const {
    switch (code) {
        case ErrorCode::SUCCESS:
            return L"Operation completed successfully";
        case ErrorCode::INITIALIZATION_FAILED:
            return L"Initialization failed";
        case ErrorCode::VIRTUALIZATION_ERROR:
            return L"Virtualization error";
        case ErrorCode::BYPASS_FAILED:
            return L"Bypass operation failed";
        case ErrorCode::TOKEN_ERROR:
            return L"Token manipulation error";
        case ErrorCode::PIPE_ERROR:
            return L"Named pipe error";
        case ErrorCode::RPC_ERROR:
            return L"RPC operation error";
        case ErrorCode::SERVICE_ERROR:
            return L"Service manipulation error";
        case ErrorCode::SECURITY_ERROR:
            return L"Security violation";
        case ErrorCode::MEMORY_ERROR:
            return L"Memory operation error";
        case ErrorCode::PERMISSION_DENIED:
            return L"Permission denied";
        case ErrorCode::INVALID_PARAMETER:
            return L"Invalid parameter";
        case ErrorCode::SYSTEM_ERROR:
            return L"System error";
        default:
            return L"Unknown error";
    }
}

DWORD ErrorHandler::getWindowsError() const {
    return GetLastError();
}

void ErrorHandler::setErrorCallback(
    std::function<void(const ErrorDetails&)> callback) {
    errorCallback = callback;
}

void ErrorHandler::updateErrorStats(const ErrorDetails& error) {
    context.errorCounts[error.code]++;
    
    // Aggiorna soglie di errore
    if (context.errorCounts[error.code] >= ERROR_THRESHOLD) {
        updateErrorThresholds();
    }
}

bool ErrorHandler::shouldAttemptRecovery(ErrorCode code) const {
    // Verifica se il recovery è possibile
    if (!context.hasRecoveryPlan) return false;
    
    // Verifica numero tentativi
    auto it = context.errorCounts.find(code);
    if (it != context.errorCounts.end() && 
        it->second >= ERROR_THRESHOLD) {
        return false;
    }
    
    return true;
}

void ErrorHandler::cleanupAfterError() {
    // Cleanup risorse
    logger.logInfo(L"Performing error cleanup");
    
    // Timeout per operazioni di cleanup
    DWORD startTime = GetTickCount();
    while (GetTickCount() - startTime < ERROR_CLEANUP_TIMEOUT) {
        // Esegui operazioni di cleanup
    }
}

bool ErrorHandler::handleInitializationError() {
    logger.logInfo(L"Handling initialization error");
    // Implementa recovery per errori di inizializzazione
    return false;
}

bool ErrorHandler::handleVirtualizationError() {
    logger.logInfo(L"Handling virtualization error");
    // Implementa recovery per errori di virtualizzazione
    return false;
}

bool ErrorHandler::handleBypassError() {
    logger.logInfo(L"Handling bypass error");
    // Implementa recovery per errori di bypass
    return false;
}

bool ErrorHandler::handleSecurityError() {
    logger.logInfo(L"Handling security error");
    // Implementa recovery per errori di sicurezza
    return false;
}

bool ErrorHandler::handleSystemError() {
    logger.logInfo(L"Handling system error");
    // Implementa recovery per errori di sistema
    return false;
}

void ErrorHandler::analyzeErrorPattern() {
    // Analizza pattern di errori
    detectRecurringErrors();
}

void ErrorHandler::detectRecurringErrors() {
    // Rileva errori ricorrenti
    for (const auto& pair : context.errorCounts) {
        if (pair.second >= ERROR_THRESHOLD) {
            logger.logWarning(L"Recurring error detected: " + 
                getErrorMessage(pair.first));
        }
    }
}

void ErrorHandler::updateErrorThresholds() {
    // Aggiorna soglie in base ai pattern
    context.hasRecoveryPlan = false;
    logger.logWarning(L"Error thresholds updated");
}

} // namespace uac_bypass