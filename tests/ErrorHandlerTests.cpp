#include <gtest/gtest.h>
#include "../include/ErrorHandler.h"
#include <thread>
#include <chrono>

using namespace uac_bypass;

class ErrorHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        errorHandler = &ErrorHandler::getInstance();
        errorHandler->clearErrors();
    }
    
    void TearDown() override {
        errorHandler->clearErrors();
    }
    
    ErrorHandler* errorHandler;
};

// Test inizializzazione
TEST_F(ErrorHandlerTest, InitializationTest) {
    EXPECT_FALSE(errorHandler->hasErrors());
    EXPECT_EQ(errorHandler->getErrorStack().size(), 0);
}

// Test gestione errori base
TEST_F(ErrorHandlerTest, BasicErrorHandlingTest) {
    errorHandler->pushError(ErrorCode::INITIALIZATION_FAILED, L"Test error");
    EXPECT_TRUE(errorHandler->hasErrors());
    EXPECT_EQ(errorHandler->getErrorStack().size(), 1);
    
    auto lastError = errorHandler->getLastError();
    EXPECT_EQ(lastError.code, ErrorCode::INITIALIZATION_FAILED);
    EXPECT_EQ(lastError.message, L"Test error");
}

// Test errori multipli
TEST_F(ErrorHandlerTest, MultipleErrorsTest) {
    errorHandler->pushError(ErrorCode::INITIALIZATION_FAILED, L"Error 1");
    errorHandler->pushError(ErrorCode::BYPASS_FAILED, L"Error 2");
    errorHandler->pushError(ErrorCode::SECURITY_ERROR, L"Error 3");
    
    EXPECT_EQ(errorHandler->getErrorStack().size(), 3);
    auto errors = errorHandler->getErrorStack();
    EXPECT_EQ(errors[0].message, L"Error 1");
    EXPECT_EQ(errors[1].message, L"Error 2");
    EXPECT_EQ(errors[2].message, L"Error 3");
}

// Test recovery automatico
TEST_F(ErrorHandlerTest, AutomaticRecoveryTest) {
    bool recoveryAttempted = false;
    
    errorHandler->setRecoveryHandler(ErrorCode::INITIALIZATION_FAILED,
        [&recoveryAttempted]() {
            recoveryAttempted = true;
            return true;
        });
    
    errorHandler->pushError(ErrorCode::INITIALIZATION_FAILED, L"Test recovery");
    EXPECT_TRUE(recoveryAttempted);
}

// Test errori critici
TEST_F(ErrorHandlerTest, CriticalErrorTest) {
    errorHandler->pushError(ErrorCode::SECURITY_ERROR, L"Critical error");
    auto lastError = errorHandler->getLastError();
    EXPECT_TRUE(lastError.isCritical);
    EXPECT_TRUE(lastError.requiresCleanup);
}

// Test callback errori
TEST_F(ErrorHandlerTest, ErrorCallbackTest) {
    bool callbackCalled = false;
    ErrorDetails callbackError;
    
    errorHandler->setErrorCallback(
        [&callbackCalled, &callbackError](const ErrorDetails& error) {
            callbackCalled = true;
            callbackError = error;
        });
    
    errorHandler->pushError(ErrorCode::BYPASS_FAILED, L"Test callback");
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackError.code, ErrorCode::BYPASS_FAILED);
}

// Test limite stack errori
TEST_F(ErrorHandlerTest, ErrorStackLimitTest) {
    for (int i = 0; i < 150; i++) {
        errorHandler->pushError(ErrorCode::BYPASS_FAILED,
            L"Error " + std::to_wstring(i));
    }
    
    EXPECT_LE(errorHandler->getErrorStack().size(), 100);
}

// Test cleanup errori
TEST_F(ErrorHandlerTest, ErrorCleanupTest) {
    errorHandler->pushError(ErrorCode::MEMORY_ERROR, L"Memory leak");
    EXPECT_TRUE(errorHandler->hasErrors());
    
    errorHandler->clearErrors();
    EXPECT_FALSE(errorHandler->hasErrors());
    EXPECT_EQ(errorHandler->getErrorStack().size(), 0);
}

// Test rollback
TEST_F(ErrorHandlerTest, RollbackTest) {
    errorHandler->pushError(ErrorCode::TOKEN_ERROR, L"Token error");
    errorHandler->pushError(ErrorCode::PIPE_ERROR, L"Pipe error");
    
    EXPECT_TRUE(errorHandler->rollback());
    EXPECT_FALSE(errorHandler->hasErrors());
}

// Test pattern detection
TEST_F(ErrorHandlerTest, ErrorPatternTest) {
    // Simula errori ricorrenti
    for (int i = 0; i < 6; i++) {
        errorHandler->pushError(ErrorCode::RPC_ERROR, L"Recurring error");
    }
    
    auto lastError = errorHandler->getLastError();
    EXPECT_FALSE(errorHandler->attemptRecovery(lastError.code));
}

// Test messaggi errore
TEST_F(ErrorHandlerTest, ErrorMessageTest) {
    EXPECT_EQ(errorHandler->getErrorMessage(ErrorCode::SUCCESS),
        L"Operation completed successfully");
    EXPECT_EQ(errorHandler->getErrorMessage(ErrorCode::INITIALIZATION_FAILED),
        L"Initialization failed");
    EXPECT_EQ(errorHandler->getErrorMessage(ErrorCode::UNKNOWN_ERROR),
        L"Unknown error");
}

// Test errori concorrenti
TEST_F(ErrorHandlerTest, ConcurrentErrorTest) {
    std::vector<std::thread> threads;
    
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([this, i]() {
            errorHandler->pushError(ErrorCode::SYSTEM_ERROR,
                L"Thread " + std::to_wstring(i));
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(errorHandler->getErrorStack().size(), 10);
}

// Test recovery personalizzato
TEST_F(ErrorHandlerTest, CustomRecoveryTest) {
    int recoveryAttempts = 0;
    
    errorHandler->setRecoveryHandler(ErrorCode::VIRTUALIZATION_ERROR,
        [&recoveryAttempts]() {
            recoveryAttempts++;
            return recoveryAttempts < 3;
        });
    
    for (int i = 0; i < 5; i++) {
        errorHandler->pushError(ErrorCode::VIRTUALIZATION_ERROR,
            L"Recovery test");
    }
    
    EXPECT_EQ(recoveryAttempts, 3);
}

// Test Windows error
TEST_F(ErrorHandlerTest, WindowsErrorTest) {
    SetLastError(ERROR_ACCESS_DENIED);
    errorHandler->pushError(ErrorCode::PERMISSION_DENIED,
        L"Access denied test");
    
    auto lastError = errorHandler->getLastError();
    EXPECT_EQ(lastError.windowsError, ERROR_ACCESS_DENIED);
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}