#include <gtest/gtest.h>
#include "../include/ComManager.h"
#include "../include/Logger.h"
#include "../include/ProcessElevator.h"

using namespace uac_bypass;

class UACBypassTest : public ::testing::Test {
protected:
    void SetUp() override {
        logger = &Logger::getInstance();
    }

    void TearDown() override {
        // Cleanup dopo ogni test
    }

    Logger* logger;
};

// Test ComManager
TEST_F(UACBypassTest, ComManagerInitialization) {
    ComManager& manager = ComManager::getInstance();
    EXPECT_TRUE(manager.initialize());
}

TEST_F(UACBypassTest, ComSecurityVerification) {
    ComManager& manager = ComManager::getInstance();
    EXPECT_TRUE(manager.verifyComSecurity());
}

TEST_F(UACBypassTest, ComIntegrityCheck) {
    ComManager& manager = ComManager::getInstance();
    EXPECT_TRUE(manager.checkComIntegrity());
}

// Test ProcessElevator
TEST_F(UACBypassTest, ProcessElevatorCreation) {
    ProcessElevator elevator;
    EXPECT_FALSE(ProcessElevator::IsProcessElevated(GetCurrentProcess()));
}

TEST_F(UACBypassTest, ProcessTrustVerification) {
    wchar_t systemPath[MAX_PATH];
    GetSystemDirectoryW(systemPath, MAX_PATH);
    std::wstring fodhelperPath = std::wstring(systemPath) + L"\\" + TARGET_PROCESS;
    
    ProcessElevator elevator;
    EXPECT_TRUE(ProcessElevator::IsProcessRunning(TARGET_PROCESS) || 
                !PathFileExistsW(fodhelperPath.c_str()));
}

// Test Logger
TEST_F(UACBypassTest, LoggerInitialization) {
    EXPECT_TRUE(logger != nullptr);
}

TEST_F(UACBypassTest, LoggingOperations) {
    logger->logInfo(L"Test info message");
    logger->logWarning(L"Test warning message");
    logger->logError(L"Test error message");
    // Verifica che i messaggi siano stati scritti nel file di log
    // TODO: Implementare verifica del contenuto del file
}

// Test Registry Operations
TEST_F(UACBypassTest, RegistryBackupRestore) {
    ProcessElevator elevator;
    std::wstring testKey = L"Software\\Classes\\TestKey";
    
    // Test backup
    EXPECT_TRUE(elevator.BackupRegistryKey(testKey));
    
    // Test restore
    EXPECT_TRUE(elevator.RestoreRegistryKey(testKey));
}

// Test Security Features
TEST_F(UACBypassTest, SignatureVerification) {
    wchar_t systemPath[MAX_PATH];
    GetSystemDirectoryW(systemPath, MAX_PATH);
    std::wstring targetPath = std::wstring(systemPath) + L"\\" + TARGET_PROCESS;
    
    ComManager& manager = ComManager::getInstance();
    EXPECT_TRUE(manager.checkProcessTrust(targetPath));
}

// Test Detection Evasion
class DetectionEvasionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup per test di evasion
    }

    void TearDown() override {
        // Cleanup
    }
};

TEST_F(DetectionEvasionTest, ProcessHollowingDetection) {
    // TODO: Implementare test per process hollowing detection
}

TEST_F(DetectionEvasionTest, MemoryProtectionCheck) {
    // TODO: Implementare test per memory protection
}

TEST_F(DetectionEvasionTest, AntiDebugCheck) {
    // TODO: Implementare test per anti-debug
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}