#ifndef UAC_BYPASS_PROCESS_ELEVATOR_H
#define UAC_BYPASS_PROCESS_ELEVATOR_H

#include <windows.h>
#include <string>
#include "Logger.h"

namespace uac_bypass {

// Struttura per i dati di elevazione
struct ElevationData {
    std::wstring targetProcess;
    std::wstring payloadPath;
    std::wstring registryKey;
    DWORD targetPID;
    bool requiresCleanup;
};

class ProcessElevator {
public:
    ProcessElevator();
    ~ProcessElevator();

    // Metodi principali per l'elevazione
    bool ElevateCurrentProcess();
    bool BypassUAC();
    
    // Metodi di utilità pubblici
    static bool IsProcessElevated(HANDLE hProcess);
    static bool IsProcessRunning(const std::wstring& processName);

private:
    // Metodi interni per il bypass
    bool SetupCOMObject();
    bool CreateElevatedProcess();
    bool ManipulateRegistry();
    bool CleanupRegistry();
    bool InjectPayload(HANDLE hProcess);
    
    // Metodi di utilità privati
    HANDLE GetTargetProcessHandle();
    bool BackupRegistryKey(const std::wstring& keyPath);
    bool RestoreRegistryKey(const std::wstring& keyPath);
    
    // Variabili membro
    Logger& logger;
    HANDLE hTargetProcess;
    std::wstring backupKeyPath;
    bool cleanupRequired;
    ElevationData elevData;
    
    // Costanti private
    static const DWORD MAX_WAIT_TIME = 30000; // 30 secondi
    static const DWORD PROCESS_CHECK_INTERVAL = 100; // 100 ms
};

} // namespace uac_bypass

#endif // UAC_BYPASS_PROCESS_ELEVATOR_H