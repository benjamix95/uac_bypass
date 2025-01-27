#include "../include/SharedMemoryManager.h"
#include <sddl.h>
#include <aes.h>
#include <memory>

namespace uac_bypass {

const WCHAR* SharedMemoryManager::MUTEX_PREFIX = L"Global\\UACBypass_Mutex_";
const WCHAR* SharedMemoryManager::EVENT_READ_PREFIX = L"Global\\UACBypass_Read_";
const WCHAR* SharedMemoryManager::EVENT_WRITE_PREFIX = L"Global\\UACBypass_Write_";

SharedMemoryManager::SharedMemoryManager()
    : logger(Logger::getInstance()),
      hSharedMemory(NULL),
      hMutex(NULL),
      hEventRead(NULL),
      hEventWrite(NULL),
      pSharedData(NULL),
      initialized(false) {
}

SharedMemoryManager::~SharedMemoryManager() {
    cleanup();
}

SharedMemoryManager& SharedMemoryManager::getInstance() {
    static SharedMemoryManager instance;
    return instance;
}

bool SharedMemoryManager::initialize(const std::wstring& name) {
    if (initialized) return true;
    
    memoryName = name;
    
    // Crea memoria condivisa e oggetti di sincronizzazione
    if (!createSharedMemory() || !createSyncObjects()) {
        cleanup();
        return false;
    }
    
    initialized = true;
    return true;
}

void SharedMemoryManager::cleanup() {
    if (pSharedData) {
        UnmapViewOfFile(pSharedData);
        pSharedData = NULL;
    }
    
    if (hSharedMemory) {
        CloseHandle(hSharedMemory);
        hSharedMemory = NULL;
    }
    
    if (hMutex) {
        CloseHandle(hMutex);
        hMutex = NULL;
    }
    
    if (hEventRead) {
        CloseHandle(hEventRead);
        hEventRead = NULL;
    }
    
    if (hEventWrite) {
        CloseHandle(hEventWrite);
        hEventWrite = NULL;
    }
    
    initialized = false;
}

bool SharedMemoryManager::writeData(const SharedData& data) {
    if (!initialized || !pSharedData) return false;
    
    // Attendi accesso esclusivo
    DWORD waitResult = WaitForSingleObject(hMutex, 5000);
    if (waitResult != WAIT_OBJECT_0) {
        logger.logError(L"Timeout attesa mutex in writeData");
        return false;
    }
    
    // Copia e cifra i dati
    SharedData encryptedData = data;
    encryptData(encryptedData);
    
    // Scrivi nella memoria condivisa
    memcpy(pSharedData, &encryptedData, sizeof(SharedData));
    
    // Segnala dati disponibili
    SetEvent(hEventWrite);
    
    // Rilascia mutex
    ReleaseMutex(hMutex);
    
    return true;
}

bool SharedMemoryManager::readData(SharedData& data) {
    if (!initialized || !pSharedData) return false;
    
    // Attendi dati disponibili
    DWORD waitResult = WaitForSingleObject(hEventWrite, 5000);
    if (waitResult != WAIT_OBJECT_0) {
        logger.logError(L"Timeout attesa dati in readData");
        return false;
    }
    
    // Attendi accesso esclusivo
    waitResult = WaitForSingleObject(hMutex, 5000);
    if (waitResult != WAIT_OBJECT_0) {
        logger.logError(L"Timeout attesa mutex in readData");
        return false;
    }
    
    // Leggi dalla memoria condivisa
    memcpy(&data, pSharedData, sizeof(SharedData));
    
    // Decifra i dati
    decryptData(data);
    
    // Resetta evento scrittura
    ResetEvent(hEventWrite);
    
    // Segnala lettura completata
    SetEvent(hEventRead);
    
    // Rilascia mutex
    ReleaseMutex(hMutex);
    
    return true;
}

bool SharedMemoryManager::waitForCompletion(DWORD timeout) {
    if (!initialized) return false;
    
    SharedData data;
    DWORD startTime = GetTickCount();
    
    while (GetTickCount() - startTime < timeout) {
        if (readData(data) && data.completed) {
            return true;
        }
        Sleep(100);
    }
    
    return false;
}

bool SharedMemoryManager::signalCompletion() {
    if (!initialized) return false;
    
    SharedData data = {};
    data.completed = TRUE;
    
    return writeData(data);
}

bool SharedMemoryManager::createSharedMemory() {
    // Security descriptor per accesso globale
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;
    
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    sa.lpSecurityDescriptor = &sd;
    
    // Crea memoria condivisa
    hSharedMemory = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        &sa,
        PAGE_READWRITE,
        0,
        SHARED_MEM_SIZE,
        memoryName.c_str()
    );
    
    if (!hSharedMemory) {
        logger.logError(L"Creazione memoria condivisa fallita");
        return false;
    }
    
    // Mappa vista della memoria
    pSharedData = MapViewOfFile(
        hSharedMemory,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        SHARED_MEM_SIZE
    );
    
    if (!pSharedData) {
        logger.logError(L"Mapping memoria condivisa fallito");
        return false;
    }
    
    return true;
}

bool SharedMemoryManager::openSharedMemory() {
    // Apri memoria condivisa esistente
    hSharedMemory = OpenFileMappingW(
        FILE_MAP_ALL_ACCESS,
        FALSE,
        memoryName.c_str()
    );
    
    if (!hSharedMemory) {
        logger.logError(L"Apertura memoria condivisa fallita");
        return false;
    }
    
    // Mappa vista della memoria
    pSharedData = MapViewOfFile(
        hSharedMemory,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        SHARED_MEM_SIZE
    );
    
    if (!pSharedData) {
        logger.logError(L"Mapping memoria condivisa fallito");
        return false;
    }
    
    return true;
}

bool SharedMemoryManager::createSyncObjects() {
    // Crea mutex per sincronizzazione
    std::wstring mutexName = MUTEX_PREFIX + memoryName;
    hMutex = CreateMutexW(NULL, FALSE, mutexName.c_str());
    if (!hMutex) {
        logger.logError(L"Creazione mutex fallita");
        return false;
    }
    
    // Crea eventi per notifica read/write
    std::wstring eventReadName = EVENT_READ_PREFIX + memoryName;
    std::wstring eventWriteName = EVENT_WRITE_PREFIX + memoryName;
    
    hEventRead = CreateEventW(NULL, TRUE, FALSE, eventReadName.c_str());
    hEventWrite = CreateEventW(NULL, TRUE, FALSE, eventWriteName.c_str());
    
    if (!hEventRead || !hEventWrite) {
        logger.logError(L"Creazione eventi fallita");
        return false;
    }
    
    return true;
}

bool SharedMemoryManager::openSyncObjects() {
    // Apri mutex esistente
    std::wstring mutexName = MUTEX_PREFIX + memoryName;
    hMutex = OpenMutexW(SYNCHRONIZE, FALSE, mutexName.c_str());
    if (!hMutex) {
        logger.logError(L"Apertura mutex fallita");
        return false;
    }
    
    // Apri eventi esistenti
    std::wstring eventReadName = EVENT_READ_PREFIX + memoryName;
    std::wstring eventWriteName = EVENT_WRITE_PREFIX + memoryName;
    
    hEventRead = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE,
        FALSE, eventReadName.c_str());
    hEventWrite = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE,
        FALSE, eventWriteName.c_str());
    
    if (!hEventRead || !hEventWrite) {
        logger.logError(L"Apertura eventi fallita");
        return false;
    }
    
    return true;
}

void SharedMemoryManager::encryptData(SharedData& data) {
    static Encryption& encryption = Encryption::getInstance();
    
    if (!encryption.initialized) {
        if (!encryption.initialize() || !encryption.generateKey()) {
            logger.logError(L"Inizializzazione cifratura fallita");
            return;
        }
    }
    
    DWORD outputSize = sizeof(SharedData);
    BYTE buffer[sizeof(SharedData)];
    
    if (!encryption.encryptData(
        reinterpret_cast<BYTE*>(&data),
        sizeof(SharedData),
        buffer,
        outputSize)) {
        logger.logError(L"Cifratura dati fallita");
        return;
    }
    
    memcpy(&data, buffer, sizeof(SharedData));
}

void SharedMemoryManager::decryptData(SharedData& data) {
    static Encryption& encryption = Encryption::getInstance();
    
    if (!encryption.initialized) {
        logger.logError(L"Sistema di cifratura non inizializzato");
        return;
    }
    
    DWORD outputSize = sizeof(SharedData);
    BYTE buffer[sizeof(SharedData)];
    
    if (!encryption.decryptData(
        reinterpret_cast<BYTE*>(&data),
        sizeof(SharedData),
        buffer,
        outputSize)) {
        logger.logError(L"Decifratura dati fallita");
        return;
    }
    
    memcpy(&data, buffer, sizeof(SharedData));
}

} // namespace uac_bypass
