#ifndef UAC_BYPASS_COM_MANAGER_H
#define UAC_BYPASS_COM_MANAGER_H

#include <windows.h>
#include <comdef.h>
#include <objbase.h>
#include <shobjidl.h>
#include <string>
#include "Logger.h"
#include "Config.h"
#include "ComInterfaces.h"

namespace uac_bypass {

class ComManager {
public:
    static ComManager& getInstance();
    ~ComManager();

    // Inizializzazione e cleanup COM
    bool initialize();
    void cleanup();

    // Operazioni di elevazione
    bool createElevatedCOMObject(const CLSID& clsid, IUnknown** ppUnknown);
    bool executeElevated(const std::wstring& command);
    bool createShellElevationObject(IShellElevation** ppShellElevation);

    // Verifica e sicurezza
    bool verifyComSecurity();
    bool checkComIntegrity();
    
private:
    ComManager();  // Singleton
    ComManager(const ComManager&) = delete;
    ComManager& operator=(const ComManager&) = delete;

    // Metodi interni
    bool setupComSecurity();
    bool createElevationMoniker(const CLSID& clsid, IUnknown** ppUnknown);
    bool verifyComObject(IUnknown* pUnknown);
    void logComError(HRESULT hr, const std::wstring& operation);

    // Utility di sicurezza
    bool checkProcessTrust(const std::wstring& processPath);
    bool validateComServer(const CLSID& clsid);
    
    // Membri
    Logger& logger;
    bool initialized;
    DWORD mainThreadId;
    
    // Costanti
    static const DWORD COM_INIT_FLAGS = COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE;
    static const DWORD COM_SEC_FLAGS = EOAC_DYNAMIC_CLOAKING | EOAC_MUTUAL_AUTH;
};

// Helper per la gestione automatica dei puntatori COM
template<typename T>
class ComPtr {
public:
    ComPtr() : ptr(nullptr) {}
    ~ComPtr() { if(ptr) ptr->Release(); }
    
    T** operator&() { return &ptr; }
    T* operator->() { return ptr; }
    operator T*() { return ptr; }
    
    bool isValid() const { return ptr != nullptr; }
    void release() { if(ptr) { ptr->Release(); ptr = nullptr; } }
    
private:
    T* ptr;
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
};

// Macro per la gestione degli errori COM
#define CHECK_HR(hr, msg) \
    if (FAILED(hr)) { \
        logger.logError(L"COM Error in " msg L": 0x" + std::to_wstring(hr)); \
        return false; \
    }

} // namespace uac_bypass

#endif // UAC_BYPASS_COM_MANAGER_H