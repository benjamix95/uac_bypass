#ifndef UAC_BYPASS_COM_INTERFACES_H
#define UAC_BYPASS_COM_INTERFACES_H

#include <windows.h>
#include <objbase.h>

// {20C3C0E6-C35E-4A66-8C20-4D8E4C5F1CD5}
DEFINE_GUID(CLSID_ShellElevation,
    0x20c3c0e6, 0xc35e, 0x4a66, 0x8c, 0x20, 0x4d, 0x8e, 0x4c, 0x5f, 0x1c, 0xd5);

// {1E27CF00-69B6-4F6F-9E59-9A8C67819F0D}
DEFINE_GUID(IID_IShellElevation,
    0x1e27cf00, 0x69b6, 0x4f6f, 0x9e, 0x59, 0x9a, 0x8c, 0x67, 0x81, 0x9f, 0x0d);

// Struttura per i parametri di esecuzione
typedef struct _SHELLELEVATION_PARAMS {
    DWORD cbSize;
    DWORD dwFlags;
    LPCWSTR lpFile;
    LPCWSTR lpParameters;
    LPCWSTR lpDirectory;
    INT nShow;
} SHELLELEVATION_PARAMS, *LPSHELLELEVATION_PARAMS;

// Interfaccia personalizzata per l'elevazione
#undef  INTERFACE
#define INTERFACE IShellElevation

DECLARE_INTERFACE_(IShellElevation, IUnknown)
{
    // IUnknown
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, LPVOID *ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef)(THIS) PURE;
    STDMETHOD_(ULONG, Release)(THIS) PURE;

    // IShellElevation
    STDMETHOD(ExecuteElevated)(THIS_ LPSHELLELEVATION_PARAMS lpParams) PURE;
    STDMETHOD(GetElevationStatus)(THIS_ LPDWORD pdwStatus) PURE;
};

// Helper per la creazione dell'oggetto elevato
class ShellElevationFactory {
public:
    static HRESULT CreateInstance(IShellElevation** ppShellElevation) {
        if (!ppShellElevation) return E_POINTER;
        
        return CoCreateInstance(
            CLSID_ShellElevation,
            NULL,
            CLSCTX_LOCAL_SERVER,
            IID_IShellElevation,
            (void**)ppShellElevation
        );
    }
};

#endif // UAC_BYPASS_COM_INTERFACES_H