#ifndef UAC_BYPASS_OBFUSCATION_UTILS_H
#define UAC_BYPASS_OBFUSCATION_UTILS_H

#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"
#include "Config.h"

namespace uac_bypass {

// Macro per offuscamento stringhe
#define XSTR_SEED 0x45C7
#define XSTR(s) ObfuscationUtils::deobfuscateString(ObfuscationUtils::obfuscateString(s, XSTR_SEED), XSTR_SEED)

// Macro per offuscamento chiamate API
#define OBFUSCATE_API(name) ObfuscationUtils::resolveAPI(#name)

class ObfuscationUtils {
public:
    static ObfuscationUtils& getInstance();

    // Offuscamento stringhe
    static std::wstring obfuscateString(const std::wstring& input, DWORD seed);
    static std::wstring deobfuscateString(const std::wstring& input, DWORD seed);
    
    // Protezione codice
    bool protectCodeSection();
    bool hideImportTable();
    bool obfuscateControlFlow();
    
    // API Resolution dinamica
    typedef FARPROC (WINAPI *GetProcAddressType)(HMODULE, LPCSTR);
    typedef HMODULE (WINAPI *LoadLibraryType)(LPCWSTR);
    
    static FARPROC resolveAPI(const char* apiName);
    bool initializeDynamicAPIs();
    
    // Offuscamento comportamento
    bool randomizeExecution();
    bool implementJunkCode();
    bool addFalseControlFlow();
    
    // Protezione runtime
    bool protectStrings();
    bool encryptConstants();
    bool hideCallStack();
    
    // Anti-Analysis
    bool implementPolymorphicCode();
    bool addCodeMutation();
    bool obfuscateMetadata();

private:
    ObfuscationUtils();  // Singleton
    ~ObfuscationUtils();
    
    ObfuscationUtils(const ObfuscationUtils&) = delete;
    ObfuscationUtils& operator=(const ObfuscationUtils&) = delete;

    // Metodi interni
    bool initializeEncryption();
    bool setupPolymorphicEngine();
    void mutateCodeSection();
    bool hideDebugInfo();
    bool hideDebugSymbols();
    bool obfuscateStackFrame();
    
    // API Resolution
    static HMODULE resolveModule(const wchar_t* moduleName);
    static void* getAPIAddress(HMODULE module, const char* apiName);
    
    // Offuscamento
    void shuffleInstructions(BYTE* start, SIZE_T size);
    void insertJunkInstructions(BYTE* location);
    bool encryptSection(BYTE* start, SIZE_T size);
    bool protectImportTable();
    
    // Membri
    Logger& logger;
    bool initialized;
    std::vector<BYTE*> protectedSections;
    
    // Cache API
    static GetProcAddressType cachedGetProcAddress;
    static LoadLibraryType cachedLoadLibrary;
    
    // Costanti
    static const SIZE_T MIN_SECTION_SIZE = 4096;
    static const DWORD MUTATION_INTERVAL = 5000; // millisecondi
};

// Struttura per la mutazione del codice
struct CodeMutation {
    BYTE* address;
    SIZE_T size;
    std::vector<BYTE> originalCode;
    std::vector<BYTE> mutatedCode;
};

// Macro per protezione funzioni
#define PROTECT_FUNCTION(func) \
    ObfuscationUtils::getInstance().protectCodeSection((BYTE*)func, sizeof(func))

// Macro per offuscamento control flow
#define OBFUSCATE_FLOW(code) \
    if (ObfuscationUtils::getInstance().randomizeExecution()) { \
        code \
    } else { \
        code \
    }

} // namespace uac_bypass

#endif // UAC_BYPASS_OBFUSCATION_UTILS_H