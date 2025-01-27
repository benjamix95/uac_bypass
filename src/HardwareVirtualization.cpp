#include "../include/HardwareVirtualization.h"
#include "../include/VMXDefs.h"
#include <intrin.h>
#include <memory>
#include <algorithm>

namespace uac_bypass {

HardwareVirtualization::HardwareVirtualization() 
    : logger(Logger::getInstance()),
      initialized(false),
      vmxon_region(nullptr),
      vmcs_region(nullptr),
      ept_pml4(nullptr),
      msr_bitmap(nullptr),
      io_bitmap_a(nullptr),
      io_bitmap_b(nullptr) {
    
    // Inizializza contesto CPU
    memset(&context, 0, sizeof(CPUContext));
}

HardwareVirtualization::~HardwareVirtualization() {
    cleanup();
}

HardwareVirtualization& HardwareVirtualization::getInstance() {
    static HardwareVirtualization instance;
    return instance;
}

bool HardwareVirtualization::initialize() {
    if (initialized) return true;
    
    logger.logInfo(L"Inizializzazione HardwareVirtualization");
    
    // Verifica supporto VT-x
    if (!checkVTSupport()) {
        logger.logError(L"VT-x non supportato");
        return false;
    }
    
    // Alloca strutture VT-x
    if (!allocateVMCS()) {
        logger.logError(L"Allocazione VMCS fallita");
        return false;
    }
    
    // Setup EPT
    if (!setupEPT()) {
        logger.logError(L"Setup EPT fallito");
        return false;
    }
    
    initialized = true;
    return true;
}

bool HardwareVirtualization::setupVirtualization() {
    if (!initialized && !initialize()) return false;
    
    // Abilita VT-x
    if (!enableVTx()) {
        logger.logError(L"Abilitazione VT-x fallita");
        return false;
    }
    
    // Setup VMCS
    if (!setupVMCS()) {
        logger.logError(L"Setup VMCS fallito");
        return false;
    }
    
    // Setup protezioni
    if (!setupMSRBitmap() || !setupIOBitmap()) {
        logger.logError(L"Setup bitmap fallito");
        return false;
    }
    
    return true;
}

bool HardwareVirtualization::emulateInstruction() {
    if (!initialized) return false;
    
    // Decodifica istruzione
    if (!decodeInstruction()) {
        logger.logError(L"Decodifica istruzione fallita");
        return false;
    }
    
    // Esegui istruzione
    if (!executeInstruction()) {
        logger.logError(L"Esecuzione istruzione fallita");
        return false;
    }
    
    // Aggiorna contesto
    if (!updateContext()) {
        logger.logError(L"Aggiornamento contesto fallito");
        return false;
    }
    
    return true;
}

bool HardwareVirtualization::cleanup() {
    // Disabilita VT-x
    __try {
        __vmx_off();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        logger.logWarning(L"Errore durante vmx_off");
    }
    
    // Libera memoria allocata
    if (vmxon_region) VirtualFree(vmxon_region, 0, MEM_RELEASE);
    if (vmcs_region) VirtualFree(vmcs_region, 0, MEM_RELEASE);
    if (ept_pml4) VirtualFree(ept_pml4, 0, MEM_RELEASE);
    if (msr_bitmap) VirtualFree(msr_bitmap, 0, MEM_RELEASE);
    if (io_bitmap_a) VirtualFree(io_bitmap_a, 0, MEM_RELEASE);
    if (io_bitmap_b) VirtualFree(io_bitmap_b, 0, MEM_RELEASE);
    
    vmxon_region = vmcs_region = ept_pml4 = nullptr;
    msr_bitmap = io_bitmap_a = io_bitmap_b = nullptr;
    
    // Libera memoria virtualizzata
    for (auto& vm : virtualMemory) {
        if (vm.memory) VirtualFree(vm.memory, 0, MEM_RELEASE);
    }
    virtualMemory.clear();
    
    initialized = false;
    return true;
}

bool HardwareVirtualization::initializeCPU() {
    // Salva stato CPU corrente
    context.rflags = __readeflags();
    context.cr0 = __readcr0();
    context.cr3 = __readcr3();
    context.cr4 = __readcr4();
    
    // Salva registri di segmento
    __asm {
        mov ax, cs
        mov context.cs, ax
        mov ax, ds
        mov context.ds, ax
        mov ax, es
        mov context.es, ax
        mov ax, fs
        mov context.fs, ax
        mov ax, gs
        mov context.gs, ax
        mov ax, ss
        mov context.ss, ax
    }
    
    // Salva stato FPU/SSE
    _fxsave(context.fxsave);
    
    return true;
}

bool HardwareVirtualization::setupVMCS() {
    // Configura controlli VMCS
    if (!setupVMCSControls()) return false;
    
    // Configura stato host
    if (!setupVMCSHostState()) return false;
    
    // Configura stato guest
    if (!setupVMCSGuestState()) return false;
    
    return true;
}

bool HardwareVirtualization::handleVMExit(DWORD exitReason) {
    switch (exitReason) {
        case EXIT_REASON_CPUID:
            return emulateCPUID();
            
        case EXIT_REASON_MSR_READ:
        case EXIT_REASON_MSR_WRITE:
            return handleMSRAccess();
            
        case EXIT_REASON_CR_ACCESS:
            return handleCRAccess();
            
        case EXIT_REASON_EPT_VIOLATION:
            return handleEPTViolation();
            
        case EXIT_REASON_EXCEPTION_NMI:
            return handleException();
            
        default:
            logger.logWarning(L"VM exit non gestito: " + std::to_wstring(exitReason));
            return false;
    }
}

bool HardwareVirtualization::injectInterrupt(BYTE vector) {
    // Configura campi VMCS per iniezione interrupt
    DWORD interruptInfo = (vector & 0xFF) |
                         (0 << 8) |        // Tipo interrupt hardware
                         (1 << 31);        // Valid bit
    
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, interruptInfo);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRORCODE, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, 0);
    
    return true;
}

bool HardwareVirtualization::allocateMemory(size_t size) {
    VirtualMemory vm = {};
    
    // Alloca memoria con allineamento pagina
    vm.memory = (BYTE*)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!vm.memory) {
        logger.logError(L"Allocazione memoria fallita");
        return false;
    }
    
    vm.size = size;
    vm.protection = PAGE_READWRITE;
    vm.mapped = false;
    
    virtualMemory.push_back(vm);
    return true;
}

bool HardwareVirtualization::mapMemory(void* hostAddr, DWORD64 guestAddr, size_t size) {
    // Trova regione di memoria virtuale
    auto it = std::find_if(virtualMemory.begin(), virtualMemory.end(),
        [hostAddr](const VirtualMemory& vm) {
            return vm.memory == hostAddr;
        });
    
    if (it == virtualMemory.end()) {
        logger.logError(L"Memoria virtuale non trovata");
        return false;
    }
    
    // Mappa memoria in EPT
    it->baseAddress = guestAddr;
    it->mapped = true;
    
    return setupEPTTables();
}

bool HardwareVirtualization::protectMemory(DWORD64 addr, size_t size, DWORD protection) {
    // Trova regione di memoria virtuale
    auto it = std::find_if(virtualMemory.begin(), virtualMemory.end(),
        [addr](const VirtualMemory& vm) {
            return vm.baseAddress <= addr &&
                   addr < (vm.baseAddress + vm.size);
        });
    
    if (it == virtualMemory.end()) {
        logger.logError(L"Memoria virtuale non trovata");
        return false;
    }
    
    // Aggiorna protezione
    DWORD oldProtect;
    if (!VirtualProtect(it->memory, size, protection, &oldProtect)) {
        logger.logError(L"Modifica protezione fallita");
        return false;
    }
    
    it->protection = protection;
    return true;
}

bool HardwareVirtualization::emulateSyscall() {
    // Emula istruzione SYSCALL
    DWORD64 syscallNumber = context.rax;
    
    // Salva stato
    DWORD64 returnAddress = context.rip + 2;  // Lunghezza SYSCALL
    
    // Setup stack shadow
    context.rsp -= 8;
    *(DWORD64*)context.rsp = returnAddress;
    
    // Carica handler syscall
    context.rip = context.lstar;
    
    return true;
}

bool HardwareVirtualization::emulateIO() {
    // Emula istruzioni I/O
    return true;
}

bool HardwareVirtualization::emulateCPUID() {
    int cpuInfo[4];
    __cpuid(cpuInfo, static_cast<int>(context.rax & 0xFFFFFFFF));
    
    context.rax = static_cast<DWORD64>(cpuInfo[0]);
    context.rbx = static_cast<DWORD64>(cpuInfo[1]);
    context.rcx = static_cast<DWORD64>(cpuInfo[2]);
    context.rdx = static_cast<DWORD64>(cpuInfo[3]);
    
    return true;
}

bool HardwareVirtualization::emulateRDTSC() {
    LARGE_INTEGER tsc;
    QueryPerformanceCounter(&tsc);
    
    context.rax = tsc.LowPart;
    context.rdx = tsc.HighPart;
    
    return true;
}

bool HardwareVirtualization::setupEPT() {
    // Alloca tabelle EPT
    if (!setupEPTTables()) {
        return false;
    }
    
    // Configura VMCS per EPT
    DWORD64 eptp = (DWORD64)ept_pml4;
    eptp |= (EPT_LEVELS - 1) << 3;     // Page-walk length
    eptp |= 6 << 0;                    // Memory type (WB)
    
    __vmx_vmwrite(VMCS_CTRL_EPT_POINTER, eptp);
    
    return true;
}

bool HardwareVirtualization::configureVMCS() {
    // Configura controlli VMCS
    return setupVMCSControls();
}

bool HardwareVirtualization::handleException() {
    // Gestisci eccezioni CPU
    return true;
}

bool HardwareVirtualization::monitorMSR() {
    // Monitora accessi MSR
    return true;
}

bool HardwareVirtualization::checkVTSupport() {
    int cpuInfo[4];
    
    // Verifica CPUID.1:ECX.VMX[bit 5]
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 5))) {
        return false;
    }
    
    // Verifica IA32_FEATURE_CONTROL.LOCK[bit 0]
    DWORD64 feature_control;
    feature_control = __readmsr(0x3A);
    if (!(feature_control & 1)) {
        return false;
    }
    
    return true;
}

bool HardwareVirtualization::enableVTx() {
    __try {
        // Abilita VMX operation
        DWORD64 cr4 = __readcr4();
        __writecr4(cr4 | (1 << 13));  // Set CR4.VMXE
        
        // Esegui VMXON
        __vmx_on((DWORD64*)&vmxon_region);
        
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool HardwareVirtualization::setupEPTTables() {
    // Setup tabelle EPT
    return true;
}

bool HardwareVirtualization::initializeIDT() {
    // Inizializza IDT
    return true;
}

bool HardwareVirtualization::allocateVMCS() {
    // Alloca regione VMCS
    vmcs_region = VirtualAlloc(NULL, VMCS_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!vmcs_region) {
        return false;
    }
    
    // Alloca regione VMXON
    vmxon_region = VirtualAlloc(NULL, VMCS_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!vmxon_region) {
        VirtualFree(vmcs_region, 0, MEM_RELEASE);
        vmcs_region = nullptr;
        return false;
    }
    
    return true;
}

bool HardwareVirtualization::setupVMCSControls() {
    // Configura controlli VMCS
    return true;
}

bool HardwareVirtualization::setupVMCSHostState() {
    // Configura stato host VMCS
    return true;
}

bool HardwareVirtualization::setupVMCSGuestState() {
    // Configura stato guest VMCS
    return true;
}

bool HardwareVirtualization::setupPageTables() {
    // Setup tabelle delle pagine
    return true;
}

bool HardwareVirtualization::handleEPTViolation() {
    // Gestisci violazioni EPT
    return true;
}

bool HardwareVirtualization::handlePageFault() {
    // Gestisci page fault
    return true;
}

bool HardwareVirtualization::decodeInstruction() {
    // Decodifica istruzione corrente
    return true;
}

bool HardwareVirtualization::executeInstruction() {
    // Esegui istruzione decodificata
    return true;
}

bool HardwareVirtualization::updateContext() {
    // Aggiorna contesto CPU
    return true;
}

bool HardwareVirtualization::setupMSRBitmap() {
    // Setup bitmap MSR
    msr_bitmap = VirtualAlloc(NULL, PAGE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!msr_bitmap) {
        return false;
    }
    
    memset(msr_bitmap, 0, PAGE_SIZE);
    return true;
}

bool HardwareVirtualization::setupIOBitmap() {
    // Setup bitmap I/O
    io_bitmap_a = VirtualAlloc(NULL, PAGE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    io_bitmap_b = VirtualAlloc(NULL, PAGE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!io_bitmap_a || !io_bitmap_b) {
        if (io_bitmap_a) VirtualFree(io_bitmap_a, 0, MEM_RELEASE);
        if (io_bitmap_b) VirtualFree(io_bitmap_b, 0, MEM_RELEASE);
        return false;
    }
    
    memset(io_bitmap_a, 0xFF, PAGE_SIZE);  // Blocca tutti gli I/O
    memset(io_bitmap_b, 0xFF, PAGE_SIZE);
    
    return true;
}

bool HardwareVirtualization::handleCRAccess() {
    // Gestisci accessi CR
    return true;
}

bool HardwareVirtualization::handleMSRAccess() {
    // Gestisci accessi MSR
    return true;
}

bool HardwareVirtualization::isVMXSupported() {
    return checkVTSupport();
}

bool HardwareVirtualization::isEPTSupported() {
    int cpuInfo[4];
    
    // Verifica CPUID.1:ECX.VMX[bit 5]
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 5))) {
        return false;
    }
    
    // Verifica supporto EPT
    DWORD64 vmx_basic = __readmsr(0x480);
    DWORD64 vmx_ept_vpid_cap = __readmsr(0x48C);
    
    return (vmx_ept_vpid_cap & 0x1);  // EPT available
}

bool HardwareVirtualization::isUREPSupported() {
    // Verifica supporto UREP (Unrestricted Execution Prevention)
    DWORD64 vmx_ept_vpid_cap = __readmsr(0x48C);
    return (vmx_ept_vpid_cap & (1ULL << 7));
}

DWORD64 HardwareVirtualization::getPhysicalAddress(DWORD64 virtualAddr) {
    // Converti indirizzo virtuale in fisico
    return virtualAddr;  // TODO: implementare conversione
}

} // namespace uac_bypass