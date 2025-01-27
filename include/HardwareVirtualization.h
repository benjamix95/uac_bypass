#ifndef UAC_BYPASS_HARDWARE_VIRTUALIZATION_H
#define UAC_BYPASS_HARDWARE_VIRTUALIZATION_H

#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"
#include "Config.h"

namespace uac_bypass {

// Struttura per il contesto CPU
struct CPUContext {
    // Registri generali
    DWORD64 rax, rbx, rcx, rdx;
    DWORD64 rsi, rdi, rbp, rsp;
    DWORD64 r8, r9, r10, r11;
    DWORD64 r12, r13, r14, r15;
    
    // Registri di controllo
    DWORD64 rip;
    DWORD64 rflags;
    DWORD64 cr0, cr2, cr3, cr4;
    
    // Registri di segmento
    WORD cs, ds, es, fs, gs, ss;
    
    // Registri MSR
    DWORD64 efer;
    DWORD64 star;
    DWORD64 lstar;
    DWORD64 cstar;
    
    // Stato FPU/SSE
    BYTE fxsave[512];
};

// Struttura per la memoria virtualizzata
struct VirtualMemory {
    BYTE* memory;
    size_t size;
    DWORD64 baseAddress;
    DWORD protection;
    bool mapped;
};

// Struttura per le interruzioni
struct InterruptDescriptor {
    WORD offset_low;
    WORD selector;
    BYTE ist;
    BYTE type_attr;
    WORD offset_middle;
    DWORD offset_high;
    DWORD reserved;
};

class HardwareVirtualization {
public:
    static HardwareVirtualization& getInstance();
    
    // Metodi principali
    bool initialize();
    bool setupVirtualization();
    bool emulateInstruction();
    bool cleanup();
    
    // Gestione CPU
    bool initializeCPU();
    bool setupVMCS();
    bool handleVMExit(DWORD exitReason);
    bool injectInterrupt(BYTE vector);
    
    // Gestione memoria
    bool allocateMemory(size_t size);
    bool mapMemory(void* hostAddr, DWORD64 guestAddr, size_t size);
    bool protectMemory(DWORD64 addr, size_t size, DWORD protection);
    
    // Emulazione istruzioni
    bool emulateSyscall();
    bool emulateIO();
    bool emulateCPUID();
    bool emulateRDTSC();
    
    // Protezioni
    bool setupEPT();
    bool configureVMCS();
    bool handleException();
    bool monitorMSR();

private:
    HardwareVirtualization();  // Singleton
    ~HardwareVirtualization();
    
    HardwareVirtualization(const HardwareVirtualization&) = delete;
    HardwareVirtualization& operator=(const HardwareVirtualization&) = delete;

    // Inizializzazione
    bool checkVTSupport();
    bool enableVTx();
    bool setupEPTTables();
    bool initializeIDT();
    
    // Gestione VMCS
    bool allocateVMCS();
    bool setupVMCSControls();
    bool setupVMCSHostState();
    bool setupVMCSGuestState();
    
    // Gestione memoria
    bool setupPageTables();
    bool handleEPTViolation();
    bool handlePageFault();
    
    // Emulazione
    bool decodeInstruction();
    bool executeInstruction();
    bool updateContext();
    
    // Protezioni
    bool setupMSRBitmap();
    bool setupIOBitmap();
    bool handleCRAccess();
    bool handleMSRAccess();
    
    // Utility
    bool isVMXSupported();
    bool isEPTSupported();
    bool isUREPSupported();
    DWORD64 getPhysicalAddress(DWORD64 virtualAddr);
    
    // Membri
    Logger& logger;
    bool initialized;
    CPUContext context;
    std::vector<VirtualMemory> virtualMemory;
    std::vector<InterruptDescriptor> idt;
    
    // Strutture VT-x
    void* vmxon_region;
    void* vmcs_region;
    void* ept_pml4;
    void* msr_bitmap;
    void* io_bitmap_a;
    void* io_bitmap_b;
    
    // Costanti
    static const size_t PAGE_SIZE = 4096;
    static const size_t VMCS_SIZE = 4096;
    static const size_t EPT_LEVELS = 4;
    static const DWORD MAX_INSTRUCTION_LEN = 15;
};

// Macro per virtualizzazione hardware
#define VIRTUALIZE_HARDWARE() \
    HardwareVirtualization::getInstance().setupVirtualization()

// Macro per emulazione CPU
#define EMULATE_CPU() \
    HardwareVirtualization::getInstance().emulateInstruction()

} // namespace uac_bypass

#endif // UAC_BYPASS_HARDWARE_VIRTUALIZATION_H