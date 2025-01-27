#ifndef UAC_BYPASS_VMX_DEFS_H
#define UAC_BYPASS_VMX_DEFS_H

// VM Exit Reasons
#define EXIT_REASON_EXCEPTION_NMI           0
#define EXIT_REASON_EXTERNAL_INTERRUPT      1
#define EXIT_REASON_TRIPLE_FAULT           2
#define EXIT_REASON_INIT                   3
#define EXIT_REASON_SIPI                   4
#define EXIT_REASON_IO_SMI                 5
#define EXIT_REASON_OTHER_SMI              6
#define EXIT_REASON_INTERRUPT_WINDOW       7
#define EXIT_REASON_NMI_WINDOW             8
#define EXIT_REASON_TASK_SWITCH            9
#define EXIT_REASON_CPUID                  10
#define EXIT_REASON_GETSEC                 11
#define EXIT_REASON_HLT                    12
#define EXIT_REASON_INVD                   13
#define EXIT_REASON_INVLPG                 14
#define EXIT_REASON_RDPMC                  15
#define EXIT_REASON_RDTSC                  16
#define EXIT_REASON_RSM                    17
#define EXIT_REASON_VMCALL                 18
#define EXIT_REASON_VMCLEAR                19
#define EXIT_REASON_VMLAUNCH               20
#define EXIT_REASON_VMPTRLD                21
#define EXIT_REASON_VMPTRST                22
#define EXIT_REASON_VMREAD                 23
#define EXIT_REASON_VMRESUME               24
#define EXIT_REASON_VMWRITE                25
#define EXIT_REASON_VMXOFF                 26
#define EXIT_REASON_VMXON                  27
#define EXIT_REASON_CR_ACCESS              28
#define EXIT_REASON_DR_ACCESS              29
#define EXIT_REASON_IO_INSTRUCTION         30
#define EXIT_REASON_MSR_READ               31
#define EXIT_REASON_MSR_WRITE              32
#define EXIT_REASON_INVALID_GUEST_STATE    33
#define EXIT_REASON_MSR_LOADING            34
#define EXIT_REASON_MWAIT_INSTRUCTION      36
#define EXIT_REASON_MONITOR_TRAP_FLAG      37
#define EXIT_REASON_MONITOR_INSTRUCTION    39
#define EXIT_REASON_PAUSE_INSTRUCTION      40
#define EXIT_REASON_MCE_DURING_VMENTRY     41
#define EXIT_REASON_TPR_BELOW_THRESHOLD    43
#define EXIT_REASON_APIC_ACCESS            44
#define EXIT_REASON_ACCESS_GDTR_OR_IDTR    46
#define EXIT_REASON_ACCESS_LDTR_OR_TR      47
#define EXIT_REASON_EPT_VIOLATION          48
#define EXIT_REASON_EPT_MISCONFIG          49
#define EXIT_REASON_INVEPT                 50
#define EXIT_REASON_RDTSCP                 51
#define EXIT_REASON_VMX_PREEMPTION_TIMER   52
#define EXIT_REASON_INVVPID                53
#define EXIT_REASON_WBINVD                 54
#define EXIT_REASON_XSETBV                 55
#define EXIT_REASON_APIC_WRITE             56
#define EXIT_REASON_RDRAND                 57
#define EXIT_REASON_INVPCID                58
#define EXIT_REASON_VMFUNC                 59
#define EXIT_REASON_ENCLS                  60
#define EXIT_REASON_RDSEED                 61
#define EXIT_REASON_PML_FULL               62
#define EXIT_REASON_XSAVES                 63
#define EXIT_REASON_XRSTORS                64

// VMCS Fields
#define VMCS_CTRL_VMENTRY_INTERRUPTION_INFO        0x00004016
#define VMCS_CTRL_VMENTRY_EXCEPTION_ERRORCODE      0x00004018
#define VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH       0x0000401A
#define VMCS_CTRL_EPT_POINTER                      0x0000201A

// VM Entry Controls
#define VM_ENTRY_LOAD_DEBUG_CONTROLS               0x00000004
#define VM_ENTRY_IA32E_MODE                        0x00000200
#define VM_ENTRY_SMM                               0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR               0x00000800

// VM Exit Controls
#define VM_EXIT_SAVE_DEBUG_CONTROLS               0x00000004
#define VM_EXIT_HOST_ADDR_SPACE_SIZE             0x00000200
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL       0x00001000
#define VM_EXIT_ACK_INTERRUPT_ON_EXIT            0x00008000
#define VM_EXIT_SAVE_IA32_PAT                    0x00040000
#define VM_EXIT_LOAD_IA32_PAT                    0x00080000
#define VM_EXIT_SAVE_IA32_EFER                   0x00100000
#define VM_EXIT_LOAD_IA32_EFER                   0x00200000
#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER        0x00400000

// Pin-Based VM-Execution Controls
#define PIN_BASED_EXTERNAL_INTERRUPT_EXITING     0x00000001
#define PIN_BASED_NMI_EXITING                    0x00000008
#define PIN_BASED_VIRTUAL_NMIS                   0x00000020
#define PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER  0x00000040
#define PIN_BASED_PROCESS_POSTED_INTERRUPTS      0x00000080

// Primary Processor-Based VM-Execution Controls
#define CPU_BASED_INTERRUPT_WINDOW_EXITING       0x00000004
#define CPU_BASED_USE_TSC_OFFSETTING             0x00000008
#define CPU_BASED_HLT_EXITING                    0x00000080
#define CPU_BASED_INVLPG_EXITING                 0x00000200
#define CPU_BASED_MWAIT_EXITING                  0x00000400
#define CPU_BASED_RDPMC_EXITING                  0x00000800
#define CPU_BASED_RDTSC_EXITING                  0x00001000
#define CPU_BASED_CR3_LOAD_EXITING               0x00008000
#define CPU_BASED_CR3_STORE_EXITING              0x00010000
#define CPU_BASED_CR8_LOAD_EXITING               0x00080000
#define CPU_BASED_CR8_STORE_EXITING              0x00100000
#define CPU_BASED_TPR_SHADOW                     0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING            0x00400000
#define CPU_BASED_MOV_DR_EXITING                 0x00800000
#define CPU_BASED_UNCOND_IO_EXITING              0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP             0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG              0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP            0x10000000
#define CPU_BASED_MONITOR_EXITING                0x20000000
#define CPU_BASED_PAUSE_EXITING                  0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS     0x80000000

#endif // UAC_BYPASS_VMX_DEFS_H