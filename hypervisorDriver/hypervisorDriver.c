#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/pcpu.h>
#include <sys/priv.h>
#include <sys/ioccom.h>  // For IOCTL command macros
#include <sys/types.h>
#include <sys/bus.h>
#include <sys/interrupt.h>
#include <sys/smp.h>

#include <machine/specialreg.h>
#include <machine/cpufunc.h>
#include <machine/segments.h>
#include <machine/intr_machdep.h>
#include <machine/segments.h>
#include <machine/md_var.h>
#include <machine/smp.h>
//#include <x86/apicvar.h>

void vmm_host_state_init(void);
int vmm_init(void);
void vmm_ipi_init(void);
void vmm_ipi_cleanup(void);
bool hasMsrSupport(void);
void readMSR_U64(uint32_t id, uint64_t *complete);
void readMSR(uint32_t id, uint32_t *hi, uint32_t *lo);
void writeMSR(uint32_t id, uint32_t hi, uint32_t lo);
bool isSvmDisabled_VM_CR(void);
uint32_t get_max_asids(void);
bool vm_run(void);

//
// A size of two the MSR permissions map.
//
#define SVM_MSR_PERMISSIONS_MAP_SIZE    (PAGE_SIZE * 2)

//
// See "SVM Related MSRs"
//
#define SVM_MSR_VM_CR                   0xc0010114
#define SVM_MSR_VM_HSAVE_PA             0xc0010117

#define SVM_VM_CR_SVMDIS                (1UL << 4)

//
// See "VMCB Layout, Control Area"
//
#define SVM_INTERCEPT_MISC1_CPUID       (1UL << 18)
#define SVM_INTERCEPT_MISC1_MSR_PROT    (1UL << 28)
#define SVM_INTERCEPT_MISC2_VMRUN       (1UL << 0)
#define SVM_NP_ENABLE_NP_ENABLE         (1UL << 0)

typedef struct _VMCB_CONTROL_AREA
{
    uint16_t InterceptCrRead;             // +0x000
    uint16_t InterceptCrWrite;            // +0x002
    uint16_t InterceptDrRead;             // +0x004
    uint16_t InterceptDrWrite;            // +0x006
    uint32_t InterceptException;          // +0x008
    uint32_t InterceptMisc1;              // +0x00c
    uint32_t InterceptMisc2;              // +0x010
    uint8_t Reserved1[0x03c - 0x014];     // +0x014
    uint16_t PauseFilterThreshold;        // +0x03c
    uint16_t PauseFilterCount;            // +0x03e
    uint64_t IopmBasePa;                  // +0x040
    uint64_t MsrpmBasePa;                 // +0x048
    uint64_t TscOffset;                   // +0x050
    uint32_t GuestAsid;                   // +0x058
    uint32_t TlbControl;                  // +0x05c
    uint64_t VIntr;                       // +0x060
    uint64_t InterruptShadow;             // +0x068
    uint64_t ExitCode;                    // +0x070
    uint64_t ExitInfo1;                   // +0x078
    uint64_t ExitInfo2;                   // +0x080
    uint64_t ExitIntInfo;                 // +0x088
    uint64_t NpEnable;                    // +0x090
    uint64_t AvicApicBar;                 // +0x098
    uint64_t GuestPaOfGhcb;               // +0x0a0
    uint64_t EventInj;                    // +0x0a8
    uint64_t NCr3;                        // +0x0b0
    uint64_t LbrVirtualizationEnable;     // +0x0b8
    uint64_t VmcbClean;                   // +0x0c0
    uint64_t NRip;                        // +0x0c8
    uint8_t NumOfBytesFetched;            // +0x0d0
    uint8_t GuestInstructionBytes[15];    // +0x0d1
    uint64_t AvicApicBackingPagePointer;  // +0x0e0
    uint64_t Reserved2;                   // +0x0e8
    uint64_t AvicLogicalTablePointer;     // +0x0f0
    uint64_t AvicPhysicalTablePointer;    // +0x0f8
    uint64_t Reserved3;                   // +0x100
    uint64_t VmcbSaveStatePointer;        // +0x108
    uint8_t Reserved4[0x400 - 0x110];     // +0x110
} VMCB_CONTROL_AREA, *PVMCB_CONTROL_AREA;
_Static_assert(sizeof(VMCB_CONTROL_AREA) == 0x400,
              "VMCB_CONTROL_AREA Size Mismatch");

//
// See "VMCB Layout, State Save Area"
//
typedef struct _VMCB_STATE_SAVE_AREA
{
    uint16_t EsSelector;                  // +0x000
    uint16_t EsAttrib;                    // +0x002
    uint32_t EsLimit;                     // +0x004
    uint64_t EsBase;                      // +0x008
    uint16_t CsSelector;                  // +0x010
    uint16_t CsAttrib;                    // +0x012
    uint32_t CsLimit;                     // +0x014
    uint64_t CsBase;                      // +0x018
    uint16_t SsSelector;                  // +0x020
    uint16_t SsAttrib;                    // +0x022
    uint32_t SsLimit;                     // +0x024
    uint64_t SsBase;                      // +0x028
    uint16_t DsSelector;                  // +0x030
    uint16_t DsAttrib;                    // +0x032
    uint32_t DsLimit;                     // +0x034
    uint64_t DsBase;                      // +0x038
    uint16_t FsSelector;                  // +0x040
    uint16_t FsAttrib;                    // +0x042
    uint32_t FsLimit;                     // +0x044
    uint64_t FsBase;                      // +0x048
    uint16_t GsSelector;                  // +0x050
    uint16_t GsAttrib;                    // +0x052
    uint32_t GsLimit;                     // +0x054
    uint64_t GsBase;                      // +0x058
    uint16_t GdtrSelector;                // +0x060
    uint16_t GdtrAttrib;                  // +0x062
    uint32_t GdtrLimit;                   // +0x064
    uint64_t GdtrBase;                    // +0x068
    uint16_t LdtrSelector;                // +0x070
    uint16_t LdtrAttrib;                  // +0x072
    uint32_t LdtrLimit;                   // +0x074
    uint64_t LdtrBase;                    // +0x078
    uint16_t IdtrSelector;                // +0x080
    uint16_t IdtrAttrib;                  // +0x082
    uint32_t IdtrLimit;                   // +0x084
    uint64_t IdtrBase;                    // +0x088
    uint16_t TrSelector;                  // +0x090
    uint16_t TrAttrib;                    // +0x092
    uint32_t TrLimit;                     // +0x094
    uint64_t TrBase;                      // +0x098
    uint8_t Reserved1[0x0cb - 0x0a0];     // +0x0a0
    uint8_t Cpl;                          // +0x0cb
    uint32_t Reserved2;                   // +0x0cc
    uint64_t Efer;                        // +0x0d0
    uint8_t Reserved3[0x148 - 0x0d8];     // +0x0d8
    uint64_t Cr4;                         // +0x148
    uint64_t Cr3;                         // +0x150
    uint64_t Cr0;                         // +0x158
    uint64_t Dr7;                         // +0x160
    uint64_t Dr6;                         // +0x168
    uint64_t Rflags;                      // +0x170
    uint64_t Rip;                         // +0x178
    uint8_t Reserved4[0x1d8 - 0x180];     // +0x180
    uint64_t Rsp;                         // +0x1d8
    uint8_t Reserved5[0x1f8 - 0x1e0];     // +0x1e0
    uint64_t Rax;                         // +0x1f8
    uint64_t Star;                        // +0x200
    uint64_t LStar;                       // +0x208
    uint64_t CStar;                       // +0x210
    uint64_t SfMask;                      // +0x218
    uint64_t KernelGsBase;                // +0x220
    uint64_t SysenterCs;                  // +0x228
    uint64_t SysenterEsp;                 // +0x230
    uint64_t SysenterEip;                 // +0x238
    uint64_t Cr2;                         // +0x240
    uint8_t Reserved6[0x268 - 0x248];     // +0x248
    uint64_t GPat;                        // +0x268
    uint64_t DbgCtl;                      // +0x270
    uint64_t BrFrom;                      // +0x278
    uint64_t BrTo;                        // +0x280
    uint64_t LastExcepFrom;               // +0x288
    uint64_t LastExcepTo;                 // +0x290
} VMCB_STATE_SAVE_AREA, *PVMCB_STATE_SAVE_AREA;
_Static_assert(sizeof(VMCB_STATE_SAVE_AREA) == 0x298,
              "VMCB_STATE_SAVE_AREA Size Mismatch");

//
// An entire VMCB (Virtual machine control block) layout.
//
typedef struct _VMCB
{
    VMCB_CONTROL_AREA ControlArea;
    VMCB_STATE_SAVE_AREA StateSaveArea;
    uint8_t Reserved1[0x1000 - sizeof(VMCB_CONTROL_AREA) - sizeof(VMCB_STATE_SAVE_AREA)];
} VMCB, *PVMCB;
_Static_assert(sizeof(VMCB) == 0x1000,
              "VMCB Size Mismatch");

//
// See "Event Injection"
//
typedef struct _EVENTINJ
{
    union
    {
        uint64_t Asuint64_t;
        struct
        {
            uint64_t Vector : 8;          // [0:7]
            uint64_t Type : 3;            // [8:10]
            uint64_t ErrorCodeValid : 1;  // [11]
            uint64_t Reserved1 : 19;      // [12:30]
            uint64_t Valid : 1;           // [31]
            uint64_t ErrorCode : 32;      // [32:63]
        } Fields;
    };
} EVENTINJ, *PEVENTINJ;
_Static_assert(sizeof(EVENTINJ) == 8,
              "EVENTINJ Size Mismatch");

//
// See "SVM Intercept Codes"
//
#define VMEXIT_CR0_READ             0x0000
#define VMEXIT_CR1_READ             0x0001
#define VMEXIT_CR2_READ             0x0002
#define VMEXIT_CR3_READ             0x0003
#define VMEXIT_CR4_READ             0x0004
#define VMEXIT_CR5_READ             0x0005
#define VMEXIT_CR6_READ             0x0006
#define VMEXIT_CR7_READ             0x0007
#define VMEXIT_CR8_READ             0x0008
#define VMEXIT_CR9_READ             0x0009
#define VMEXIT_CR10_READ            0x000a
#define VMEXIT_CR11_READ            0x000b
#define VMEXIT_CR12_READ            0x000c
#define VMEXIT_CR13_READ            0x000d
#define VMEXIT_CR14_READ            0x000e
#define VMEXIT_CR15_READ            0x000f
#define VMEXIT_CR0_WRITE            0x0010
#define VMEXIT_CR1_WRITE            0x0011
#define VMEXIT_CR2_WRITE            0x0012
#define VMEXIT_CR3_WRITE            0x0013
#define VMEXIT_CR4_WRITE            0x0014
#define VMEXIT_CR5_WRITE            0x0015
#define VMEXIT_CR6_WRITE            0x0016
#define VMEXIT_CR7_WRITE            0x0017
#define VMEXIT_CR8_WRITE            0x0018
#define VMEXIT_CR9_WRITE            0x0019
#define VMEXIT_CR10_WRITE           0x001a
#define VMEXIT_CR11_WRITE           0x001b
#define VMEXIT_CR12_WRITE           0x001c
#define VMEXIT_CR13_WRITE           0x001d
#define VMEXIT_CR14_WRITE           0x001e
#define VMEXIT_CR15_WRITE           0x001f
#define VMEXIT_DR0_READ             0x0020
#define VMEXIT_DR1_READ             0x0021
#define VMEXIT_DR2_READ             0x0022
#define VMEXIT_DR3_READ             0x0023
#define VMEXIT_DR4_READ             0x0024
#define VMEXIT_DR5_READ             0x0025
#define VMEXIT_DR6_READ             0x0026
#define VMEXIT_DR7_READ             0x0027
#define VMEXIT_DR8_READ             0x0028
#define VMEXIT_DR9_READ             0x0029
#define VMEXIT_DR10_READ            0x002a
#define VMEXIT_DR11_READ            0x002b
#define VMEXIT_DR12_READ            0x002c
#define VMEXIT_DR13_READ            0x002d
#define VMEXIT_DR14_READ            0x002e
#define VMEXIT_DR15_READ            0x002f
#define VMEXIT_DR0_WRITE            0x0030
#define VMEXIT_DR1_WRITE            0x0031
#define VMEXIT_DR2_WRITE            0x0032
#define VMEXIT_DR3_WRITE            0x0033
#define VMEXIT_DR4_WRITE            0x0034
#define VMEXIT_DR5_WRITE            0x0035
#define VMEXIT_DR6_WRITE            0x0036
#define VMEXIT_DR7_WRITE            0x0037
#define VMEXIT_DR8_WRITE            0x0038
#define VMEXIT_DR9_WRITE            0x0039
#define VMEXIT_DR10_WRITE           0x003a
#define VMEXIT_DR11_WRITE           0x003b
#define VMEXIT_DR12_WRITE           0x003c
#define VMEXIT_DR13_WRITE           0x003d
#define VMEXIT_DR14_WRITE           0x003e
#define VMEXIT_DR15_WRITE           0x003f
#define VMEXIT_EXCEPTION_DE         0x0040
#define VMEXIT_EXCEPTION_DB         0x0041
#define VMEXIT_EXCEPTION_NMI        0x0042
#define VMEXIT_EXCEPTION_BP         0x0043
#define VMEXIT_EXCEPTION_OF         0x0044
#define VMEXIT_EXCEPTION_BR         0x0045
#define VMEXIT_EXCEPTION_UD         0x0046
#define VMEXIT_EXCEPTION_NM         0x0047
#define VMEXIT_EXCEPTION_DF         0x0048
#define VMEXIT_EXCEPTION_09         0x0049
#define VMEXIT_EXCEPTION_TS         0x004a
#define VMEXIT_EXCEPTION_NP         0x004b
#define VMEXIT_EXCEPTION_SS         0x004c
#define VMEXIT_EXCEPTION_GP         0x004d
#define VMEXIT_EXCEPTION_PF         0x004e
#define VMEXIT_EXCEPTION_15         0x004f
#define VMEXIT_EXCEPTION_MF         0x0050
#define VMEXIT_EXCEPTION_AC         0x0051
#define VMEXIT_EXCEPTION_MC         0x0052
#define VMEXIT_EXCEPTION_XF         0x0053
#define VMEXIT_EXCEPTION_20         0x0054
#define VMEXIT_EXCEPTION_21         0x0055
#define VMEXIT_EXCEPTION_22         0x0056
#define VMEXIT_EXCEPTION_23         0x0057
#define VMEXIT_EXCEPTION_24         0x0058
#define VMEXIT_EXCEPTION_25         0x0059
#define VMEXIT_EXCEPTION_26         0x005a
#define VMEXIT_EXCEPTION_27         0x005b
#define VMEXIT_EXCEPTION_28         0x005c
#define VMEXIT_EXCEPTION_VC         0x005d
#define VMEXIT_EXCEPTION_SX         0x005e
#define VMEXIT_EXCEPTION_31         0x005f
#define VMEXIT_INTR                 0x0060
#define VMEXIT_NMI                  0x0061
#define VMEXIT_SMI                  0x0062
#define VMEXIT_INIT                 0x0063
#define VMEXIT_VINTR                0x0064
#define VMEXIT_CR0_SEL_WRITE        0x0065
#define VMEXIT_IDTR_READ            0x0066
#define VMEXIT_GDTR_READ            0x0067
#define VMEXIT_LDTR_READ            0x0068
#define VMEXIT_TR_READ              0x0069
#define VMEXIT_IDTR_WRITE           0x006a
#define VMEXIT_GDTR_WRITE           0x006b
#define VMEXIT_LDTR_WRITE           0x006c
#define VMEXIT_TR_WRITE             0x006d
#define VMEXIT_RDTSC                0x006e
#define VMEXIT_RDPMC                0x006f
#define VMEXIT_PUSHF                0x0070
#define VMEXIT_POPF                 0x0071
#define VMEXIT_CPUID                0x0072
#define VMEXIT_RSM                  0x0073
#define VMEXIT_IRET                 0x0074
#define VMEXIT_SWINT                0x0075
#define VMEXIT_INVD                 0x0076
#define VMEXIT_PAUSE                0x0077
#define VMEXIT_HLT                  0x0078
#define VMEXIT_INVLPG               0x0079
#define VMEXIT_INVLPGA              0x007a
#define VMEXIT_IOIO                 0x007b
#define VMEXIT_MSR                  0x007c
#define VMEXIT_TASK_SWITCH          0x007d
#define VMEXIT_FERR_FREEZE          0x007e
#define VMEXIT_SHUTDOWN             0x007f
#define VMEXIT_VMRUN                0x0080
#define VMEXIT_VMMCALL              0x0081
#define VMEXIT_VMLOAD               0x0082
#define VMEXIT_VMSAVE               0x0083
#define VMEXIT_STGI                 0x0084
#define VMEXIT_CLGI                 0x0085
#define VMEXIT_SKINIT               0x0086
#define VMEXIT_RDTSCP               0x0087
#define VMEXIT_ICEBP                0x0088
#define VMEXIT_WBINVD               0x0089
#define VMEXIT_MONITOR              0x008a
#define VMEXIT_MWAIT                0x008b
#define VMEXIT_MWAIT_CONDITIONAL    0x008c
#define VMEXIT_XSETBV               0x008d
#define VMEXIT_EFER_WRITE_TRAP      0x008f
#define VMEXIT_CR0_WRITE_TRAP       0x0090
#define VMEXIT_CR1_WRITE_TRAP       0x0091
#define VMEXIT_CR2_WRITE_TRAP       0x0092
#define VMEXIT_CR3_WRITE_TRAP       0x0093
#define VMEXIT_CR4_WRITE_TRAP       0x0094
#define VMEXIT_CR5_WRITE_TRAP       0x0095
#define VMEXIT_CR6_WRITE_TRAP       0x0096
#define VMEXIT_CR7_WRITE_TRAP       0x0097
#define VMEXIT_CR8_WRITE_TRAP       0x0098
#define VMEXIT_CR9_WRITE_TRAP       0x0099
#define VMEXIT_CR10_WRITE_TRAP      0x009a
#define VMEXIT_CR11_WRITE_TRAP      0x009b
#define VMEXIT_CR12_WRITE_TRAP      0x009c
#define VMEXIT_CR13_WRITE_TRAP      0x009d
#define VMEXIT_CR14_WRITE_TRAP      0x009e
#define VMEXIT_CR15_WRITE_TRAP      0x009f
#define VMEXIT_NPF                  0x0400
#define AVIC_INCOMPLETE_IPI         0x0401
#define AVIC_NOACCEL                0x0402
#define VMEXIT_VMGEXIT              0x0403
#define VMEXIT_INVALID              -1

/*#define DEVICE_NAME "Hypervisor"
static struct cdev *hypervisor_dev;

static d_open_t     hypervisor_open;
static d_close_t    hypervisor_close;
static d_read_t     hypervisor_read;
static d_write_t    hypervisor_write;

static struct cdevsw hypervisor_cdevsw = {
    .d_version = D_VERSION,
    .d_open = hypervisor_open,
    .d_close = hypervisor_close,
    .d_read = hypervisor_read,
    .d_write = hypervisor_write,
    .d_name = DEVICE_NAME,
};
*/

#define EFER_ADDR 0xC0000080
#define VM_CR_ADDR 0xC0010114
#define VM_HSAVE_PA_ADDR 0xC0010117

enum SVM_SUPPORT {
    SVM_ALLOWED,
    SVM_NOT_AVAIL,
    SVM_DISABLED_AT_BIOS_NOT_UNLOCKABLE,
    SVM_DISABLED_WITH_KEY
};

bool isSvmDisabled_VM_CR(void) {
    uint32_t vm_cr;
    uint32_t high;

    // Read VM_CR MSR
    readMSR(VM_CR_ADDR, &high, &vm_cr);

    printf("[+] Is SVM Lock enabled: %s\n",
           vm_cr & (1 << 3) ? "true" : "false");

    return (bool)(vm_cr & (1 << 4));
}

static enum SVM_SUPPORT hasSvmSupport(void) {
    uint32_t cpuid_response;

    // Získání CPUID pro kontrolu podpory SVM
    __asm __volatile (
        "mov $0x80000001, %%eax\n\t"
        "cpuid\n\t"
        "mov %%ecx, %0\n\t"
        : "=r" (cpuid_response)
        :
        : "rax", "rbx", "rcx", "rdx"
        );

    // Kontrola, zda je SVM rozšíření k dispozici
    if (!(cpuid_response & 0x2)) {
        return SVM_NOT_AVAIL;
    }

    // Kontrola, zda je SVM povoleno
    if (!isSvmDisabled_VM_CR()) {
        return SVM_ALLOWED;
    }

    // Získání CPUID pro kontrolu, zda je SVM zakázáno v BIOSu
    __asm __volatile (
        "mov $0x8000000A, %%eax\n\t"
        "cpuid\n\t"
        "mov %%edx, %0\n\t"
        : "=r" (cpuid_response)
        :
        : "rax", "rbx", "rcx", "rdx"
        );

    // Kontrola, zda je SVM zakázáno v BIOSu
    if ((cpuid_response & 0x2) == 0) {
        return SVM_DISABLED_AT_BIOS_NOT_UNLOCKABLE;
    } else {
        return SVM_DISABLED_WITH_KEY;
    }
}

// Function to enable AMD-V by setting the SVM bit (12th bit) in the EFER register
static void inline AsmEnableSvmOperation(void) {
    __asm__ __volatile__ (
        "mov $0xC0000080, %%ecx\n"  // EFER MSR address
        "rdmsr\n"                   // Read the current value of EFER into EAX:EDX
        "or $0x1000, %%eax\n"       // Set the 12th bit in EAX (SVM enable)
        "wrmsr\n"                   // Write the modified value back to EFER
        :
        :
        : "eax", "ecx", "edx"
        );
}

// Function to enable VMX operation by setting the 14th bit of CR4
static void inline AsmEnableVmxOperation(void) {
    __asm__ __volatile__ (
        "mov %%cr4, %%rax\n"         // Move CR4 into RAX
        "or $0x2000, %%rax\n"        // Set the 14th bit in RAX (for VMX)
        "mov %%rax, %%cr4\n"         // Move the modified value back into CR4
        :
        :
        : "rax"
        );
}

bool inline hasMsrSupport(void) {
    uint32_t cpuid_response;

    __asm__ __volatile__ (
        "mov $0x00000001, %%eax\n\t"   // Nastav EAX na 1 pro CPUID funkci 1
        "cpuid\n\t"                     // Zavolej CPUID
        "mov %%edx, %0\n\t"             // Ulož obsah registru EDX do cpuid_response
        : "=r" (cpuid_response)         // Výstupní operandy
        :                               // Žádné vstupní operandy
        : "rax", "rbx", "rcx", "rdx"    // Clobber list - registry, které mohou být změněny
        );

    return (cpuid_response & (1 << 5)) != 0;  // Kontrola 5. bitu v EDX
}

void readMSR_U64(uint32_t id, uint64_t *complete) {
    uint32_t hi, lo;

    __asm __volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(id));

    *complete = ((uint64_t)hi << 32) | lo;
}

void readMSR(uint32_t id, uint32_t *hi, uint32_t *lo) {
    __asm __volatile("rdmsr" : "=a"(*lo), "=d"(*hi) : "c"(id));
}

void writeMSR(uint32_t id, uint32_t hi, uint32_t lo) {
    __asm __volatile("wrmsr" : : "a"(lo), "d"(hi), "c"(id));
}

static uint64_t vmm_host_efer, vmm_host_pat, vmm_host_cr0, vmm_host_cr4;

extern inthand_t IDTVEC(rsvd), IDTVEC(justreturn);

/*
 * The default is to use the IPI_AST to interrupt a vcpu.
 */
int vmm_ipinum = IPI_AST;

CTASSERT(APIC_SPURIOUS_INT == 255);

void
vmm_ipi_init(void)
{
    int idx;
    uintptr_t func;
    struct gate_descriptor *ip;

    /*
     * Search backwards from the highest IDT vector available for use
     * as our IPI vector. We install the 'justreturn' handler at that
     * vector and use it to interrupt the vcpus.
     *
     * We do this because the IPI_AST is heavyweight and saves all
     * registers in the trapframe. This is overkill for our use case
     * which is simply to EOI the interrupt and return.
     */
    idx = APIC_SPURIOUS_INT;
    while (--idx >= APIC_IPI_INTS) {
        ip = &idt[idx];
        func = ((long)ip->gd_hioffset << 16 | ip->gd_looffset);
        if (func == (uintptr_t)&IDTVEC(rsvd)) {
            vmm_ipinum = idx;
            setidt(vmm_ipinum, IDTVEC(justreturn), SDT_SYSIGT,
                   SEL_KPL, 0);
            break;
        }
    }

    if (vmm_ipinum != IPI_AST && bootverbose) {
        printf("vmm_ipi_init: installing ipi handler to interrupt "
               "vcpus at vector %d\n", vmm_ipinum);
    }
}

void
vmm_ipi_cleanup(void)
{
    if (vmm_ipinum != IPI_AST)
        setidt(vmm_ipinum, IDTVEC(rsvd), SDT_SYSIGT, SEL_KPL, 0);
}

void
vmm_host_state_init(void)
{
    vmm_host_efer = rdmsr(MSR_EFER);
    vmm_host_pat = rdmsr(MSR_PAT);
    vmm_host_cr0 = rcr0() | CR0_TS;
    vmm_host_cr4 = rcr4();
}

void inline enableSVM_EFER(void) {
    uint32_t efer;
    uint32_t high;
    uint64_t cr0;
    uint64_t cs;

    // read MSR EFER
    readMSR(EFER_ADDR, &high, &efer);
    printf("[*] Is EFER.SVM enabled: %s\n",
           (efer & (1 << 12)) ? "true" : "false");

    // control protected mode memory (Protected Mode)
    __asm __volatile__("mov %%cr0, %0" : "=r" (cr0));
    printf("[*] Is protected mode enabled: %s\n",
           (cr0 & 1) ? "true" : "false");

    // read CPL (Current Privilege Level)
    __asm __volatile__("mov %%cs, %0" : "=r" (cs));
    printf("[*] DPL is: %lu\n", cs & ((1 << 13) | (1 << 14)));

    // enalble EFER.SVM set bit 12
    efer |= 1 << 12;
    writeMSR(EFER_ADDR, high, efer);
}

uint32_t get_max_asids(void) {
    unsigned int cpuid_response;

    __asm __volatile__(
        "mov $0x8000000A, %%eax\n\t"
        "cpuid\n\t"
        "mov %%ebx, %0\n\t"
        : "=r" (cpuid_response)
        :
        : "rax", "rbx", "rcx", "rdx"
        );

    return cpuid_response;
}

static void *vmcb = NULL;
static void *hsave = NULL;


bool vm_run(void) {
   /* uint32_t hsave_high;
    uint32_t hsave_low;
    uint32_t max_asids;
    */
    vmcb = malloc(4096, M_DEVBUF, M_WAITOK | M_ZERO);
    printf("vmcb pointer: %p\n", vmcb);

    if (vmcb == NULL) {
        printf("[-] Could not allocate memory for vmcb\n");
        return false;
    }

    if ((uint64_t)vmcb % 4096 != 0) {
        printf("[-] VMCB is not 4k aligned!\n");
        return false;
    }

    // allocation memory for hsave (4 KB)
    hsave = malloc(4096, M_DEVBUF, M_WAITOK | M_ZERO);
    printf("[*] hsave pointer is: %p\n", hsave);

    if (hsave == NULL) {
        printf("[-] Could not allocate memory for HSAVE\n");
        return false;
    }

    if (((uint64_t)hsave & 0xfff) > 0) {
        printf("[-] The low 12 bits are not zero!\n");
        return false;
    }

    if ((uint64_t)hsave % 4096 != 0) {
        printf("[-]  HSAVE is not 4k aligned!\n");
        return false;
    }

    enableSVM_EFER();

    uint32_t hsave_high = (uint32_t)((uint64_t)hsave >> 32);
    uint32_t hsave_low = (uint32_t)((uint64_t)hsave & 0xFFFFFFFF);
    uint32_t max_asids;

    // Zápis adresy bufferu do HSAVE MSR
    writeMSR(VM_HSAVE_PA_ADDR, hsave_high, hsave_low);

    // Čtení zpět z MSR a kontrola hodnoty
    readMSR_U64(VM_HSAVE_PA_ADDR, (uint64_t *)hsave);
    printf("VM_HSAVE_PA_ADDR: %p\n", hsave);

    // Čtení maximálního počtu ASID
    max_asids = get_max_asids();
    max_asids -= 1;

    // Nastavení ASID ve VMCB
    memcpy((char*)vmcb + 0x58, &max_asids, sizeof(uint32_t));

    // Provádění instrukce VMRUN
    printf("Start executing vmrun\n");
    __asm __volatile__(
        "mov %0, %%rax\n\t"
        "vmrun\n\t"
        :
        : "r" (vmcb)
        : "rax"
        );
    printf("Done executing vmrun\n");

    return true;
}


int
vmm_init(void) {
    enum SVM_SUPPORT svm;
    int error = 0;
    AsmEnableSvmOperation();
    if(hasMsrSupport())
    {
        printf("[*] has msr support.\n");
    }

    svm = hasSvmSupport();
    switch (svm) {
    case SVM_ALLOWED:
        printf("[*] Has SVM support: true\n");
        break;
    case SVM_NOT_AVAIL:
        printf("[-] Has SVM support: false\n");
        return 1;
    case SVM_DISABLED_WITH_KEY:
        printf("[-] SVM is bios disabled with key\n");
        return 1;
    case SVM_DISABLED_AT_BIOS_NOT_UNLOCKABLE:
        printf("[-] SVM is bios disabled not unlockable\n");
        return 1;
    }

    vmm_host_state_init();
    if(!vm_run()){
        printf("[-] vm run failed!");
        return 1;
    }

    return error;
}

static int
hypervisor_loader(module_t mod, int what, void *arg)
{
    int error = 0;
    switch (what) {
    case MOD_LOAD:
        printf("[*] Loading hypervisor module.\n");
        error = vmm_init();

    case MOD_UNLOAD:
        printf("[*] Unloading hypervisor module.\n");
        free(vmcb, M_DEVBUF);
        free(hsave, M_DEVBUF);
        break;
    default:
        error = EOPNOTSUPP;
        break;
    }
    return error;
}

static moduledata_t hypervisor_kmod = {
    "hypervisor",
    hypervisor_loader,
    NULL
};

DECLARE_MODULE(hypervisor_loader, hypervisor_kmod, SI_SUB_SMP + 1, SI_ORDER_ANY);
MODULE_VERSION(hypervisor_loader, 1);
