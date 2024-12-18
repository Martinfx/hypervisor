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

#include <vm/vm.h>
#include <vm/pmap.h>


#define EFER_ADDR 0xC0000080
#define VM_CR_ADDR 0xC0010114
#define VM_HSAVE_PA_ADDR 0xC0010117

enum SVM_SUPPORT {
    SVM_ALLOWED,
    SVM_NOT_AVAIL,
    SVM_DISABLED_AT_BIOS_NOT_UNLOCKABLE,
    SVM_DISABLED_WITH_KEY
};

void readMSR_U64(uint32_t id, uint64_t *complete);
void readMSR(uint32_t id, uint32_t *hi, uint32_t *lo);
void writeMSR(uint32_t id, uint32_t hi, uint32_t lo);

void inline AsmEnableSvmOperation(void);
enum SVM_SUPPORT hasSvmSupport(void);
bool isSvmDisabled_VM_CR(void);

int vmm_init(void);

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

bool isSvmDisabled_VM_CR(void) {
    uint32_t vm_cr;
    uint32_t high;

    // Read VM_CR MSR
    readMSR(VM_CR_ADDR, &high, &vm_cr);

    printf("[+] Is SVM Lock enabled: %s\n",
           vm_cr & (1 << 3) ? "true" : "false");

    return (bool)(vm_cr & (1 << 4));
}

enum SVM_SUPPORT hasSvmSupport(void) {
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
void inline AsmEnableSvmOperation(void) {
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

  /*  vmm_host_state_init();
    if(!vm_run()){
        printf("[-] vm run failed!");
        return 1;
    }
*/
    return error;
}
/*
void free_vmcb(void) {
    if (vmcb) {
        free(vmcb, M_DEVBUF);
        vmcb = NULL;
        printf("[*] VMCB uvolněno.\n");
    }
}*/
static int
hypervisor_loader(module_t mod, int what, void *arg)
{
    int error = 0;
    switch (what) {
    case MOD_LOAD:
        printf("[*] Loading hypervisor module.\n");
        error = vmm_init();
        break;
    case MOD_UNLOAD:
        printf("[*] Unloading hypervisor module.\n");
 //       free(vmcb, M_DEVBUF);
 //       free(hsave, M_DEVBUF);
        break;
    case MOD_SHUTDOWN:
        printf("[*] Shutdown hypervisor module.\n");
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
