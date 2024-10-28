#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <machine/specialreg.h>
#include <sys/pcpu.h>
#include <sys/priv.h>
#include <sys/ioccom.h>  // For IOCTL command macros

#define IOCTL_SIOCTL_METHOD_BUFFERED _IOW('M', 1, char*)
#define IOCTL_SIOCTL_METHOD_NEITHER  _IOR('M', 2, char*)
#define IOCTL_SIOCTL_METHOD_IN_DIRECT _IOWR('M', 3, char*)
#define IOCTL_SIOCTL_METHOD_OUT_DIRECT _IOR('M', 4, char*)

#define DEVICE_NAME "Hypevisor"
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

static int
hypervisor_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
    printf("[*] hypervisor: Device opened\n");
    AsmEnableSvmOperation();
    printf("[*] SVM Operation Enabled Successfully!\n");
    return 0;
}

static int
hypervisor_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
    printf("[*] hypervisor: Device closed\n");
    return 0;
}

static int
hypervisor_read(struct cdev *dev, struct uio *uio, int ioflag)
{
    printf("[*] hypervisor: Read not implemented\n");
    return 0;
}

static int
hypervisor_write(struct cdev *dev, struct uio *uio, int ioflag)
{
    printf("[*] hypervisor: Write not implemented\n");
    return 0;
}

static int
hypervisor_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag, struct thread *td)
{
    char kernel_buffer[100];
    int error = 0;

    switch (cmd) {
    case IOCTL_SIOCTL_METHOD_BUFFERED:
        error = copyin(data, kernel_buffer, sizeof(kernel_buffer));
        if (error) return error;
        printf("[*] IOCTL METHOD_BUFFERED Called: %s\n", kernel_buffer);
        snprintf(kernel_buffer, sizeof(kernel_buffer), "Response from kernel - METHOD_BUFFERED");
        error = copyout(kernel_buffer, data, sizeof(kernel_buffer));
        break;

    case IOCTL_SIOCTL_METHOD_NEITHER:
        error = copyin(data, kernel_buffer, sizeof(kernel_buffer));
        if (error) return error;
        printf("[*] IOCTL METHOD_NEITHER Called: %s\n", kernel_buffer);
        snprintf(kernel_buffer, sizeof(kernel_buffer), "Response from kernel - METHOD_NEITHER");
        error = copyout(kernel_buffer, data, sizeof(kernel_buffer));
        break;

    case IOCTL_SIOCTL_METHOD_IN_DIRECT:
        error = copyin(data, kernel_buffer, sizeof(kernel_buffer));
        if (error) return error;
        printf("[*] IOCTL METHOD_IN_DIRECT Called: %s\n", kernel_buffer);
        snprintf(kernel_buffer, sizeof(kernel_buffer), "Response from kernel - METHOD_IN_DIRECT");
        error = copyout(kernel_buffer, data, sizeof(kernel_buffer));
        break;

    case IOCTL_SIOCTL_METHOD_OUT_DIRECT:
        error = copyin(data, kernel_buffer, sizeof(kernel_buffer));
        if (error) return error;
        printf("[*] IOCTL METHOD_OUT_DIRECT Called: %s\n", kernel_buffer);
        snprintf(kernel_buffer, sizeof(kernel_buffer), "Response from kernel - METHOD_OUT_DIRECT");
        error = copyout(kernel_buffer, data, sizeof(kernel_buffer));
        break;

    default:
        return ENOTTY;
    }
    return error;
}


static int
hypervisor_loader(struct module *m, int event, void *arg)
{
    int error = 0;
    switch (event) {
    case MOD_LOAD:
        printf("[*] Loading hypervisor module.\n");
        hypervisor_dev = make_dev(&hypervisor_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, DEVICE_NAME);
        if (!hypervisor_dev) {
            printf("Failed to create device node.\n");
            return ENOMEM;
        }
        break;
    case MOD_UNLOAD:
        printf("[*] Unloading hypervisor module.\n");
        if (hypervisor_dev) {
            destroy_dev(hypervisor_dev);
        }
        break;
    default:
        error = EOPNOTSUPP;
        break;
    }
    return error;
}

DEV_MODULE(hypervisor, hypervisor_loader, NULL);

