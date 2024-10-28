#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#define IOCTL_SIOCTL_METHOD_BUFFERED _IOW('M', 1, char*)
#define IOCTL_SIOCTL_METHOD_NEITHER  _IOR('M', 2, char*)
#define IOCTL_SIOCTL_METHOD_IN_DIRECT _IOWR('M', 3, char*)
#define IOCTL_SIOCTL_METHOD_OUT_DIRECT _IOR('M', 4, char*)

void GetCpuID(char *vendor)
{
    unsigned int eax, ebx, ecx, edx;

    // Execute CPUID with EAX=0 to get the CPU vendor ID
    __asm__ __volatile__(
        "cpuid"
        : "=b"(ebx), "=c"(ecx), "=d"(edx) // Output registers
        : "a"(0)                          // Input: EAX=0
        );

    // Copy the CPU vendor string into the provided buffer
    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);
    vendor[12] = '\0'; // Null-terminate the string
}

int DetectVmxSupport()
{
    unsigned int eax, ebx, ecx, edx;

    // Execute CPUID with EAX=1 to get feature information
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) // Output registers
        : "a"(1)                                     // Input: EAX=1
        );

    // Check if the 5th bit of ECX is set, which indicates VMX support
    return (ecx & (1 << 5)) != 0;
}

int DetectkAmdVSupport() {
    unsigned int eax, ebx, ecx, edx;

    // CPUID with EAX=0x80000001 for AMD-V support in ECX (bit 2)
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x80000001)
        );

    // Check if the SVM bit (bit 2 of ECX) is set
    return (ecx & (1 << 2)) != 0;
}

void TestIoctl(int fd)
{
    char input_buffer[100] = "Message from user program";
    char output_buffer[100] = {0};

    printf("Calling IOCTL METHOD_BUFFERED:\n");
    if (ioctl(fd, IOCTL_SIOCTL_METHOD_BUFFERED, input_buffer) == -1) {
        perror("IOCTL METHOD_BUFFERED failed");
    } else {
        printf("Output: %s\n", input_buffer);
    }

    printf("Calling IOCTL METHOD_NEITHER:\n");
    if (ioctl(fd, IOCTL_SIOCTL_METHOD_NEITHER, output_buffer) == -1) {
        perror("IOCTL METHOD_NEITHER failed");
    } else {
        printf("Output: %s\n", output_buffer);
    }

    printf("Calling IOCTL METHOD_IN_DIRECT:\n");
    if (ioctl(fd, IOCTL_SIOCTL_METHOD_IN_DIRECT, input_buffer) == -1) {
        perror("IOCTL METHOD_IN_DIRECT failed");
    } else {
        printf("Output: %s\n", input_buffer);
    }

    printf("Calling IOCTL METHOD_OUT_DIRECT:\n");
    if (ioctl(fd, IOCTL_SIOCTL_METHOD_OUT_DIRECT, output_buffer) == -1) {
        perror("IOCTL METHOD_OUT_DIRECT failed");
    } else {
        printf("Output: %s\n", output_buffer);
    }
}

int main()
{
    char CpuId[13];


    GetCpuID(CpuId);

    printf("[*] The CPU Vendor is : %s\n", CpuId);

    if (strcmp(CpuId, "GenuineIntel") == 0)
    {
        printf("[*] The Processor virtualization technology is VT-x. \n");
    }
  /*  else
    {
        printf("[*] This program is not designed to run in a non-VT-x environment!\n");
        return 1;
    }*/

    if (DetectVmxSupport())
    {
        printf("[*] VMX Operation is supported by your processor.\n");
    }
    else
    {
        printf("[-] VMX Operation is not supported by your processor.\n");
        //return 1;
    }

    if(DetectkAmdVSupport()) {
        std::cout << "[+] AMDV operation is supported.\n";
    }
    else{
        std::cout << "[-] AMDV operation is not supported.\n";
    }

    // Open device file in FreeBSD (replace "MyHypervisorDevice" with your actual device)
    int fd = open("/dev/MyHypervisorDevice", O_RDWR);
    if (fd == -1)
    {
        perror("Failed to open the device file");
        return 1;
    }
    else
    {
        printf("[*] Device opened successfully.\n");
    }

    TestIoctl(fd);

    // Close the device file
    close(fd);

    return 0;
}
