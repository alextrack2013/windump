#include <intrin.h>
#include <wchar.h>
#include <stdio.h>
#include <vector>
#define PHNT_VERSION PHNT_WIN11
#include "phnt.h"
#include "json.hpp"
#pragma comment(lib, "ntdll.lib")

void DumpKUSD() {
    PKUSER_SHARED_DATA pKUSD = (PKUSER_SHARED_DATA)0x7ffe0000;
    printf("\nKUSER_SHARED_DATA @ 0x7FFE0000");
    printf("\n------------------------------\n");
    printf("        NtBuildNumber: %u (0x%X)\n", pKUSD->NtBuildNumber, pKUSD->NtBuildNumber);
    // https://learn.microsoft.com/en-us/windows/win32/msi/msintproducttype
    printf("        NtProductType: %s\n",
        pKUSD->NtProductType == NtProductWinNt ? "Workstation" :
        pKUSD->NtProductType == NtProductLanManNt ? "Domain Controller" : "Server");
    printf("   ProductTypeIsValid: %s\n", pKUSD->ProductTypeIsValid ? "TRUE" : "FALSE");
    printf("       NtMajorVersion: %u\n", pKUSD->NtMajorVersion);
    printf("       NtMinorVersion: %u\n", pKUSD->NtMinorVersion);
    printf("  NativeProcessorArch: 0x%X\n", pKUSD->NativeProcessorArchitecture);
    printf("            SuiteMask: 0x%X\n", pKUSD->SuiteMask);
    printf("NumberOfPhysicalPages: %u (%.1f GB)\n",
        pKUSD->NumberOfPhysicalPages,
        (float)pKUSD->NumberOfPhysicalPages * 4 / 1024);
    printf(" ActiveProcessorCount: %u\n", pKUSD->ActiveProcessorCount);

    printf("\n> Processor Features\n");
    const char* featureNames[] = {
        "FPU", "VME", "DE", "PSE", "TSC", "MSR", "PAE", "MCE",
        "CX8", "APIC", "SEP", "MTRR", "PGE", "MCA", "CMOV"
    };
    for (int i = 0; i < sizeof(featureNames) / sizeof(featureNames[0]); i++) {
        printf("%-6s: %s\n", featureNames[i],
            pKUSD->ProcessorFeatures[i] ? "Yes" : "No");
    }
}

void DumpPEB() {
    PPEB pPeb;
#ifdef _WIN64
    pPeb = (PPEB)__readgsqword(0x60);
#else
    pPeb = (PPEB)__readfsdword(0x30);
#endif

    printf("\nPEB");
    printf("\n---\n");
    printf("            OSMajorVersion: %lu\n", pPeb->OSMajorVersion);
    printf("            OSMinorVersion: %lu\n", pPeb->OSMinorVersion);
    printf("ImageSubsystemMajorVersion: %lu\n", pPeb->ImageSubsystemMajorVersion);
    printf("ImageSubsystemMinorVersion: %lu\n", pPeb->ImageSubsystemMinorVersion);
}

void DumpCPUID() {
    int regs[4];
    char brand[49] = { 0 };

    printf("\nCPUID");
    printf("\n-----");

    __cpuid(regs, 1);
    printf("\n> Feature Flags\n");
    printf("          Stepping: %u\n", regs[0] & 0xF);
    printf("             Model: %u\n", (regs[0] >> 4) & 0xF);
    printf("            Family: %u\n", (regs[0] >> 8) & 0xF);
    printf("Hypervisor Present: %s\n", (regs[2] & (1 << 31)) ? "Yes" : "No");

    __cpuidex(regs, 0x80000001, 0);
    printf("\n> Extended Processor Info\n");
    printf(" LM: %s\n", (regs[3] & (1 << 29)) ? "Yes" : "No");
    printf(" NX: %s\n", (regs[3] & (1 << 20)) ? "Yes" : "No");
    printf("SVM: %s\n", (regs[2] & (1 << 2)) ? "Yes" : "No");

    printf("\n> Processor Brand String\n");
    __cpuidex((int*)brand, 0x80000002, 0);
    __cpuidex((int*)(brand + 16), 0x80000003, 0);
    __cpuidex((int*)(brand + 32), 0x80000004, 0);
    printf("%.48s\n", brand);
}

void DumpXGETBV() {
    ULONG64 xcr0 = _xgetbv(0);
    printf("\nXGETBV");
    printf("\n------\n");
    printf("         XCR0: 0x%llX\n", xcr0);
    printf("AVX supported: %s\n", (xcr0 & 6) ? "Yes" : "No");
}

void DumpSystemInfo() {
    typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
        );

    _NtQuerySystemInformation NtQuerySystemInformation =
        (_NtQuerySystemInformation)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation"
        );

    if (!NtQuerySystemInformation) {
        printf("Failed to get NtQuerySystemInformation\n");
        return;
    }

    SYSTEM_BASIC_INFORMATION sysInfo;
    ULONG returnLength;

    NTSTATUS status = NtQuerySystemInformation(
        0,
        &sysInfo,
        sizeof(sysInfo),
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        printf("\nNtQuerySystemInformation");
        printf("\n------------------------\n");
        printf("  Number of Processors: %d\n", sysInfo.NumberOfProcessors);
        printf("             Page Size: %lu bytes\n", sysInfo.PageSize);
        printf("Allocation Granularity: %lu bytes\n", sysInfo.AllocationGranularity);
    }
    else {
        printf("NtQuerySystemInformation failed with status 0x%X\n", status);
    }
}

void DumpWindowsAPI() {
    printf("\nWindows API");
    printf("\n-----------");
    wchar_t winDir[MAX_PATH];
    if(GetWindowsDirectoryW(winDir, MAX_PATH))
        printf("\n> GetWindowsDirectoryW\n%ls\n", winDir);

    wchar_t volName[MAX_PATH], fsName[MAX_PATH];
    DWORD serial, maxLen, flags;
    GetVolumeInformationW(L"C:\\", volName, MAX_PATH, &serial, &maxLen, &flags, fsName, MAX_PATH);
    printf("\n> GetVolumeInformationW\nName: %ls\nFS: %ls\nSerial: %08X\n", volName, fsName, serial);

    wchar_t computerName[MAX_PATH];
    DWORD size = MAX_PATH;
    GetComputerNameW(computerName, &size);
    printf("\n> GetComputerNameW\n%ls\n", computerName);

    wchar_t userName[MAX_PATH];
    size = MAX_PATH;
    GetUserNameW(userName, &size);
    printf("\n> GetUserNameW\n%ls\n\n", userName);
}

void SaveToJson() {
    std::ostringstream json;
    JSON::StartObject(json);

    CollectKUSD(json);
    CollectPEB(json);
    CollectCPUID(json);
    CollectXGETBV(json);
    CollectSystemInfo(json);
    CollectWindowsInfo(json);

    JSON::EndObject(json);

    JSON::SaveToFile("windump.json", json);
}

int main() {
    DumpKUSD();
    DumpPEB();
    DumpCPUID();
    DumpXGETBV();
    DumpSystemInfo();
    DumpWindowsAPI();
    SaveToJson();

    system("pause");

    return 0;
}