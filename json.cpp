#include <intrin.h>
#include <wchar.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#define PHNT_VERSION PHNT_WIN11
#include "phnt.h"
#pragma comment(lib, "ntdll.lib")
#include "json.hpp"

int indent = 0;

std::string JSON::EscapeString(const std::string& input) {
    std::ostringstream ss;
    for (char c : input) {
        switch (c) {
        case '"': ss << "\\\""; break;
        case '\\': ss << "\\\\"; break;
        case '\b': ss << "\\b"; break;
        case '\f': ss << "\\f"; break;
        case '\n': ss << "\\n"; break;
        case '\r': ss << "\\r"; break;
        case '\t': ss << "\\t"; break;
        default: ss << c; break;
        }
    }
    return ss.str();
}

std::string JSON::WideToJsonString(const wchar_t* wideStr) {
    if (!wideStr || !*wideStr) {
        return "";
    }

    size_t len = wcslen(wideStr) + 1;
    std::vector<char> narrowStr(len * 2);
    size_t converted = 0;

    errno_t err = wcstombs_s(&converted, narrowStr.data(), narrowStr.size(), wideStr, _TRUNCATE);
    if (err != 0) {
        return "";
    }

    return EscapeString(narrowStr.data());
}

void JSON::AddIndent(std::ostringstream& json) {
    json << "\n" << std::string(indent * 2, ' ');
}

void JSON::StartObject(std::ostringstream& json, const std::string& key) {
    AddIndent(json);
    if (!key.empty()) {
        json << "\"" << key << "\": ";
    }
    json << "{";
    indent++;
}

void JSON::EndObject(std::ostringstream& json) {
    indent--;
    AddIndent(json);
    json << "}";
}

void JSON::AddKeyValue(std::ostringstream& json, const std::string& key, const std::string& value, bool last) {
    AddIndent(json);
    json << "\"" << key << "\": \"" << value << "\"";
    if (!last) json << ",";
}

void JSON::AddKeyValue(std::ostringstream& json, const std::string& key, int value, bool last) {
    AddIndent(json);
    json << "\"" << key << "\": " << value;
    if (!last) json << ",";
}

void JSON::AddKeyValue(std::ostringstream& json, const std::string& key, long long value, bool last) {
    AddIndent(json);
    json << "\"" << key << "\": " << value;
    if (!last) json << ",";
}

void JSON::AddKeyValue(std::ostringstream& json, const std::string& key, unsigned long value, bool last) {
    AddIndent(json);
    json << "\"" << key << "\": " << value;
    if (!last) json << ",";
}

void JSON::AddKeyValue(std::ostringstream& json, const std::string& key, bool value, bool last) {
    AddIndent(json);
    json << "\"" << key << "\": " << (value ? "true" : "false");
    if (!last) json << ",";
}

void JSON::AddKeyValue(std::ostringstream& json, const std::string& key, float value, bool last) {
    AddIndent(json);
    json << "\"" << key << "\": " << value;
    if (!last) json << ",";
}

void JSON::SaveToFile(const std::string& filename, std::ostringstream& json) {
    std::ofstream outFile(filename);
    if (outFile.is_open()) {
        outFile << json.str();
        outFile.close();
    }
}

void CollectKUSD(std::ostringstream& json) {
    PKUSER_SHARED_DATA pKUSD = (PKUSER_SHARED_DATA)0x7ffe0000;

    JSON::StartObject(json, "kuser_shared_data");
    {
        JSON::AddKeyValue(json, "NtBuildNumber", pKUSD->NtBuildNumber);
        JSON::AddKeyValue(json, "NtProductType",
            pKUSD->NtProductType == NtProductWinNt ? "Workstation" :
            pKUSD->NtProductType == NtProductLanManNt ? "Domain Controller" : "Server");
        JSON::AddKeyValue(json, "ProductTypeIsValid", pKUSD->ProductTypeIsValid);
        JSON::AddKeyValue(json, "NtMajorVersion", pKUSD->NtMajorVersion);
        JSON::AddKeyValue(json, "NtMinorVersion", pKUSD->NtMinorVersion);
        JSON::AddKeyValue(json, "NativeProcessorArchitecture", pKUSD->NativeProcessorArchitecture);
        JSON::AddKeyValue(json, "SuiteMask", pKUSD->SuiteMask);
        JSON::AddKeyValue(json, "NumberOfPhysicalPages", pKUSD->NumberOfPhysicalPages);
        JSON::AddKeyValue(json, "ActiveProcessorCount", pKUSD->ActiveProcessorCount);

        JSON::StartObject(json, "ProcessorFeatures");
        {
            const char* featureNames[] = {
                "FPU", "VME", "DE", "PSE", "TSC", "MSR", "PAE", "MCE",
                "CX8", "APIC", "SEP", "MTRR", "PGE", "MCA", "CMOV"
            };
            for (int i = 0; i < sizeof(featureNames) / sizeof(featureNames[0]); i++) {
                JSON::AddKeyValue(json, featureNames[i], pKUSD->ProcessorFeatures[i], i == sizeof(featureNames) / sizeof(featureNames[0]) - 1);
            }
        }
        JSON::EndObject(json);
    }
    JSON::EndObject(json);
    json << ",";
}

void CollectPEB(std::ostringstream& json) {
    PPEB pPeb;
#ifdef _WIN64
    pPeb = (PPEB)__readgsqword(0x60);
#else
    pPeb = (PPEB)__readfsdword(0x30);
#endif

    JSON::StartObject(json, "peb");
    {
        JSON::AddKeyValue(json, "OSMajorVersion", pPeb->OSMajorVersion);
        JSON::AddKeyValue(json, "OSMinorVersion", pPeb->OSMinorVersion);
        JSON::AddKeyValue(json, "ImageSubsystemMajorVersion", pPeb->ImageSubsystemMajorVersion);
        JSON::AddKeyValue(json, "ImageSubsystemMinorVersion", pPeb->ImageSubsystemMinorVersion, true);
    }
    JSON::EndObject(json);
    json << ",";
}

void CollectCPUID(std::ostringstream& json) {
    int regs[4];
    char brand[49] = { 0 };

    JSON::StartObject(json, "cpuid");
    {
        __cpuid(regs, 1);
        JSON::StartObject(json, "FeatureFlags");
        {
            JSON::AddKeyValue(json, "Stepping", regs[0] & 0xF);
            JSON::AddKeyValue(json, "Model", (regs[0] >> 4) & 0xF);
            JSON::AddKeyValue(json, "Family", (regs[0] >> 8) & 0xF);
            JSON::AddKeyValue(json, "HypervisorPresent", (regs[2] & (1 << 31)) != 0, true);
        }
        JSON::EndObject(json);
        json << ",";

        __cpuidex(regs, 0x80000001, 0);
        JSON::StartObject(json, "ExtendedProcessorInfo");
        {
            JSON::AddKeyValue(json, "64bitSupport", (regs[3] & (1 << 29)) != 0);
            JSON::AddKeyValue(json, "NXSupport", (regs[3] & (1 << 20)) != 0);
            JSON::AddKeyValue(json, "SVMSupport", (regs[2] & (1 << 2)) != 0, true);
        }
        JSON::EndObject(json);
        json << ",";

        __cpuidex((int*)brand, 0x80000002, 0);
        __cpuidex((int*)(brand + 16), 0x80000003, 0);
        __cpuidex((int*)(brand + 32), 0x80000004, 0);
        JSON::AddKeyValue(json, "ProcessorBrandString", brand, true);
    }
    JSON::EndObject(json);
    json << ",";
}

void CollectXGETBV(std::ostringstream& json) {
    ULONG64 xcr0 = _xgetbv(0);

    JSON::StartObject(json, "xgetbv");
    {
        JSON::AddKeyValue(json, "XCR0", (long long)xcr0);
        JSON::AddKeyValue(json, "AVXSupported", (xcr0 & 6) != 0, true);
    }
    JSON::EndObject(json);
    json << ",";
}

void CollectSystemInfo(std::ostringstream& json) {
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

    if (NtQuerySystemInformation) {
        SYSTEM_BASIC_INFORMATION sysInfo;
        ULONG returnLength;

        if (NT_SUCCESS(NtQuerySystemInformation(0, &sysInfo, sizeof(sysInfo), &returnLength))) {
            JSON::StartObject(json, "system_information");
            {
                JSON::AddKeyValue(json, "NumberOfProcessors", sysInfo.NumberOfProcessors);
                JSON::AddKeyValue(json, "PageSize", sysInfo.PageSize);
                JSON::AddKeyValue(json, "AllocationGranularity", sysInfo.AllocationGranularity, true);
            }
            JSON::EndObject(json);
            json << ",";
        }
    }
}

void CollectWindowsInfo(std::ostringstream& json) {
    JSON::StartObject(json, "windows_api");
    {
        wchar_t winDir[MAX_PATH];
        if (GetWindowsDirectoryW(winDir, MAX_PATH)) {
            JSON::AddKeyValue(json, "WindowsDirectory", JSON::WideToJsonString(winDir));
        }

        wchar_t volName[MAX_PATH], fsName[MAX_PATH];
        DWORD serial, maxLen, flags;
        if (GetVolumeInformationW(L"C:\\", volName, MAX_PATH, &serial, &maxLen, &flags, fsName, MAX_PATH)) {
            JSON::StartObject(json, "VolumeInformation");
            {
                JSON::AddKeyValue(json, "Name", JSON::WideToJsonString(volName));
                JSON::AddKeyValue(json, "FileSystem", JSON::WideToJsonString(fsName));
                JSON::AddKeyValue(json, "SerialNumber", serial, true);
            }
            JSON::EndObject(json);
            json << ",";
        }

        wchar_t computerName[MAX_PATH];
        DWORD size = MAX_PATH;
        if (GetComputerNameW(computerName, &size)) {
            JSON::AddKeyValue(json, "ComputerName", JSON::WideToJsonString(computerName));
        }

        wchar_t userName[MAX_PATH];
        size = MAX_PATH;
        if (GetUserNameW(userName, &size)) {
            JSON::AddKeyValue(json, "UserName", JSON::WideToJsonString(userName), true);
        }
    }
    JSON::EndObject(json);
}