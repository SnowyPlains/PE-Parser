#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct FlagMap {
    WORD flag;
    const char* name;
};

const struct FlagMap FileCharacteristicsTable[] = {
    { IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED" },
    { IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE" },
    { IMAGE_FILE_LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED" },
    { IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED" },
    { IMAGE_FILE_AGGRESIVE_WS_TRIM, "AGGRESIVE_WS_TRIM" },
    { IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE" },
    { IMAGE_FILE_BYTES_REVERSED_LO, "BYTES_REVERSED_LO" },
    { IMAGE_FILE_32BIT_MACHINE, "32BIT_MACHINE" },
    { IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED" },
    { IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP" },
    { IMAGE_FILE_NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP" },
    { IMAGE_FILE_SYSTEM, "SYSTEM" },
    { IMAGE_FILE_DLL, "DLL" },
    { IMAGE_FILE_UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY" },
    { IMAGE_FILE_BYTES_REVERSED_HI, "BYTES_REVERSED_HI" }
};

bool FormatTime(char* formattedTime, size_t stringSize, DWORD originalTime);
void GetSubsystem32(char* subSystem, int sizeOfSubSystem, PIMAGE_NT_HEADERS32 nt32);
void GetSubsystem64(char* subSystem, int sizeOfSubSystem, PIMAGE_NT_HEADERS64 nt64);
void GetSectionPermissions(char* permissions, int sizeOfPermissions, DWORD characteristics);

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Error! Please provide the name of the executable to analyze\n");
        printf("Example Usage: .\\PEParser.exe MyApp.exe\n");

        return -1;
    }

    if (argc > 2) {
        printf("Too Many Arguments! Please provide the name of 1 executable to analyze\n");
        printf("Example Usage: .\\PEParser.exe MyApp.exe\n");

        return -1;
    }

    if (strcmp(argv[1], "") == 0) {
        printf("The name of the program shouldn't be empty!\n");

        return -1;
    }

    printf("\n=====================================================================\n");
    printf("                          Static PE Parser                    \n");
    printf("=====================================================================\n\n");
    
    printf("Target Binary: %s\n", argv[1]);

    HANDLE fileHandle = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (fileHandle == INVALID_HANDLE_VALUE) {
        printf("Couldn't Open the program! Error Code: %lu\n", GetLastError());

        return -1;
    }

    LARGE_INTEGER fileSize;
    bool result = GetFileSizeEx(fileHandle, &fileSize);

    if (result == 0) {
        printf("Couldn't get the size of the program! Error Code: %lu\n", GetLastError());

        CloseHandle(fileHandle);

        return -1;
    }

    printf("File Size: %lld bytes\n", (long long)fileSize.QuadPart);

    HANDLE fileMappingObjectHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);

    if (fileMappingObjectHandle == INVALID_HANDLE_VALUE) {
        printf("Couldn't create a File Mapping Object! Error Code: %lu\n", GetLastError());

        CloseHandle(fileHandle);

        return -1;
    }

    LPVOID mapViewPointer = MapViewOfFile(fileMappingObjectHandle, FILE_MAP_READ, 0, 0, 0);

    if (mapViewPointer == NULL) {
        printf("Couldn't make a Map View Pointer! Error Code: %lu\n", GetLastError());

        CloseHandle(fileMappingObjectHandle);
        CloseHandle(fileHandle);

        return -1;
    }

    BYTE* basePointer = (BYTE*)mapViewPointer;

    printf("\nDOS Header Analysis:\n");
    printf("-------------------------------------------------\n");
    PIMAGE_DOS_HEADER dosHeaderPointer = (PIMAGE_DOS_HEADER)basePointer;

    printf("- Magic Signature: ");
    if (dosHeaderPointer->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("0x%X (Invalid DOS Signature)\n", dosHeaderPointer->e_magic);

        CloseHandle(fileMappingObjectHandle);
        CloseHandle(fileHandle);

        return -1;
    }

    printf("0x%X (Valid DOS Signature)\n", dosHeaderPointer->e_magic);

    if (dosHeaderPointer->e_lfanew < 64) {
        printf("- Offset to NT Headers: Invalid! (Inside of DOS Header)\n");
    } else if (dosHeaderPointer->e_lfanew % 4 != 0) {
       printf("- Offset to NT Headers: Invalid! (Unaligned)\n");
    } else if ((unsigned long long)dosHeaderPointer->e_lfanew > (UINT32_MAX - sizeof(IMAGE_NT_HEADERS32))) {
        printf("- Offset to NT Headers: Invalid! (Larger than limit)\n");
    } else if ((dosHeaderPointer->e_lfanew + sizeof(IMAGE_NT_HEADERS32)) > (unsigned long long)fileSize.QuadPart) {
        printf("- Offset to NT Headers: Invalid! (Outside of File Size)\n");
    }

    printf("- Offset to NT Headers: 0x%08lX (e_lfanew)\n", dosHeaderPointer->e_lfanew);

    printf("\nNT Headers Analysis:\n");
    printf("-------------------------------------------------\n");
    PIMAGE_NT_HEADERS32 ntHeaderPointer = (PIMAGE_NT_HEADERS32)(basePointer + dosHeaderPointer->e_lfanew);
    
    printf("- NT Signature: ");

    DWORD ntHeadersRealSignature = 0x4550;
    if (ntHeaderPointer->Signature != ntHeadersRealSignature) {
        printf("0x%lX (Invalid)\n", ntHeaderPointer->Signature);
    }

    printf("0x%lX (Valid)\n", ntHeaderPointer->Signature);

    printf("- Target Architecture: ");
    if (ntHeaderPointer->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        printf("x64\n");
    } else if (ntHeaderPointer->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64) {
        printf("ARM64\n");
    } else if (ntHeaderPointer->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        printf("I386\n");
    } else {
        printf("Unknown\n");
    }

    char formattedTimeStamp[64];
    bool formattingResult = FormatTime(formattedTimeStamp, sizeof(formattedTimeStamp), ntHeaderPointer->FileHeader.TimeDateStamp);

    printf("- Compiled Time: ");
    if (!formattingResult) {
        printf("%ld\n", ntHeaderPointer->FileHeader.TimeDateStamp);
    }
    printf("%ld (%s)\n", ntHeaderPointer->FileHeader.TimeDateStamp, formattedTimeStamp);

    printf("- Number of Sections: %d\n", ntHeaderPointer->FileHeader.NumberOfSections);

    int characteristicsTableSize = 15;
    printf("- File Characteritics: 0x%X (", ntHeaderPointer->FileHeader.Characteristics);

    bool isFirst = true;
    for (int i = 0; i < characteristicsTableSize; i++) {
        if ((ntHeaderPointer->FileHeader.Characteristics & FileCharacteristicsTable[i].flag) == FileCharacteristicsTable[i].flag) {
            if (!isFirst) {
                printf(", ");
            }

            printf("%s", FileCharacteristicsTable[i].name);
            isFirst = false;
        }
    }
    
    if (isFirst) {
        printf("None");
    }

    printf(")\n");

    printf("\nOptional Header Analysis:\n");
    printf("-------------------------------------------------\n");

    if (ntHeaderPointer->OptionalHeader.Magic == 0x10b) {
        printf("- Magic: 0x%x (PE32 - 32-bit)\n", ntHeaderPointer->OptionalHeader.Magic);
        printf("- Address of Entry Point: 0x%08lX\n", ntHeaderPointer->OptionalHeader.AddressOfEntryPoint);
        printf("- Image Base: 0x%016lX\n", ntHeaderPointer->OptionalHeader.ImageBase);
        printf("- Section Alignment: %lu bytes (0x%04lX)\n", ntHeaderPointer->OptionalHeader.SectionAlignment, ntHeaderPointer->OptionalHeader.SectionAlignment);
        printf("- File Alignment: %lu bytes (0x%04lX)\n", ntHeaderPointer->OptionalHeader.FileAlignment, ntHeaderPointer->OptionalHeader.FileAlignment);
        
        char subSystem32[64];
        GetSubsystem32(subSystem32, sizeof(subSystem32), ntHeaderPointer);
        printf("- Subsystem: %s (0x%04X)\n", subSystem32, ntHeaderPointer->OptionalHeader.Subsystem);

        printf("- Size of Image: %lu (0x%08lX)\n", ntHeaderPointer->OptionalHeader.SizeOfImage, ntHeaderPointer->OptionalHeader.SizeOfImage);
        printf("- Size of Headers: %lu (0x%08lX)\n", ntHeaderPointer->OptionalHeader.SizeOfHeaders, ntHeaderPointer->OptionalHeader.SizeOfHeaders);
    } else if (ntHeaderPointer->OptionalHeader.Magic == 0x20b) {
        PIMAGE_NT_HEADERS64 ntHeaderPointer64 = (PIMAGE_NT_HEADERS64)ntHeaderPointer;
        printf("- Magic: 0x%x (PE32+ - 64-bit)\n", ntHeaderPointer64->OptionalHeader.Magic);
        printf("- Address of Entry Point: 0x%08lX\n", ntHeaderPointer64->OptionalHeader.AddressOfEntryPoint);
        printf("- Image Base: 0x%016llX\n", ntHeaderPointer64->OptionalHeader.ImageBase);
        printf("- Section Alignment: %lu bytes (0x%04lX)\n", ntHeaderPointer64->OptionalHeader.SectionAlignment, ntHeaderPointer64->OptionalHeader.SectionAlignment);
        printf("- File Alignment: %lu bytes (0x%04lX)\n", ntHeaderPointer64->OptionalHeader.FileAlignment, ntHeaderPointer64->OptionalHeader.FileAlignment);
        
        char subSystem64[64];
        GetSubsystem64(subSystem64, sizeof(subSystem64), ntHeaderPointer64);
        printf("- Subsystem: %s (0x%04X)\n", subSystem64, ntHeaderPointer64->OptionalHeader.Subsystem);
        
        printf("- Size of Image: %lu (0x%08lX)\n", ntHeaderPointer64->OptionalHeader.SizeOfImage, ntHeaderPointer64->OptionalHeader.SizeOfImage);
        printf("- Size of Headers: %lu (0x%08lX)\n", ntHeaderPointer64->OptionalHeader.SizeOfHeaders, ntHeaderPointer64->OptionalHeader.SizeOfHeaders);
    } else {
        printf("- Magic: 0x%x (Unknown)\n", ntHeaderPointer->OptionalHeader.Magic);
    }
    
    printf("\nSections Header Analysis:\n");
    printf("----------------------------------------------------------------------------------------------------------------------\n");

    PIMAGE_SECTION_HEADER sectionsHeaderPointer = IMAGE_FIRST_SECTION(ntHeaderPointer);

    printf("%-10s   %-12s   %-12s   %-15s   %-20s   %-20s   %-s\n", "Name", "V. Size", "V. Address", "Data Raw Size", "Data Raw Pointer", "Characteristics", "Permissions");
    printf("----------------------------------------------------------------------------------------------------------------------\n");

    int rwxCounter = 0;
    for (int j = 0; j < ntHeaderPointer->FileHeader.NumberOfSections; j++) {
        char sectionName[9] = {0};
        memcpy(sectionName, sectionsHeaderPointer->Name, 8);
        
        DWORD virtualSize = sectionsHeaderPointer->Misc.VirtualSize;
        DWORD virtualAddress = sectionsHeaderPointer->VirtualAddress;
        DWORD dataRawSize = sectionsHeaderPointer->SizeOfRawData;
        DWORD dataRawPointer = sectionsHeaderPointer->PointerToRawData;
        DWORD characteristics = sectionsHeaderPointer->Characteristics;
        char permissions[4];
        GetSectionPermissions(permissions, sizeof(permissions), characteristics);

        printf("%-10s   0x%08lX     0x%08lX     0x%08lX        0x%08lX             0x%08lX             %-s\n", sectionName, virtualSize, virtualAddress, dataRawSize, dataRawPointer, characteristics, permissions);

        if (strcmp(permissions, "RWX") == 0) {
            rwxCounter++;
        }

        sectionsHeaderPointer++;
    }
    printf("----------------------------------------------------------------------------------------------------------------------\n");

    printf("\nAnalysis Complete!\nSuspicious Sections with Full Permissiosn: %d\n", rwxCounter);

    UnmapViewOfFile(mapViewPointer);
    CloseHandle(fileMappingObjectHandle);
    CloseHandle(fileHandle);
    
    return 0;
}

bool FormatTime(char* formattedTime, size_t stringSize, DWORD originalTime) {
    time_t rawTime = (time_t)originalTime;
    struct tm *utc_time;

    utc_time = gmtime(&rawTime);

    if (utc_time == NULL) {
        printf("Couldn't format the date!\n");

        return false;
    }

    size_t result = strftime(formattedTime, stringSize, "%a %b %d %H:%M:%S %Y UTC", utc_time);
    
    if (result == 0) {
        return false;
    }

    return true;
}

void GetSubsystem32(char* subSystem, int sizeOfSubSystem, PIMAGE_NT_HEADERS32 nt32) {
    if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_UNKNOWN) {
        strcpy_s(subSystem, sizeOfSubSystem, "Unknown");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE) {
        strcpy_s(subSystem, sizeOfSubSystem, "Device Driver / Native System Process");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
        strcpy_s(subSystem, sizeOfSubSystem, "Windows GUI");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
        strcpy_s(subSystem, sizeOfSubSystem, "Windows CUI (Console)");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_OS2_CUI) {
        strcpy_s(subSystem, sizeOfSubSystem, "OS/2 CUI");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_POSIX_CUI) {
        strcpy_s(subSystem, sizeOfSubSystem, "POSIX CUI");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CE_GUI) {
        strcpy_s(subSystem, sizeOfSubSystem, "Windows CE System");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_APPLICATION) {
        strcpy_s(subSystem, sizeOfSubSystem, "EFI Application");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) {
        strcpy_s(subSystem, sizeOfSubSystem, "EFI Driver with Boot Services");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
        strcpy_s(subSystem, sizeOfSubSystem, "EFI Driver with Run-Time Services");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_ROM) {
        strcpy_s(subSystem, sizeOfSubSystem, "EFI ROM Image");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_XBOX) {
        strcpy_s(subSystem, sizeOfSubSystem, "Xbox System");
    } else if (nt32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION) {
        strcpy_s(subSystem, sizeOfSubSystem, "Windows Boot Application");
    }
}

void GetSubsystem64(char* subSystem, int sizeOfSubSystem, PIMAGE_NT_HEADERS64 nt64) {
    if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_UNKNOWN) {
        strcpy_s(subSystem, sizeOfSubSystem, "Unknown");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE) {
        strcpy_s(subSystem, sizeOfSubSystem, "Device Driver / Native System Process");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
        strcpy_s(subSystem, sizeOfSubSystem, "Windows GUI");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
        strcpy_s(subSystem, sizeOfSubSystem, "Windows CUI (Console)");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_OS2_CUI) {
        strcpy_s(subSystem, sizeOfSubSystem, "OS/2 CUI");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_POSIX_CUI) {
        strcpy_s(subSystem, sizeOfSubSystem, "POSIX CUI");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CE_GUI) {
        strcpy_s(subSystem, sizeOfSubSystem, "Windows CE System");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_APPLICATION) {
        strcpy_s(subSystem, sizeOfSubSystem, "EFI Application");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) {
        strcpy_s(subSystem, sizeOfSubSystem, "EFI Driver with Boot Services");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
        strcpy_s(subSystem, sizeOfSubSystem, "EFI Driver with Run-Time Services");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_ROM) {
        strcpy_s(subSystem, sizeOfSubSystem, "EFI ROM Image");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_XBOX) {
        strcpy_s(subSystem, sizeOfSubSystem, "Xbox System");
    } else if (nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION) {
        strcpy_s(subSystem, sizeOfSubSystem, "Windows Boot Application");
    }
}

void GetSectionPermissions(char* permissions, int sizeOfPermissions, DWORD characteristics) {
    char r = (characteristics & IMAGE_SCN_MEM_READ) ? 'R' : '-';
    char w = (characteristics & IMAGE_SCN_MEM_WRITE) ? 'W' : '-';
    char x = (characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-';

    char tempPermissions[] = {r, w, x, '\0'};
    strcpy_s(permissions, sizeOfPermissions, tempPermissions);
}