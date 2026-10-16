# PE32/PE32+ File Header Parser
#### **Description:** A lightweight, zero-dependency C utility for statically parsing Portable Executable (PE32/PE32+) binaries on Windows. Built using Win32 File Mapping APIs, this tool extracts DOS headers, NT file headers, optional headers, and section headers directly from memory-mapped executable files on disk.
#### **Date:** 08 October 2026

## Features:
- **Zero-Copy File Ingestion:** Uses Win32 File Mapping (CreateFileMappingA / MapViewOfFile) to parse headers directly in virtual memory without full heap allocations.
- **Defensive Boundary Validation:** Sanitizes e_lfanew against alignment shifts, header sizes, 32-bit integer overflow limits, and overall file boundaries to prevent parser crashes on malformed/malicious binaries.
- **Dual Architecture Support:** Automatically detects PE32 (32-bit) vs PE32+ (64-bit) optional headers via magic byte branching.
- **Flag & Permission Extraction:**
    - Decodes IMAGE_FILE_HEADER.Characteristics bitmasks into human-readable flags.
    - Converts unix timestamps into UTC formatted string dates.
    - Parses section header flags to evaluate Read, Write, and Execute permissions.
- **Heuristic Threat Flagging:** Detects and counts sections with combined RWX (Read-Write-Execute) permissions, commonly used by packers, shellcode buffers, or self-modifying code.

## Compilation & Usage:
**Prerequisites:**  
- Any C standard compliant compiler such as gcc, clang, ...

**Build Instructions Example Using GCC:**
- gcc -Wall -Wextra -O3 main.c -o PEParser

*PEParser is the name of the program, you can name it anything you want

**Execution Examples:**
- **General Syntax:** .\PEParser.exe \<path_to_file\>
- **Example:** .\PEParser.exe PEParser.exe

## Sample Output:
```
=====================================================================
                          Static PE Parser                    
=====================================================================

Target Binary: PEParser.exe
File Size: 101972 bytes

DOS Header Analysis:
-------------------------------------------------
- Magic Signature: 0x5A4D (Valid DOS Signature)
- Offset to NT Headers: 0x00000080 (e_lfanew)

NT Headers Analysis:
-------------------------------------------------
- NT Signature: 0x4550 (Valid)
- Target Architecture: x64
- Compiled Time: 1791453869 (Thu Oct 08 10:04:29 2026 UTC)
- Number of Sections: 18
- File Characteritics: 0x26 (EXECUTABLE_IMAGE, LINE_NUMS_STRIPPED, LARGE_ADDRESS_AWARE)

Optional Header Analysis:
-------------------------------------------------
- Magic: 0x20b (PE32+ - 64-bit)
- Address of Entry Point: 0x0000105F
- Image Base: 0x0000000140000000
- Section Alignment: 4096 bytes (0x1000)
- File Alignment: 512 bytes (0x0200)
- Subsystem: Windows CUI (Console) (0x0003)
- Size of Image: 122880 (0x0001E000)
- Size of Headers: 1536 (0x00000600)

Sections Header Analysis:
----------------------------------------------------------------------------------------------------------------------
Name         V. Size        V. Address     Data Raw Size     Data Raw Pointer       Characteristics        Permissions
----------------------------------------------------------------------------------------------------------------------
.text        0x000096B0     0x00001000     0x00009800        0x00000600             0x60000020             R-X
.data        0x00000150     0x0000B000     0x00000200        0x00009E00             0xC0000040             RW-
.rdata       0x000014E8     0x0000C000     0x00001600        0x0000A000             0x40000040             R--
/4           0x00000004     0x0000E000     0x00000200        0x0000B600             0xC0000040             RW-
.pdata       0x000005D0     0x0000F000     0x00000600        0x0000B800             0x40000040             R--
.xdata       0x000005C4     0x00010000     0x00000600        0x0000BE00             0x40000040             R--
.bss         0x00000BB0     0x00011000     0x00000000        0x00000000             0xC0000080             RW-
.idata       0x000008D4     0x00012000     0x00000A00        0x0000C400             0x40000040             R--
.tls         0x00000010     0x00013000     0x00000200        0x0000CE00             0xC0000040             RW-
.rsrc        0x000001E0     0x00014000     0x00000200        0x0000D000             0x40000040             R--
.reloc       0x000000A0     0x00015000     0x00000200        0x0000D200             0x42000040             R--
/14          0x00000050     0x00016000     0x00000200        0x0000D400             0x42000040             R--
/29          0x00001244     0x00017000     0x00001400        0x0000D600             0x42000040             R--
/41          0x000000CA     0x00019000     0x00000200        0x0000EA00             0x42000040             R--
/55          0x000000A4     0x0001A000     0x00000200        0x0000EC00             0x42000040             R--
/67          0x00000048     0x0001B000     0x00000200        0x0000EE00             0x42000040             R--
/80          0x00000080     0x0001C000     0x00000200        0x0000F000             0x42000040             R--
/91          0x00000180     0x0001D000     0x00000200        0x0000F200             0x42000040             R--
----------------------------------------------------------------------------------------------------------------------

Analysis Complete!
Suspicious Sections with Full Permissiosn: 0
```

## Engineering Journal and Implementation Process:
This section documents a summary of the implementation process:

### Phase 1: Argument Validation and Memory Bounds Setup
The program checks if the argument count is correct, then checks if the file argument is not empty using strcmp.

To get the file size, the program uses CreateFileA to open the file:
```c
HANDLE fileHandle = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```

Then uses GetFileSizeEx to get its size:
```c
LARGE_INTEGER fileSize;
bool result = GetFileSizeEx(fileHandle, &fileSize);
```

Getting the size didn't work the first time, this was the first version of it:
```c
PLARGE_INTEGER fileSize = 0;
bool result = GetFileSizeEx(fileHandle, fileSize);
```

The program was exiting on its own without errors or warnings on GetFileSizeEx. After researching, I found that the problem was me assigning fileSize (which is a pointer) to 0!

### Phase 2: In-Memory File Mapping
I read about the DOS Header and found the struct IMAGE_DOS_HEADER, but my problem was how to be able to read the file's data? I couldn't find useful information online, so in the end, I asked Gemini to give me a clue and it told to read about CreateFileMappingA and MapViewOfFile.

Reading about them:
- **CreateFileMappingA:** Creates a file mapping object. It basically creates let's say a virtual bridge to a binary file which is the PE file in this project. It establishes the permissions and the maximum size of the file to look at.
- **MapViewOfFile:** Carves out a block of virtual addresses in the main program which in this case is this parser program itself and mirrors the PE file into it. It returns a regular memory pointer that pointers directly at the very first byte of the PE file.

Using that knowledge, I used these functions to get to the DOS Header:
```c
HANDLE fileMappingObjectHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID mapViewPointer = MapViewOfFile(fileMappingObjectHandle, FILE_MAP_READ, 0, 0, 0);
BYTE* basePointer = (BYTE*)mapViewPointer;
PIMAGE_DOS_HEADER dosHeaderPointer = (PIMAGE_DOS_HEADER)basePointer;
```

the basePointer variables wasn't added at first, I added it later on when I encountered a problem in the NT Header. At first, the dosHeaderPointer was assigned like this:
```c
PIMAGE_DOS_HEADER dosHeaderPointer = (PIMAGE_DOS_HEADER)mapViewPointer;
```

In CreateFileMappingA, I researched the difference between PAGE_EXECUTE_READ and PAGE_READONLY, and found that PAGE_EXECUTE_READ can lead to a security risk in this program because it can execute the memory of the target file, so a malicious program can do malicious stuff. PAGE_READONLY only copies the memory of the target file.

### Phase 3: DOS Header
First, the program checks the Signature:
```c
if (dosHeaderPointer->e_magic != IMAGE_DOS_SIGNATURE)
```

Then checks e_lfanew using 4 checks:
- If it's less than 64 (pointing to something in the DOS Header)
- Not aligned to 4
- If it's very large that can overflow
- If its size + the NT Header size exceeds the file size
```c
if (dosHeaderPointer->e_lfanew < 64) {
        printf("- Offset to NT Headers: Invalid! (Inside of DOS Header)\n");
    } else if (dosHeaderPointer->e_lfanew % 4 != 0) {
       printf("- Offset to NT Headers: Invalid! (Unaligned)\n");
    } else if ((unsigned long long)dosHeaderPointer->e_lfanew > (UINT32_MAX - sizeof(IMAGE_NT_HEADERS32))) {
        printf("- Offset to NT Headers: Invalid! (Larger than limit)\n");
    } else if ((dosHeaderPointer->e_lfanew + sizeof(IMAGE_NT_HEADERS32)) > (unsigned long long)fileSize.QuadPart) {
        printf("- Offset to NT Headers: Invalid! (Outside of File Size)\n");
    }
```

### Phase 4: NT Headers
Initially, I accessed the NT Headers this way:
```c
PIMAGE_NT_HEADERS32 ntHeaderPointer = (PIMAGE_NT_HEADERS32)(dosHeaderPointer + dosHeaderPointer->e_lfanew);
```

This lead to a different place than the NT Headers. I catched this problem when I was checking the Signature. After researching, I've learned that working with PIMAGE_DOS_HEADER for PIMAGE_NT_HEADERS32 is not the way to do it. Instead, I should have a base pointer of type BYTE*. This is the point where I added the basePointer and did the changes. After that, I accessed the NT Header this way:
```c
PIMAGE_NT_HEADERS32 ntHeaderPointer = (PIMAGE_NT_HEADERS32)(basePointer + dosHeaderPointer->e_lfanew);
```

Next, the program checks the Signature, the target architecture, the compiled timestamp (formatted), number of section, and the file's Characteristics:
```c
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
```

Timestamp Formatting function:
```c
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
```

And this is the data structure I made to format the characteristics:
```c
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
```

### Phase 5: Optional Headers
The program first checks the Optional Header's Magic value to see if the target file is a PE32 or a PE32+ file. This is important since many of the Optional Header's data differ from a 32-bit format to a 64-bit format, after determining the format, the program then prints the Address of Entry Point, the Image Base, the Section Alignment, the File Alignment, the Subsystem (with helper functions to format them), the Size of Image, and the size of Headers.

### Phase 6: Sections Header
I couldn't find how to access the Sections Header online, so I asked Gemini and it told me that there is a Macro called IMAGE_FIRST_SECTION that I can use. So I used it:
```c
PIMAGE_SECTION_HEADER sectionsHeaderPointer = IMAGE_FIRST_SECTION(ntHeaderPointer);
```

Then the program iterates through each section, and each iteration, the program gets the Section Name, the Section Virtual Size, the Section Virtual Address, the Section Data Raw Size, the Section Data Raw Pointer, the Section Characteristics, and the Section's Permissions (through a helper function), and prints these data. The Permissions helper function is the following:
```c
void GetSectionPermissions(char* permissions, int sizeOfPermissions, DWORD characteristics) {
    char r = (characteristics & IMAGE_SCN_MEM_READ) ? 'R' : '-';
    char w = (characteristics & IMAGE_SCN_MEM_WRITE) ? 'W' : '-';
    char x = (characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-';

    char tempPermissions[] = {r, w, x, '\0'};
    strcpy_s(permissions, sizeOfPermissions, tempPermissions);
}
```

### Phase 7: Final Fixes
Getting the section name from Phase 6 initially was like this:
```c
BYTE* sectionName = sectionsHeaderPointer->Name;
```

I changed it to:
```c
char sectionName[9] = {0};
memcpy(sectionName, sectionsHeaderPointer->Name, 8);
```
Just in case a section name is 8 bytes long, this way an extra byte will be present for the null terminator.


## References:
1) [strcmp](https://www.w3schools.com/c/ref_string_strcmp.php)
2) [GetFileSizeEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesizeex)
3) [Opening A File](https://learn.microsoft.com/en-us/windows/win32/fileio/opening-a-file-for-reading-or-writing)
4) [CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/FileAPI/nf-fileapi-createfilea)
5) [PE File Format: DOS Header](https://alon-alush.github.io/pe%20file%20format/dosheader/)
6) [CreateFileMappingA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)
7) [MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
8) [IMAGE_NT_HEADERS32](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32)
9) [PE Format: Machine Types](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types)