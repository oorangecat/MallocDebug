//
// Created by marco on 24/11/2022.
//

#include "MallocDebug.h"

uint32_t MallocDebug::oldMalloc, MallocDebug::oldCalloc, MallocDebug::oldRealloc, MallocDebug::oldFree;


void MallocDebug::MallocDebug_Init() {

	//Exit if already initiated
	if((uint32_t)malloc == (uint32_t)MallocDebug_malloc || (uint32_t)calloc == (uint32_t) MallocDebug_calloc || (uint32_t)realloc == (uint32_t)MallocDebug_realloc ) {
		return;
	}

	//Getting the DOS Header
	HMODULE hPEFile = GetModuleHandle(NULL); // NULL means the current process
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;

	//Extracting the NT header and DataDirectory
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)( ((BYTE*)pDosHeader) + pDosHeader->e_lfanew );

	PIMAGE_DATA_DIRECTORY PDataDir = pNTHeaders->OptionalHeader.DataDirectory;

	//Extract IAT address and size
	uint32_t* IATAddress = (uint32_t*)(((BYTE*)pDosHeader) + PDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	size_t IATSize =  PDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size;

	//temp variable for retbyref OldProtect of VirtualProtect
	PDWORD temp = (PDWORD)malloc(sizeof(PDWORD));

	//Set the IAT as writable
	if(!VirtualProtect((LPVOID)IATAddress,IATSize,PAGE_EXECUTE_READWRITE,temp)){
		printf("\nVirtual Protect did not work");
		exit(4);
	}

	//find and replace malloc address, saving it in a static uint32
	oldMalloc = (uint32_t) malloc;
	oldCalloc = (uint32_t) calloc;
	oldRealloc = (uint32_t) realloc;
	oldFree = (uint32_t) free;


	int idx=0;
	do{

		if(IATAddress[idx] == (uint32_t)malloc) {
			IATAddress[idx] = (uint32_t) MallocDebug_malloc;

		} else if(IATAddress[idx] == (uint32_t)calloc){

			IATAddress[idx] = (uint32_t) MallocDebug_calloc;

		} else if(IATAddress[idx] == (uint32_t)realloc){

			IATAddress[idx] = (uint32_t) MallocDebug_realloc;
		} else if(IATAddress[idx] == (uint32_t)free){

			IATAddress[idx] = (uint32_t) MallocDebug_free;
		}
		idx++;
	}while(idx < IATSize/sizeof(uint32_t));

}

void MallocDebug::MallocDebug_Done() {
	//Return if the functions were not initalized
	if((uint32_t) malloc != (uint32_t) MallocDebug_malloc){
		return;
	}

	//Getting the DOS Header
	HMODULE hPEFile = GetModuleHandle(NULL); // NULL means the current process
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;

	//Extracting the NT header and DataDirectory
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)( ((BYTE*)pDosHeader) + pDosHeader->e_lfanew );

	PIMAGE_DATA_DIRECTORY PDataDir = pNTHeaders->OptionalHeader.DataDirectory;

	//Extract IAT address and size

	uint32_t* IATAddress = (uint32_t*)(((BYTE*)pDosHeader) + PDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	size_t IATSize =  PDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size;
	PDWORD temp = (PDWORD)malloc(sizeof(PDWORD));		//temp variable for return OldProtect of VirtualProtect

	//find and replace malloc address, saving it in a static uint32
	int idx=0;
	do{

		if(IATAddress[idx] == (uint32_t) MallocDebug_malloc) {
			IATAddress[idx] = oldMalloc;

		} else if(IATAddress[idx] == (uint32_t)MallocDebug_calloc){

			IATAddress[idx] = oldCalloc;

		} else if(IATAddress[idx] == (uint32_t)MallocDebug_realloc){

			IATAddress[idx] = oldRealloc;
		} else if(IATAddress[idx] == (uint32_t) MallocDebug_free){

			IATAddress[idx] = oldFree;
		}
		idx++;
	}while(idx < IATSize/sizeof(uint32_t));



}


void* MallocDebug::MallocDebug_malloc(size_t Size) {
	printf("\na %d\n",Size);
	return 0;
}

void* MallocDebug::MallocDebug_realloc(void *Block, size_t size) {
	printf("\nRealloc: %p %d", Block, size);
	return 0;
}

void* MallocDebug::MallocDebug_calloc(size_t count, size_t size) {
	printf("\nCalloc %d %d\n",count,size);
	return 0;
}

void MallocDebug::MallocDebug_free(void *Block) {
	printf("\nFree: %p\n", Block);
}

