//
// Created by marco on 24/11/2022.
//

#include "MallocDebug.h"

uint32_t MallocDebug::oldMalloc, MallocDebug::oldCalloc, MallocDebug::oldRealloc, MallocDebug::oldFree;
allocMem_t MallocDebug::allocatedBlocks[BLOCKSPACE];
uint32_t MallocDebug::firstBlock;

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
	DWORD temp;

	//Set the IAT as writable
	if(!VirtualProtect((LPVOID)IATAddress,IATSize,PAGE_EXECUTE_READWRITE, (PDWORD) &temp)){
		fprintf(stderr, "\nVirtual Protect failed, MallocDebug not initiated");
		return;
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
	}while(idx < IATSize/sizeof(uint32_t));		//Size in bytes, 4 bytes per pointer

	firstBlock=0;

	return;
}



void MallocDebug::MallocDebug_Done() {
	//Return if the functions were not initalized
	if((uint32_t) malloc != (uint32_t) MallocDebug_malloc){
		return;
	}

	//
	HMODULE hPEFile = GetModuleHandle(NULL); // NULL means the current process
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)( ((BYTE*)pDosHeader) + pDosHeader->e_lfanew );
	PIMAGE_DATA_DIRECTORY PDataDir = pNTHeaders->OptionalHeader.DataDirectory;
	uint32_t* IATAddress = (uint32_t*)(((BYTE*)pDosHeader) + PDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	size_t IATSize =  PDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size;

	allocMem_t *curr;
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


	for(int i=0; i<firstBlock; i++){
		curr = &allocatedBlocks[i];
		if( curr->allocated){
			fprintf(stderr, "\nBlock %p of size %d not freed. Last operation called on the block: ", curr->ptr, curr->size);

			switch(curr->lastOp){
				case mal:
					fprintf(stderr,"malloc");
					break;

				case cal:
					fprintf(stderr,"calloc");
					break;
					
				case real:
					fprintf(stderr,"realloc");
					break;

				case fr:
					fprintf(stderr,"free");
					break;
				
				default:
					fprintf(stderr,"unknown");
					break;
				}
		}
	}

	return;


}


void* MallocDebug::MallocDebug_malloc(size_t Size) {
	void* (*localMalloc)(size_t);
	localMalloc=(void* (*) (size_t))oldMalloc;
	
	void* funRet;

	//reset the error status in case it was previously set
	_set_errno(0);
	//calls the original function 
	funRet = localMalloc(Size);

	//if errno is set, the function did not succeed
	if(errno == ENOMEM) {
		fprintf(stderr, "\nMalloc of size %d failed",Size);
	} else {
		allocatedBlocks[firstBlock].size = Size;
		allocatedBlocks[firstBlock].lastOp = mal;
		allocatedBlocks[firstBlock].ptr = funRet;
		allocatedBlocks[firstBlock].allocated = true;
		
		printf("\nMalloc size:%d ptr: %p\n",Size, allocatedBlocks[firstBlock].ptr);
		
		firstBlock++;
	}

	return funRet;
}

void* MallocDebug::MallocDebug_realloc(void *Block, size_t size) {
	void* (*localRealloc)(void*,size_t);
	localRealloc=(void* (*) (void*,size_t))oldRealloc;

	void* funRet;

	int idx = 0;
	allocMem_t *curr;

	//find the relative block
	do{
		if(Block==allocatedBlocks[idx].ptr){
			curr=&allocatedBlocks[idx];
			break;
		}
		idx++;
	}while(idx < firstBlock);

	if(idx>=firstBlock && Block != NULL){		//These situations may cause a crash
		fprintf(stderr, "\nRealloc called on a not dinamically allocated memory area");
	} else if (Block == NULL){
		fprintf(stderr, "\nRealloc called on a NULL pointer with size %d", size);
	}

	//if size==0, works as a free
	funRet = localRealloc(Block,size);

	if(size==0){
		if(funRet==NULL){
			curr->allocated = false;
			curr->lastOp = real;
		} else { 	//if size==0 and ret!=NULL, error occurred 
			fprintf(stderr, "\nRealloc of %p with size 0 failed", Block);
		}
	} else if(funRet==NULL) {		//if size>0 and ret==NULL, error occurred
		fprintf(stderr, "Realloc of ptr %p with size %d failed", Block, size);
	} else {
		curr->ptr = funRet;
		curr->lastOp = real;
		curr->size = size;
		curr->allocated = true;
	}

	printf("\nRealloc ptr: %p size: %d\n", Block, size);
	return funRet;
}

//TODO Implement specific cases
void* MallocDebug::MallocDebug_calloc(size_t count, size_t size) {
	void* (*localCalloc)(size_t,size_t);
	localCalloc=(void* (*) (size_t,size_t))oldCalloc;
	
	if(count == 0 || size == 0){
		fprintf(stderr, "\nCalloc called with size or count equal to 0, accessing the returned pointer will result in undefined beahviour");
	}

	_set_errno(0);		//Resets errno
	void* funRet = localCalloc(count,size);

	if(errno == ENOMEM){
		fprintf(stderr,"\nCalloc failed, %d elements of %d size not allocated", count, size);
	} else {
		allocatedBlocks[firstBlock].size = count * size;
		allocatedBlocks[firstBlock].lastOp = cal;
		allocatedBlocks[firstBlock].ptr = funRet;
		allocatedBlocks[firstBlock].allocated = true;

		firstBlock++;
	}
	printf("\nCalloc count: %d size: %d ptr: %p\n",count,size,funRet);
	return funRet;
}

void MallocDebug::MallocDebug_free(void *Block) {
	void (*localFree)(void*);
	localFree = (void (*) (void*)) oldFree;

	int idx=0;
	allocMem_t *curr;
	printf("\nFree: %p\n", Block);

	if(Block == NULL){
		fprintf(stderr, "\nFree was called with a NULL pointer. No block will be freed");
		localFree(Block);
		return;
	} else {
		//find the allocated block 
		do{
			curr = &allocatedBlocks[idx];
			if(!curr->allocated){
				idx++;
				continue;
			}

			if(Block == curr->ptr){
				break;
			} 
			idx++;
		}while(idx < firstBlock);
		
		//reset errno and call free
		_set_errno(0);
		localFree(Block);

		//check for errors
		if(errno != 0){
			fprintf(stderr,"\nAn error occured while freeing pointer %p", Block);
		} else if(idx>=firstBlock){
			fprintf(stderr,"\nFree was called with pointer %p which was not dinamically allocated",Block);
		} else{
			curr->allocated = false;
			curr->lastOp = fr;
		}
	}

	return;

}

