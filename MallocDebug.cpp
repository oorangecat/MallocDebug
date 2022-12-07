//
// Created by marco on 24/11/2022.
//

#include "MallocDebug.h"

void *MallocDebug::oldMalloc=NULL;
void *MallocDebug::oldCalloc=NULL;
void *MallocDebug::oldRealloc=NULL;
void *MallocDebug::oldFree=NULL;

bool MallocDebug::initiated=false;

allocMem_t MallocDebug::allocatedBlocks[BLOCKSPACE];
unsigned int MallocDebug::firstBlock;

void MallocDebug::MallocDebug_Init() {

	//Exit if already initiated
	if(initiated) {
		return;
	}

	//Getting the DOS Header
	HMODULE hPEFile = GetModuleHandle(NULL); // NULL means the current process
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;

	//Extracting the NT header and DataDirectory
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)( ((BYTE*)pDosHeader) + pDosHeader->e_lfanew );

	PIMAGE_DATA_DIRECTORY PDataDir = pNTHeaders->OptionalHeader.DataDirectory;


	//temp variable for retbyref OldProtect of VirtualProtect
	DWORD temp;

	//list of imported dll
	PIMAGE_IMPORT_DESCRIPTOR ImportListAddress = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pDosHeader) + PDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	size_t ImportListSize =  PDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	PIMAGE_IMPORT_DESCRIPTOR ImportListEnd = ImportListAddress + ImportListSize;

	char funname[8];

	PIMAGE_THUNK_DATA OriginalFirstT;
	PIMAGE_IMPORT_BY_NAME impByName;

	PIMAGE_IMPORT_DESCRIPTOR curr = ImportListAddress; 
	PIMAGE_THUNK_DATA FirstThunk;

	oldMalloc=NULL; oldFree=NULL; oldRealloc=NULL; oldCalloc=NULL;

	//loop inside DLL import functions list
	for(; curr != ImportListEnd && curr->Characteristics != NULL; curr++ ){

		//Extract OriginalFirstT (needed for name) and FirstThunk (actual address used)
		OriginalFirstT = (PIMAGE_THUNK_DATA)(((BYTE*)pDosHeader)+(curr->OriginalFirstThunk));
		FirstThunk = (PIMAGE_THUNK_DATA)(((BYTE*)pDosHeader)+(curr->FirstThunk));

		//The end of the list can be identified by an empty struct
		while(OriginalFirstT->u1.AddressOfData != NULL) {

				impByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDosHeader + OriginalFirstT->u1.AddressOfData);
				strncpy_s(funname,impByName->Name,7);

				if(strncmp(funname,"malloc",6) == 0 ) {


					//Make the field writable
					if(!VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READWRITE, (PDWORD) &temp)){
						MallocDebug_Done();
						fprintf(stderr, "\nVirtual Protect failed, MallocDebug not initiated");
						return;
					}
					if(oldMalloc==NULL)
						oldMalloc = (void*) FirstThunk->u1.Function;

					//Replace the address
					FirstThunk->u1.Function = (DWORD_PTR) MallocDebug_malloc;
					VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READONLY, (PDWORD) &temp);
				} else if(strncmp(funname,"calloc",6) == 0 ) {


					if(!VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READWRITE, (PDWORD) &temp)){
						MallocDebug_Done();	//revert any change
						fprintf(stderr, "\nVirtual Protect failed, MallocDebug not initiated");
						return;
					}

					if(oldCalloc==NULL)
						oldCalloc = (void*) FirstThunk->u1.Function;

					FirstThunk->u1.Function = (DWORD_PTR) MallocDebug_calloc;
					VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READONLY, (PDWORD) &temp);

				} else if(strncmp(funname,"realloc",6) == 0 ) {


					if(!VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READWRITE, (PDWORD) &temp)){
						MallocDebug_Done();
						fprintf(stderr, "\nVirtual Protect failed, MallocDebug not initiated");
						return;
					}

					if(oldRealloc==NULL)
						oldRealloc = (void*) FirstThunk->u1.Function;

					FirstThunk->u1.Function = (DWORD_PTR) MallocDebug_realloc;
					VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READONLY, (PDWORD) &temp);

				} else if(strncmp(funname,"free",4) == 0 ) {


					if(!VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READWRITE, (PDWORD) &temp)){
						MallocDebug_Done();
						fprintf(stderr, "\nVirtual Protect failed, MallocDebug not initiated");
						return;
					}

					if(oldFree==NULL)
						oldFree = (void*) FirstThunk->u1.Function;

					FirstThunk->u1.Function = (DWORD_PTR) MallocDebug_free;
					VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READONLY, (PDWORD) &temp);

				}

					++OriginalFirstT; ++FirstThunk;
		}
	}

	initiated = true;
	firstBlock = 0;

	return;
}


//If MallocDebug_Init() was not called before, this will not have any effect

void MallocDebug::MallocDebug_Done() {


	//Getting the DOS Header
	HMODULE hPEFile = GetModuleHandle(NULL); // NULL means the current process
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) hPEFile;

	//Extracting the NT header and DataDirectory
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)( ((BYTE*)pDosHeader) + pDosHeader->e_lfanew );

	PIMAGE_DATA_DIRECTORY PDataDir = pNTHeaders->OptionalHeader.DataDirectory;

	//Extract IAT address and size
	void** IATAddress = (void**)(((BYTE*)pDosHeader) + PDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	size_t IATSize =  PDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size;

	//temp variable for retbyref OldProtect of VirtualProtect
	DWORD temp;

	//list of imported dll
	PIMAGE_IMPORT_DESCRIPTOR ImportListAddress = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pDosHeader) + PDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	size_t ImportListSize =  PDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	PIMAGE_IMPORT_DESCRIPTOR ImportListEnd = ImportListAddress + ImportListSize;

	char funname[8];

	PIMAGE_THUNK_DATA OriginalFirstT;
	PIMAGE_IMPORT_BY_NAME impByName;

	PIMAGE_IMPORT_DESCRIPTOR curr = ImportListAddress;
	PIMAGE_THUNK_DATA FirstThunk;


	//loop inside DLL import functions list
	for(; curr != ImportListEnd && curr->Characteristics != NULL; curr++ ){

		//Extract OriginalFirstT (needed for name) and FirstThunk (actual address used)
		OriginalFirstT = (PIMAGE_THUNK_DATA)(((BYTE*)pDosHeader)+(curr->OriginalFirstThunk));
		FirstThunk = (PIMAGE_THUNK_DATA)(((BYTE*)pDosHeader)+(curr->FirstThunk));

		//The end of the list can be identified by an empty struct
		while(OriginalFirstT->u1.AddressOfData != NULL) {

			impByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDosHeader + OriginalFirstT->u1.AddressOfData);
			strncpy_s(funname,impByName->Name,7);

			if(strncmp(funname,"malloc",6) == 0 ) {
				//oldMalloc will be initiated only if the virtualProtect did not fail in the init
				if(oldMalloc!=NULL) {
					if(!VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READWRITE, (PDWORD) &temp)){
						fprintf(stderr, "\nFailed to restore original IAT. MallocDebug still in place");
						return;
					}
					FirstThunk->u1.Function = (DWORD_PTR) oldMalloc;

					VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READONLY, (PDWORD) &temp);

				}
			} else if(strncmp(funname,"calloc",6) == 0 ) {

				if(oldCalloc!=NULL){
					if(!VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READWRITE, (PDWORD) &temp)){
						fprintf(stderr, "\nFailed to restore original IAT. MallocDebug still in place");
						return;
					}
					FirstThunk->u1.Function = (DWORD_PTR) oldCalloc;
					VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READONLY, (PDWORD) &temp);

				}
			} else if(strncmp(funname,"realloc",6) == 0 ) {

				if(oldRealloc!=NULL){
					if(!VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READWRITE, (PDWORD) &temp)){
						fprintf(stderr, "\nFailed to restore original IAT. MallocDebug still in place");
						return;
					}
					FirstThunk->u1.Function = (DWORD_PTR) oldRealloc;
					VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READONLY, (PDWORD) &temp);

				}

			} else if(strncmp(funname,"free",4) == 0 ) {

				if(oldFree!=NULL){
					if(!VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READWRITE, (PDWORD) &temp)){
						fprintf(stderr, "\nFailed to restore original IAT. MallocDebug still in place");
						return;
					}
					FirstThunk->u1.Function = (DWORD_PTR) oldFree;
					VirtualProtect((LPVOID) &(FirstThunk->u1.Function), sizeof(DWORD_PTR), PAGE_READONLY, (PDWORD) &temp);

				}

			}

			++OriginalFirstT; ++FirstThunk;
		}


	}

	if(initiated) {
		allocMem_t *currBlock;
		//Report memory leaks

		for (int i = 0; i < firstBlock; i++) {
			currBlock = &allocatedBlocks[i];
			if (currBlock->allocated) {
				currBlock->allocated = false;

				fprintf(stderr, "\nBlock %p of size %zd was not freed. Last operation on the block: ", currBlock->ptr,
								currBlock->size);

				switch (currBlock->lastOp) {
					case mal:
						fprintf(stderr, "malloc");
						break;

					case cal:
						fprintf(stderr, "calloc");
						break;

					case real:
						fprintf(stderr, "realloc");
						break;

					case fr:
						fprintf(stderr, "free");
						break;

					default:
						fprintf(stderr, "unknown");
						break;
				}
			}
		}
	}

	initiated = false;
	oldMalloc=NULL; oldRealloc=NULL; oldCalloc=NULL; oldFree=NULL;
	return;


}


void* MallocDebug::MallocDebug_malloc(size_t Size) {
	void* (*localMalloc)(size_t);
	localMalloc=(void* (*) (size_t))oldMalloc;
	
	void* funRet;
	//Size==0 should not cause an error but return a pointer to an item of length 0
	if(Size==0){
		fprintf(stderr, "\nMalloc called with Size 0.");
	}


	//reset the error status in case it was previously set
	_set_errno(0);
	//calls the original function 
	funRet = localMalloc(Size);

	//if errno is set, the function did not succeed
	if(errno != 0) {
		fprintf(stderr, "\nMalloc of size %zd failed",Size);
	} else if(firstBlock < BLOCKSPACE) {
		allocatedBlocks[firstBlock].size = Size;
		allocatedBlocks[firstBlock].lastOp = mal;
		allocatedBlocks[firstBlock].ptr = funRet;
		allocatedBlocks[firstBlock].allocated = true;
		
		#if DEBUG == true
		printf("\nMalloc size:%zd ptr: %p\n",Size, allocatedBlocks[firstBlock].ptr);
		#endif
		
		firstBlock++;
	}

	return funRet;
}

void* MallocDebug::MallocDebug_realloc(void *Block, size_t size) {
	void* (*localRealloc)(void*,size_t);
	localRealloc=(void* (*) (void*,size_t))oldRealloc;

	void* funRet;

	allocMem_t *curr;
	int idx;

	//find relative block
	for(idx=0; idx<firstBlock; idx++){
		if(Block==allocatedBlocks[idx].ptr){
			curr=&allocatedBlocks[idx];
			break;
		}
		idx++;
	}

	if((idx>=firstBlock || idx == 0) && Block != NULL){		//These situations may cause a crash
		fprintf(stderr, "\nRealloc called on an unknown block, possibly a memory area not dinamically allocated");
		curr = NULL;
	} else if (Block == NULL){
		fprintf(stderr, "\nRealloc called on a NULL pointer with size %zd. It will allocate %zd bytes, behaving as a malloc", size, size);
	}

	//if size==0, works as a free
	funRet = localRealloc(Block,size);

	if(size==0){
		if(funRet==NULL && curr != NULL){
			curr->allocated = false;
			curr->lastOp = real;
		} else { 	//if size==0 and ret!=NULL, error occurred 
			fprintf(stderr, "\nRealloc of %p with size 0 failed", Block);
		}
	} else if(funRet==NULL) {		//if size>0 and ret==NULL, error occurred
		fprintf(stderr, "Realloc of ptr %p with size %zd failed", Block, size);
	} else if(curr != NULL) {
		curr->ptr = funRet;
		curr->lastOp = real;
		curr->size = size;
		curr->allocated = true;
	}

	#if DEBUG == true
	printf("\nRealloc ptr: %p size: %zd\n", Block, size);
	#endif
	
	return funRet;
}

void* MallocDebug::MallocDebug_calloc(size_t count, size_t size) {
	void* (*localCalloc)(size_t,size_t);
	localCalloc=(void* (*) (size_t,size_t))oldCalloc;
	
	if(count == 0 || size == 0){
		fprintf(stderr, "\nCalloc called with size or count equal to 0, accessing the returned pointer will result in undefined beahviour");
	}

	_set_errno(0);		//Resets errno
	void* funRet = localCalloc(count,size);

	if(errno != 0){
		fprintf(stderr,"\nCalloc failed, %zd elements of %zd size not allocated", count, size);
	} else if(firstBlock < BLOCKSPACE) {
		allocatedBlocks[firstBlock].size = count * size;
		allocatedBlocks[firstBlock].lastOp = cal;
		allocatedBlocks[firstBlock].ptr = funRet;
		allocatedBlocks[firstBlock].allocated = true;

		firstBlock++;
	}

	#if DEBUG == true
	printf("\nCalloc count: %zd size: %zd ptr: %p\n",count,size,funRet);
	#endif
	
	return funRet;
}

void MallocDebug::MallocDebug_free(void *Block) {
	void (*localFree)(void*);
	localFree = (void (*) (void*)) oldFree;

	int idx=0;
	allocMem_t *curr;

	#if DEBUG == true
	printf("\nFree: %p\n", Block);
	#endif

	if(Block == NULL){
		fprintf(stderr, "\nFree was called with a NULL pointer. No block will be freed");
		localFree(Block);
		return;
	} else {
		//find the allocated block
		for(idx=0; idx < firstBlock; idx++) {
			curr = &allocatedBlocks[idx];

			if(!curr->allocated)
				continue;

			if(Block == curr->ptr)
				break;
		}

		if(idx >=firstBlock)
			fprintf(stderr, "Free called on an unknown Block. Dependingly on how the memory was allocated, this may cause a crash.");

		//reset errno and call free
		_set_errno(0);
		localFree(Block);

		//check for errors
		if(errno != 0){
			fprintf(stderr,"\nAn error occured while freeing pointer %p", Block);
		} else if(idx >= firstBlock){
			fprintf(stderr,"\nFree was called with pointer %p which was not dinamically allocated",Block);
		} else {
			curr->allocated = false;
			curr->lastOp = fr;
		}
	}

	return;

}

