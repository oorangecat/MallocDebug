#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <String.h>
#include "MallocDebug.h"



int main() {

	char* tmp = (char*)malloc(16);
	char* tmp2 = (char*) realloc(tmp,3*sizeof(char));
	char* tmp3 = (char*) calloc(3,sizeof(int));
	void* a = MallocDebug::MallocDebug_malloc(34);
	//printf("%3s\n\n", tmp);


	MallocDebug::MallocDebug_Init();
	malloc(2);
	calloc(3,3);
	MallocDebug::MallocDebug_Init();
	MallocDebug::MallocDebug_Init();

	realloc(tmp,4);
	free(tmp);

	MallocDebug::MallocDebug_Done();

//does not work, i am probably not in the IAT
//THE INDEX OF THE ORIGINAL-FIRST-THUNK WILL THE BE SAME IN THE IAT

	printf("\nmalloc after sub: %p", malloc);
	tmp = (char*)malloc(2);
	MallocDebug::MallocDebug_Done();

	printf("\n%p",tmp);

	//Generic IAT for all imported functions


 	//PFirstImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pDosHeader) + PDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress+1);

	return 0;
}
