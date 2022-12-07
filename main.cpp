#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <String.h>

#include "MallocDebug.h"
#include "MallocDebug.h"



int main() {

	MallocDebug::MallocDebug_Init();
	MallocDebug::MallocDebug_Init();
	void* goodPointer0 = malloc(10*sizeof(int));

	void* goodPointer1 = calloc(20, sizeof(int));
	void* leakPointer0 = malloc(10*sizeof(int));
	void* leakPointer1 = calloc(20, sizeof(int));
	void* leakPointer2 = malloc(100*sizeof(int));
	int* arrayLeak = new int[300];
	int* arrayGood = new int[300];

	leakPointer2 = realloc(leakPointer2, 500*sizeof(int));
	
	MallocDebug::MallocDebug_Init();

	void* wrongCall0 = malloc(NULL);
	void* wrongCall1 = malloc(0);		//should be same as NULL
	void* wrongCall2 = calloc(0,0);
	void* wrongCall3 = calloc(0,1);
	void* wrongCall4 = calloc(1,0);


	/*		//Wrong usage of realloc will cause a crash
	void* wrongCall5 = realloc(NULL,3);
	void* wrongCall6 = realloc(NULL,0);
	int test;
	void* wrongCall7 = realloc(&test,5);
	void* wrongCall8 = realloc(&test,0);
*/


	delete(arrayGood);
	free(goodPointer0);
	free(goodPointer1);

	MallocDebug::MallocDebug_Done();

	void* checkOldMal = malloc(3*sizeof(int));
	void* checkOldCal = calloc(3,4);
	checkOldMal = realloc(checkOldMal, 200);
	checkOldCal = realloc(checkOldCal, 400);

	free(checkOldCal);
	free(checkOldMal);

	MallocDebug::MallocDebug_Done();

	checkOldMal = malloc(3*sizeof(int));
	checkOldCal = calloc(3,4);
	checkOldMal = realloc(checkOldMal, 200);
	checkOldCal = realloc(checkOldCal, 400);

	free(checkOldCal);
	free(checkOldMal);











	return 0;
}
