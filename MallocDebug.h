//
// Created by marco on 24/11/2022.
//

#ifndef H2_MALLOCDEBUG_H
#define H2_MALLOCDEBUG_H

#ifndef DEBUG 
#define DEBUG false
#endif

#include <iostream>
#include <windows.h>

#define BLOCKSPACE 2000


enum funTypes{none, mal, cal, real, fr};

typedef struct allocMem_s{
		bool allocated = false;
		void* ptr;
		size_t size;
		funTypes lastOp = none;
}allocMem_t;

static class MallocDebug {
		static void *oldMalloc, *oldCalloc, *oldRealloc, *oldFree;
		static allocMem_t allocatedBlocks[BLOCKSPACE];
		static unsigned int firstBlock;
		static bool initiated;

public:

		static void MallocDebug_Init();

		static void MallocDebug_Done();


		static void* MallocDebug_malloc(size_t Size);


		static void* MallocDebug_calloc(size_t count, size_t size);


		static void* MallocDebug_realloc(void *Block, size_t size);


		static void MallocDebug_free(void *Block);

};


#endif //H2_MALLOCDEBUG_H
