//
// Created by marco on 24/11/2022.
//

#ifndef H2_MALLOCDEBUG_H
#define H2_MALLOCDEBUG_H

#include <iostream>
#include <windows.h>


static class MallocDebug {
		static uint32_t oldMalloc, oldCalloc, oldRealloc, oldFree;

public:

		static void MallocDebug_Init();

		static void MallocDebug_Done();


		static void* MallocDebug_malloc(size_t Size);


		static void* MallocDebug_calloc(size_t count, size_t size);


		static void* MallocDebug_realloc(void *Block, size_t size);


		static void MallocDebug_free(void *Block);

};


#endif //H2_MALLOCDEBUG_H
