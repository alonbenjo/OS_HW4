#include <stdlib.h>
#include <cmath>
#include <iostream>
#include "smalloc.h"
#include "memory_list3.h"

constexpr unsigned int MAX_SIZE = 1E8;


void *smalloc(size_t size) {
    if (size == 0 || size > MAX_SIZE) {
        return nullptr;
    }
    return MemoryList3::get().allocate(size, BY_ADDRESS);
}

void* scalloc(size_t num, size_t size) {
    void* address = smalloc(size * num);
    if(address == nullptr)
    {
        return nullptr;
    }
    for (int i = 0; i < size*num; i++) {
        ((char *) address)[i] = 0;
    }
}

void* srealloc(void * oldp, size_t size){
    return MemoryList3::get().reallocate(oldp, size, BY_ADDRESS);
}

void sfree(void *p) {
    if (p == nullptr)
    {
        return;
    }
    MemoryList3::get().free(p);
}
