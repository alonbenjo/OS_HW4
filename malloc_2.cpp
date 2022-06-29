#include <stdlib.h>
#include <cmath>
#include <iostream>
#include "smalloc.h"
#include "memory_list2.h"

constexpr unsigned int MAX_SIZE = 1E8;

void *smalloc(size_t size) {
    if (size == 0 || size > MAX_SIZE) {
        return nullptr;
    }
    return MemoryList2::get().allocate(size);
}

void* scalloc(size_t num, size_t size) {
    void* address = smalloc(size * num);
    if(address == nullptr)
    {
        return nullptr;
    }
    for (unsigned i = 0; i < size*num; i++) {
        ((char *) address)[i] = 0;
    }
    return address;
}

void* srealloc(void * oldp, size_t size){
    auto& list = MemoryList2::get();
    if(oldp == nullptr)
    {
        return list.allocate(size);
    }
    return list.reallocate(oldp, size);
}

void sfree(void *p) {
    if (p == nullptr)
    {
        return;
    }
    MemoryList2::get().free(p);
}
