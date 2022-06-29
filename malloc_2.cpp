#include <stdlib.h>
#include <cmath>
#include <unistd.h>
#include <iostream>
#include "smalloc.h"
#include "memory_list2.h"

constexpr unsigned int MAX_SIZE = 1E8;

struct MallocMetadata {
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
    void *data;
};


void *smalloc(size_t size) {
    if (size == 0 || size > MAX_SIZE) {
        return nullptr;
    }
    return MemoryList2::get().allocate(size, BY_ADDRESS);
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
    MemoryList2::get().reallocate(oldp, size, BY_ADDRESS);
}

void sfree(void *p) {
    if (p == nullptr) {
        return;
    }
    MallocMetadata *temp = alloc_list->getHead();
    for (int i = 0; i < alloc_list->getSize(); i++) {
        if (temp == p) {
            temp->is_free = true;
            return;
        }
        temp = temp->next;
    }
}
