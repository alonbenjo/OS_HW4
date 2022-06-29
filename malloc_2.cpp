#include <stdlib.h>
#include <cmath>
#include <unistd.h>
#include <iostream>
#include "smalloc.h"
#include "memory_list.h"

constexpr unsigned int MAX_SIZE = 1E8;

struct MallocMetadata {
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
    void *data;
};


MemoryList* alloc_list;

void *smalloc(size_t size) {
    if (size == 0 || size > MAX_SIZE) {
        return NULL;
    }
    //head is the one whose prev is null
    MallocMetadata *temp = alloc_list->getHead();
    for (int i = 0; i < alloc_list->length; i++)
    {
        if (temp->is_free && temp->size >= size)
        {
            temp->is_free = false;
            return temp->data;
        }
        temp = temp->next;
    }
    //if temp reached the end we need to alloc new space for the request
    //gotta create his metadata somehow it will be clearer with a list hence I left it in the air
    void *start_of_alloc = sbrk((long) (size + sizeof(MallocMetadata)));
    if (start_of_alloc == (void *) -1) {
        return nullptr;
    }
    MallocMetadata new_data;
    new_data.prev = temp;
    new_data.next = nullptr;
    new_data.size = size;
    new_data.is_free = false;
    temp->next = &new_data;
    *(MallocMetadata *) start_of_alloc = new_data;
    return start_of_alloc;
}

void sfree(void *p) {
    //I persume p is allways a smalloced thing hence
    if (p == NULL) {
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
