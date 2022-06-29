//
// Created by alonb on 29/06/2022.
//

#include <cstdlib>
#include "memory_list2.h"
#include <unistd.h>


MemoryList2::MemoryList2() :
head_list(),
end_list() {
    head_list.next = &end_list;
    end_list.prev = &head_list;
}

void * MemoryList2::allocate(size_t size) {
    // * step 1: search by ADDRESS a fitting block
    MallocMetadataNode* node;
    for (node = head_list.next; node != &end_list ; node = node->next) {
        if (!node->metadata.is_free)
            continue;
        if (node->metadata.size < size)
            continue;
        node->metadata.is_free = false;
        return node->metadata.address;
    }

    // * step 2: if none of the existing blocks fit create a new one!
    return add_node(size);
}

void * MemoryList2::add_node(size_t size) {
    void* new_node_ptr = sbrk(sizeof(MallocMetadataNode) + size);
    if(new_node_ptr == (void *) -1) return nullptr;
    auto our_data = (MallocMetadataNode*) new_node_ptr;
    our_data->metadata.is_free = false;
    our_data->metadata.size = size;
    our_data->metadata.address = (char*) new_node_ptr + sizeof(MallocMetadataNode);
    MallocMetadataNode *next_ptr, *prev_ptr;

    //address (no) loop:
    next_ptr = &end_list;
    prev_ptr = next_ptr->prev;

    our_data->next = next_ptr;
    our_data->prev = prev_ptr;
    prev_ptr->next = our_data;
    next_ptr->prev = our_data;

    return our_data->metadata.address;
}

void MemoryList2::free(void *address) {
    for (MallocMetadataNode* ptr = head_list.next; ptr != &end_list; ptr = ptr->next)
    {
        if(ptr->metadata.address == address){
            ptr->metadata.is_free = true;
            return;
        }
    }
    exit(1);
}

void *MemoryList2::reallocate(void *address, size_t size) {
    //address loop:
    MallocMetadataNode* ptr;
    for (ptr = head_list.next; ptr != &end_list; ptr = ptr->next)
    {
        if(ptr->metadata.address == address)
            break;
    }
    if (ptr == &end_list)
        exit(1);

    if(ptr->metadata.size >= size)
        return ptr->metadata.address;

    void* ret_address = allocate(size);
    if(ret_address == nullptr)
        return nullptr;
    for (int i = 0; i < size; i++) {
        ((char *) ret_address)[i] = ((char *) address)[i];
    }
    ptr->metadata.is_free = true;
    return ret_address;
}




