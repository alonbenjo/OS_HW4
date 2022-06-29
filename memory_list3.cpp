//
// Created by alonb on 29/06/2022.
//

#include <cstdlib>
#include "memory_list3.h"

MemoryList::MemoryList() :
        head_size_list(),
        head_address_list() , end_address_list(), end_size_list() , length(0) {
    head_address_list.next_by_address = &end_address_list;
    end_address_list.prev_by_address = &head_address_list;

    head_size_list.next_by_address = &end_size_list;
    end_size_list.prev_by_address = &head_size_list;
}

void * MemoryList::allocate(size_t size, SearchDirection direction) {
    // * step 1: search by ADDRESS a fitting block
    MallocMetadataNode* node;
    for (node = head_address_list.next_by_address; node != &end_address_list ; node = node->next_by_address) {
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

void * MemoryList::add_node(size_t size) {
    void* new_node_ptr = sbrk(sizeof(MallocMetadataNode) + size);
    if(new_node_ptr == (void *) -1) return nullptr;
    auto our_data = (MallocMetadataNode*) new_node_ptr;
    our_data->metadata.is_free = false;
    our_data->metadata.size = size;
    our_data->metadata.address = (char*) new_node_ptr + sizeof(MallocMetadataNode);
    MallocMetadataNode *next_ptr, *prev_ptr;

    //size loop:
    for (prev_ptr = &head_size_list, next_ptr = prev_ptr->next_by_size; next_ptr != &end_size_list; next_ptr = next_ptr->next_by_size){
        if(next_ptr->metadata.size > our_data->metadata.size){
            break;
        }
        prev_ptr = next_ptr;
    }

    our_data->next_by_size = next_ptr;
    our_data->prev_by_size = prev_ptr;
    prev_ptr->next_by_size = our_data;
    next_ptr->prev_by_size = our_data;

    //address (no) loop:
    next_ptr = &end_address_list;
    prev_ptr = next_ptr->prev_by_address;

    our_data->next_by_address = next_ptr;
    our_data->prev_by_address = prev_ptr;
    prev_ptr->next_by_address = our_data;
    next_ptr->prev_by_address = our_data;

    return our_data->metadata.address;
}

void MemoryList::free(void *address) {
    for (MallocMetadataNode* ptr = head_address_list.next_by_address; ptr != &end_address_list; ptr = ptr->next_by_address)
    {
        if(ptr->metadata.address == address){
            ptr->metadata.is_free = true;
            return;
        }
    }
    exit(1);
}

void *MemoryList::reallocate(void *address, size_t size, enum SearchDirection direction) {
    if(address == nullptr)
    {
        return allocate(size,BY_ADDRESS);
    }
    //address loop:
    MallocMetadataNode* ptr;
    for (ptr = head_address_list.next_by_address; ptr != &end_address_list; ptr = ptr->next_by_address)
    {
        if(ptr->metadata.address == address)
            break;
    }
    if (ptr == &end_address_list)
        exit(1);
    if(ptr->metadata.size >= size)
        return ptr->metadata.address;
    auto ret_address = allocate(size, BY_ADDRESS);
    if(ret_address == nullptr)
        return nullptr;
    for (int i = 0; i < size; i++) {
        ((char *) ret_address)[i] = ((char *) address)[i];
    }
    ptr->metadata.is_free = true;
    return ret_address;
}




