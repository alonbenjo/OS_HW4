//
// Created by alonb on 29/06/2022.
//

#include <cstddef>
#include "memory_list.h"

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


/*
void *MemoryList::find_allocatable(size_t size, enum SearchDirection direction) {
    const auto next = [&](MallocMetadataNode *node) {
        switch (direction) {
            case BySize:
                return node->next_by_size;
            case ByAddress:
                return node->next_by_address;
            default:
                return (MallocMetadataNode *) nullptr;
        }
    };
    MallocMetadataNode *node;
    for (node = head_size_list; node != nullptr; node = next(node)) {
        if (!node->metadata.is_free || node->metadata.size - size < 0) continue;
        if (node->metadata.size - size == 0) {
            node->metadata.is_free = false;
            return node->metadata.address;
        }
        break;
    }
    if(node == nullptr) return nullptr;

    size_t remainder = node->metadata.size - size;
    auto new_node = new MallocMetadataNode(remainder - sizeof(MallocMetadataNode),
                                           (char *) node->metadata.address + size + sizeof(MallocMetadataNode),
                                           true);
    //TODO fix op new
    node->metadata.size -= remainder;
    node->metadata.is_free = false;
    node->next_by_address = new_node;
    new_node->prev_by_address = node;

    if (node->next_by_size)
        node->next_by_size->prev_by_size = node->prev_by_size;
    if (node->prev_by_size)
        node->prev_by_size->next_by_size = node->next_by_size;

    MallocMetadataNode *prev = node;
    for (; prev != nullptr; prev = prev->prev_by_size) {
        if (prev->metadata.size > node->metadata.size) continue;
        node->next_by_size = prev->next_by_size;
        prev->next_by_size->prev_by_size = node;
        prev->next_by_size = node;
        node->prev_by_size = prev;
        break;
    }

    if (prev == nullptr) {
        node->prev_by_size = nullptr;
        node->next_by_size = head_size_list;
        head_size_list->prev_by_size = node;
        head_size_list = node;
    }

    for (prev = new_node; prev != nullptr; prev = prev->prev_by_size) {
        if (prev->metadata.size > new_node->metadata.size) continue;
        new_node->next_by_size = prev->next_by_size;
        prev->next_by_size->prev_by_size = new_node;
        prev->next_by_size = new_node;
        new_node->prev_by_size = prev;
        break;
    }

    if (prev == nullptr) {
        new_node->prev_by_size = nullptr;
        new_node->next_by_size = head_size_list;
        head_size_list->prev_by_size = new_node;
        head_size_list = new_node;
    }
    return node->metadata.address;
}
*/


