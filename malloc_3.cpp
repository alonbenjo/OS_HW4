#include <stdlib.h>
#include <cmath>
#include <iostream>
#include <unistd.h>


// ****************************** list.h file: ******************************
using SearchDirection = enum SearchDirection {BY_SIZE, BY_ADDRESS};

class MemoryList3 {
private:

    struct Metadata {
        size_t size;
        void * address;
        bool is_free;
    };

    struct MallocMetadataNode {
        Metadata metadata;
        MallocMetadataNode *next_by_size;
        MallocMetadataNode *prev_by_size;
        MallocMetadataNode *next_by_address;
        MallocMetadataNode *prev_by_address;

        explicit MallocMetadataNode(size_t size = 0, void * address = nullptr, bool is_free = false) :
                metadata{size, address, is_free},
                next_by_size(nullptr),
                prev_by_size(nullptr),
                next_by_address(nullptr),
                prev_by_address(nullptr) {};

        ~MallocMetadataNode() = default;
    };

    MallocMetadataNode head_size_list;
    MallocMetadataNode head_address_list;
    MallocMetadataNode end_size_list;
    MallocMetadataNode end_address_list;
    unsigned int length;

    MemoryList3();
    void * add_node(size_t size);
public:
    static MemoryList3& get(){
        static MemoryList3 list;
        return list;
    }

    MemoryList3(MemoryList3&) = delete;
    MemoryList3 operator=(MemoryList3&) = delete;
    void * allocate(size_t size, enum SearchDirection direction);
    void free(void* address);
    void * reallocate(void* address, size_t size, enum SearchDirection direction);
};


// ****************************** list.cpp file: ******************************
MemoryList3::MemoryList3() :
        head_size_list(),
        head_address_list() , end_address_list(), end_size_list() , length(0) {
    head_address_list.next_by_address = &end_address_list;
    end_address_list.prev_by_address = &head_address_list;

    head_size_list.next_by_address = &end_size_list;
    end_size_list.prev_by_address = &head_size_list;
}

void * MemoryList3::allocate(size_t size, SearchDirection direction) {
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

void * MemoryList3::add_node(size_t size) {
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

void MemoryList3::free(void *address) {
    for (MallocMetadataNode* ptr = head_address_list.next_by_address; ptr != &end_address_list; ptr = ptr->next_by_address)
    {
        if(ptr->metadata.address == address){
            ptr->metadata.is_free = true;
            return;
        }
    }
    exit(1);
}

void *MemoryList3::reallocate(void *address, size_t size, enum SearchDirection direction) {
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

// ****************************** malloc_3.cpp file: ******************************
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
