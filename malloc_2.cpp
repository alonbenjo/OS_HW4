#include <stdlib.h>
#include <cmath>
#include <iostream>
#include <unistd.h>


// ****************************** H file: ******************************
class MemoryList2 {
private:

    struct Metadata {
        size_t size;
        void * address;
        bool is_free;
    };

    struct MallocMetadataNode {
        Metadata metadata;
        MallocMetadataNode *next;
        MallocMetadataNode *prev;

        explicit MallocMetadataNode(size_t size = 0, void * address = nullptr, bool is_free = false) :
                metadata{size, address, is_free},
                next(nullptr),
                prev(nullptr) {}
        ~MallocMetadataNode() = default;
    };


    MallocMetadataNode head_list;
    MallocMetadataNode end_list;

    MemoryList2();
    void * add_node(size_t size);
public:
    static MemoryList2& get(){
        static MemoryList2 list;
        return list;
    }

    MemoryList2(MemoryList2&) = delete;
    MemoryList2 operator=(MemoryList2&) = delete;
    void * allocate(size_t size);
    void free(void* address);
    void * reallocate(void* address, size_t size);
};


// ****************************** CPP file: ******************************
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
    for (unsigned i = 0; i < size; i++) {
        ((char *) ret_address)[i] = ((char *) address)[i];
    }
    ptr->metadata.is_free = true;
    return ret_address;
}

// ****************************** malloc_2.cpp file: ******************************
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
