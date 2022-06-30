#include <stdlib.h>
#include <cmath>
#include <iostream>
#include <unistd.h>
#include <cstring>

static constexpr unsigned int MAX_SIZE = 1E8;

static constexpr unsigned int MIN_SIZE = 128;

// ****************************** list.h file: ******************************

class MemoryList3 {
private:
    struct Metadata {
        size_t size;
        bool is_free;
    };

    struct MallocMetadataNode {
        Metadata metadata;
        MallocMetadataNode *next_by_size;
        MallocMetadataNode *prev_by_size;
        MallocMetadataNode *next_by_address;
        MallocMetadataNode *prev_by_address;

        explicit MallocMetadataNode(size_t size = 0, bool is_free = false) :
                metadata{size,  is_free},
                next_by_size(nullptr),
                prev_by_size(nullptr),
                next_by_address(nullptr),
                prev_by_address(nullptr) {};

        ~MallocMetadataNode() = default;
        void* address() const{
            return (char *) this + sizeof(*this);
        }
    };

    MallocMetadataNode head_size_list;
    MallocMetadataNode head_address_list;
    MallocMetadataNode end_size_list;
    MallocMetadataNode end_address_list;

    size_t free_blocks ;
    size_t free_bytes ;
    size_t allocated_bytes ;
    size_t allocated_blocks ;
    size_t meta_data_bytes ;

    MemoryList3();
    void * add_node(size_t size);
    bool split_node(MallocMetadataNode& node, size_t data_size);
    void enter_to_size_list(MallocMetadataNode& node);

public:
    static MemoryList3& get(){
        static MemoryList3 list;
        return list;
    }

    size_t getFreeBlocks() const;
    size_t getFreeBytes() const;
    size_t getAllocatedBytes() const;
    size_t getAllocatedBlocks() const;
    size_t getMetaDataBytes() const;

    MemoryList3(MemoryList3&) = delete;
    MemoryList3 operator=(MemoryList3&) = delete;

    void *allocate(size_t size);
    void free(void* address);
    void *reallocate(void *address, size_t size);
};


// ****************************** list.cpp file: ******************************
MemoryList3::MemoryList3() :
        head_size_list(),
        head_address_list() , end_address_list(), end_size_list() {
    head_address_list.next_by_address = &end_address_list;
    end_address_list.prev_by_address = &head_address_list;

    head_size_list.next_by_address = &end_size_list;
    end_size_list.prev_by_address = &head_size_list;
}

void * MemoryList3::allocate(size_t size) {
    // * step 1: search by ADDRESS a fitting block
    MallocMetadataNode* node;
    for (node = head_address_list.next_by_size; node != &end_size_list ; node = node->next_by_size) {
        if (!node->metadata.is_free || node->metadata.size < size)
            continue;
        node->metadata.is_free = false;
        free_blocks --;
        //TODO for fragmentation
        free_bytes -= node->metadata.size;
        return node->address();
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
    MallocMetadataNode *next_ptr, *prev_ptr;

    //size loop:
    for(prev_ptr = &head_size_list, next_ptr = prev_ptr->next_by_size; next_ptr != &end_size_list; next_ptr = next_ptr->next_by_size)
    {
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

    allocated_blocks++;
    allocated_bytes += size;
    meta_data_bytes += sizeof(MallocMetadataNode);
    return our_data->address();
}

void MemoryList3::free(void *address) {
    for (MallocMetadataNode* ptr = head_address_list.next_by_address; ptr != &end_address_list; ptr = ptr->next_by_address)
    {
        if(ptr->address() == address){
            ptr->metadata.is_free = true;
            free_blocks++;

            free_bytes += ptr->metadata.size;
            return;
        }
    }
    exit(1);
}

void *MemoryList3::reallocate(void *address, size_t size) {
    if(address == nullptr)
    {
        return allocate(size);
    }
    //address loop:
    MallocMetadataNode* ptr;
    for (ptr = head_address_list.next_by_address; ptr != &end_address_list; ptr = ptr->next_by_address)
    {
        if(ptr->address() == address)
            break;
    }
    if (ptr == &end_address_list)
        exit(1);
    if(ptr->metadata.size >= size)
    {
        //TODO the split node here
        return ptr->address();
    }
    auto ret_address = allocate(size);
    if(ret_address == nullptr)
        return nullptr;
    
    todo memmove
    for (int i = 0; i < size; i++) {
        ((char *) ret_address)[i] = ((char *) address)[i];
    }
    ptr->metadata.is_free = true;
    free_blocks++;
    free_bytes += ptr->metadata.size;
    return ret_address;
}

size_t MemoryList3::getFreeBlocks() const {
    return free_blocks;
}

size_t MemoryList3::getFreeBytes() const {
    return free_bytes;
}

size_t MemoryList3::getAllocatedBytes() const {
    return allocated_bytes;
}

size_t MemoryList3::getAllocatedBlocks() const {
    return allocated_blocks;
}

size_t MemoryList3::getMetaDataBytes() const {
    return meta_data_bytes;
}

bool MemoryList3::split_node(MemoryList3::MallocMetadataNode &node, size_t data_size) {
    size_t new_node_size = node.metadata.size - data_size - sizeof(MallocMetadataNode);
    if(new_node_size < MIN_SIZE){
        return false;
    }

    MallocMetadataNode new_node(new_node_size, true);
    void* new_node_address = (char *) node.address() + data_size;
    memmove(new_node_address, &new_node, sizeof(MallocMetadataNode));
    auto* new_node_heap = (MallocMetadataNode *) new_node_address;

    new_node_heap->next_by_address = node.next_by_address;
    new_node_heap->prev_by_address = &node;
    node.next_by_address->prev_by_address = new_node_heap;
    node.next_by_address = new_node_heap;
    node.metadata.size = data_size;
    node.metadata.is_free = false;

    node.next_by_size->prev_by_size = node.prev_by_size;
    node.prev_by_size->next_by_size = node.next_by_size;


}

void MemoryList3::enter_to_size_list(MemoryList3::MallocMetadataNode &node) {

}

// ****************************** malloc_2.cpp file: ******************************

void *smalloc(size_t size) {
    if (size == 0 || size > MAX_SIZE) {
        return nullptr;
    }
    return MemoryList3::get().allocate(size);
}

void* scalloc(size_t num, size_t size) {
    void* address = smalloc(size * num);
    if(address == nullptr)
    {
        return nullptr;
    }
    memset(address, 0, size*num);
    return address;
}

void* srealloc(void * oldp, size_t size){
    if(size > MAX_SIZE || size == 0)
        return nullptr;
    auto& list = MemoryList3::get();
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
    MemoryList3::get().free(p);
}
