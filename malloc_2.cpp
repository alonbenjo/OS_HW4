#include <stdlib.h>
#include <cmath>
#include <iostream>
#include <unistd.h>
#include <cstring>

#define PRINT_PARAM(input) \
    std::cin << "PRINT_PARAM:\t" << input << std::endl;

// ****************************** H file: ******************************
class MemoryList2 {
private:
    struct Metadata {
        size_t size;
        bool is_free;
    };

    struct MallocMetadataNode {
        Metadata metadata;
        MallocMetadataNode *next;
        MallocMetadataNode *prev;

        explicit MallocMetadataNode(size_t size = 0, void * address = nullptr, bool is_free = false) :
                metadata{size,address, is_free},
                next(nullptr),
                prev(nullptr) {}
        ~MallocMetadataNode() = default;
        void* address() const{
            return (char *) this + sizeof(*this);
        }
    };

    MallocMetadataNode head_list;
    MallocMetadataNode end_list;

    size_t free_blocks ;
    size_t free_bytes ;
    size_t allocated_bytes ;
    size_t allocated_blocks ;
    size_t meta_data_bytes ;

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
    const size_t& getFreeBlocks() const;
    const size_t& getFreeBytes() const;
    const size_t& getAllocatedBytes() const;
    size_t  getAllocatedBlocks() const;
    const size_t& getMetaDataBytes() const;
    static size_t getMetaData();

};


// ****************************** CPP file: ******************************
MemoryList2::MemoryList2() : head_list(), end_list(), free_blocks(0), free_bytes(0),  allocated_bytes(0), meta_data_bytes(0) {
    head_list.next = &end_list;
    end_list.prev = &head_list;
    allocated_blocks = 0;
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
        free_blocks --;
        free_bytes -= node->metadata.size;
        return node->address();
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
    MallocMetadataNode *next_ptr, *prev_ptr;

    //address (no) loop:
    next_ptr = &end_list;
    prev_ptr = next_ptr->prev;

    our_data->next = next_ptr;
    our_data->prev = prev_ptr;
    prev_ptr->next = our_data;
    next_ptr->prev = our_data;
    allocated_blocks++;
    allocated_bytes += size;
    meta_data_bytes += sizeof(MallocMetadataNode);
    return our_data->address();
}

void MemoryList2::free(void *address) {
    for (MallocMetadataNode* ptr = head_list.next; ptr != &end_list; ptr = ptr->next)
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

void *MemoryList2::reallocate(void *address, size_t size) {
    //address loop:
    MallocMetadataNode* ptr;
    for (ptr = head_list.next; ptr != &end_list; ptr = ptr->next)
    {
        if(ptr->address() == address)
            break;
    }
    if (ptr == &end_list)
        exit(1);

    if(ptr->metadata.size >= size)
        return ptr->address();

    void* ret_address = allocate(size);
    if(ret_address == nullptr)
        return nullptr;

    std::memmove(ret_address, address, size);

    ptr->metadata.is_free = true;
    free_blocks++;
    free_bytes += ptr->metadata.size;
    return ret_address;
}

const size_t& MemoryList2::getFreeBlocks() const {
    return free_blocks;
}

const size_t& MemoryList2::getFreeBytes() const {
    return free_bytes;
}

const size_t& MemoryList2::getAllocatedBytes() const {
    return allocated_bytes;
}

size_t MemoryList2::getAllocatedBlocks() const {
    return allocated_blocks;
}

const size_t& MemoryList2::getMetaDataBytes() const {
    return meta_data_bytes;
}

size_t MemoryList2::getMetaData() {
    return sizeof(MallocMetadataNode);
}

// ****************************** malloc_2.cpp file: ******************************
static constexpr unsigned int MAX_SIZE = 1E8;

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
    memset(address, 0, size*num);
    return address;
}

void* srealloc(void * oldp, size_t size){
    if(size > MAX_SIZE || size == 0)
        return nullptr;
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

size_t _num_free_blocks(){
    return MemoryList2::get().getFreeBlocks();
}

size_t _num_free_bytes(){
    return MemoryList2::get().getFreeBytes();
}

size_t _num_allocated_bytes(){
    return MemoryList2::get().getAllocatedBytes();
}

size_t _num_allocated_blocks(){
    return MemoryList2::get().getAllocatedBlocks();
}

size_t _num_meta_data_bytes(){
    return MemoryList2::get().getMetaDataBytes();
}

size_t _size_meta_data(){
    return MemoryList2::getMetaData();
}