#include <stdlib.h>
#include <cmath>
#include <iostream>
#include <unistd.h>
#include <cstring>
#include <sys/mman.h>

#define PRINT_PARAM(input) \
    std::cout << "PRINT_PARAM:\t" << input << std::endl;

#define EXIT_MESSAGE(integer) \
    do{\
    std::cout << "EXIT:\tline:" << __LINE__ << "status:\t" << integer <<std::endl; \
    exit(integer);            \
}while(0)

static constexpr unsigned int MAX_SIZE = 1E8;
static constexpr unsigned int MIN_SIZE = 128;
static constexpr unsigned int MIN_MMAP = 128 * 1024;

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

        explicit MallocMetadataNode(size_t size = 0, bool is_free = false, bool is_mmap = false) :
                metadata{size,  is_free},
                next_by_size(nullptr),
                prev_by_size(nullptr),
                next_by_address(nullptr),
                prev_by_address(nullptr) {};

        ~MallocMetadataNode() = default;
        void* address() const{
            return (char *) this + sizeof(*this);
        }
        size_t& size(){
            return metadata.size;
        }
        bool& is_free(){
            return is_free();
        }
        size_t total_size(){
            return metadata.size + sizeof(*this);
        }
    };

    struct MmapMetadataNode {
        Metadata metadata;
        MmapMetadataNode *next;
        MmapMetadataNode *prev;

        explicit MmapMetadataNode(size_t size = 0, bool is_free = false) :
                metadata{size,  is_free}, next(nullptr), prev(nullptr) {}

        ~MmapMetadataNode() = default;
        void* address() const{
            return (char *) this + sizeof(*this);
        }
        size_t& size(){
            return metadata.size;
        }
        bool& is_free(){
            return is_free();
        }
        size_t total_size(){
            return metadata.size + sizeof(*this);
        }
    };

    MallocMetadataNode head_size_list;
    MallocMetadataNode head_address_list;
    MallocMetadataNode end_size_list;
    MallocMetadataNode end_address_list;

    MmapMetadataNode head_mmap;
    MmapMetadataNode end_mmap;

    size_t free_blocks ;
    size_t free_bytes ;
    size_t allocated_bytes ;
    size_t allocated_blocks ;
    size_t meta_data_bytes ;

    MemoryList3();
    void * add_node(size_t size);
    bool split_node(MallocMetadataNode& node, size_t data_size);
    void enter_to_size_list(MallocMetadataNode* node);
    void enter_to_size_list(MallocMetadataNode& node);
    void remove_from_size_list(MallocMetadataNode* node);
    void remove_from_size_list(MallocMetadataNode& node);
    void merge_nodes(MallocMetadataNode* node);
    void merge_nodes(MallocMetadataNode& node);
    void * add_node_mmap();
    void *reallocate_block(MallocMetadataNode* node, size_t size);
    void *reallocate_mmap(MmapMetadataNode* node, size_t size);


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
    void dealocate(void* address);
    void *reallocate(void *address, size_t size);

    void merge_with_next_node(MallocMetadataNode *node);
};


// ****************************** list.cpp file: ******************************
MemoryList3::MemoryList3()
{
    head_size_list = MallocMetadataNode();
    head_address_list = MallocMetadataNode();
    end_address_list = MallocMetadataNode();
    end_size_list = MallocMetadataNode();
    head_mmap = MmapMetadataNode();
    end_mmap = MmapMetadataNode();
    head_address_list.next_by_address = &end_address_list;
    end_address_list.prev_by_address = &head_address_list;

    head_size_list.next_by_address = &end_size_list;
    end_size_list.prev_by_address = &head_size_list;

    head_mmap.next = &end_mmap;
    head_mmap.prev = &head_mmap;
}

void * MemoryList3::allocate(size_t size) {
    // * step 0: if size >= MIN_MMAP use mmap
    if(size >= MIN_MMAP){
        add_node(size);
    }
    // * step 1: search by ADDRESS a fitting block
    MallocMetadataNode* node;
    for (node = head_address_list.next_by_size; node != &end_size_list ; node = node->next_by_size) {
        if (!node->is_free() || node->size() < size)
            continue;
        if(split_node(*node,size))
        {
            free_bytes -= size;
        }
        else {
            node->is_free() = false;
            free_blocks--;
            free_bytes -= node->size();
        }
        return node->address();
    }

    // * step 2: if none of the existing blocks fit, create a new one!
    return add_node(size);
}
void * MemoryList3::add_node(size_t size) {
    //mmap:
    if(size >= MIN_MMAP){
        void* address = mmap(nullptr, size + sizeof(MmapMetadataNode), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if(address == MAP_FAILED)
            return nullptr;
        MmapMetadataNode* mmap_node = (MmapMetadataNode *) address;
        *mmap_node = MmapMetadataNode(size);

        MmapMetadataNode* next_ptr = &end_mmap;
        MmapMetadataNode* prev_ptr = next_ptr->prev;
        mmap_node->next = next_ptr;
        mmap_node->prev = prev_ptr;
        prev_ptr->next = mmap_node;
        next_ptr->prev = mmap_node;
        return mmap_node->address();
    }

    MallocMetadataNode* end_node = end_address_list.prev_by_address;
    //if the wilderness is dealocate use it
    // TODO: verify
    if(end_node->is_free() && end_node != &head_address_list)
    {
        void* extension = sbrk(size - end_node->size());
        if( extension == (void *) -1) return nullptr;
        end_node->is_free() = false;
        end_node->size() = size;
        (end_node->prev_by_size)->next_by_size = end_node->next_by_size;
        (end_node->next_by_size)->prev_by_size = end_node->prev_by_size;
        enter_to_size_list(end_node);

        return end_node;
    }
    //else allocate as usual
    MallocMetadataNode* new_node_ptr = (MallocMetadataNode*)sbrk(sizeof(MallocMetadataNode) + size);
    if((void *) new_node_ptr == (void *) -1) return nullptr;
    *new_node_ptr = MallocMetadataNode(size);

    //size loop:
    enter_to_size_list(new_node_ptr);

    //address (no) loop:
    MallocMetadataNode* next_ptr = &end_address_list;
    MallocMetadataNode* prev_ptr = next_ptr->prev_by_address;

    new_node_ptr->next_by_address = next_ptr;
    new_node_ptr->prev_by_address = prev_ptr;
    prev_ptr->next_by_address = new_node_ptr;
    next_ptr->prev_by_address = new_node_ptr;

    allocated_blocks++;
    allocated_bytes += size;
    meta_data_bytes += sizeof(MallocMetadataNode);
    return new_node_ptr->address();
}

void MemoryList3::dealocate(void *address) {
    //try sbrk list:
    for (MallocMetadataNode* ptr = head_address_list.next_by_address; ptr != &end_address_list; ptr = ptr->next_by_address)
    {
        if(ptr->address() == address){
            ptr->is_free() = true;
            merge_nodes(ptr);
            //TODO add statistics stage 2
            free_blocks++;
            free_bytes += ptr->size();
            return;
        }
    }

    //try mmap list:
    for (auto ptr = head_mmap.next; ptr != &end_mmap; ptr = ptr->next)
    {
        if(ptr->address() != address)
            continue;
        //else
        if(munmap(address,ptr->size() + sizeof(MallocMetadataNode)) == 0){
        }
        return;
    }
    EXIT_MESSAGE(1);
}

void *MemoryList3::reallocate(void *address, size_t size) {
    //find in blocks:
    for (auto ptr = head_address_list.next_by_address; ptr != &end_address_list; ptr = ptr->next_by_address)
    {
        if(ptr->address() == address && !ptr->is_free)
            return reallocate_block((MallocMetadataNode*)address, size);
    }
    for (auto ptr = head_mmap.next; ptr != &end_mmap; ptr = ptr->next)
    {
        if(ptr->address() == address)
            return reallocate_mmap((MmapMetadataNode*)address, size);
    }
    EXIT_MESSAGE(1);
    //return
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
    size_t new_node_size = node.size() - data_size - sizeof(MallocMetadataNode);
    if(new_node_size < MIN_SIZE){
        return false;
    }

    MallocMetadataNode * new_node_heap = (MallocMetadataNode *) node.address() + data_size;
    *new_node_heap = MallocMetadataNode(new_node_size, true);

    new_node_heap->next_by_address = node.next_by_address;
    new_node_heap->prev_by_address = &node;

    node.next_by_address->prev_by_address = new_node_heap;
    node.next_by_address = new_node_heap;
    node.size() = data_size;
    node.is_free() = false;

    node.next_by_size->prev_by_size = node.prev_by_size;
    node.prev_by_size->next_by_size = node.next_by_size;

    enter_to_size_list(node);
    enter_to_size_list(*new_node_heap);
    return true;
}
void MemoryList3::remove_from_size_list(MallocMetadataNode* node)
{
    if(node == &end_address_list ||  node == &head_address_list  ||node == &end_size_list ||  node == &head_size_list )
    {
        exit(1);
    }
    (node->prev_by_size)->next_by_size = node->next_by_size;
    (node->next_by_size)->prev_by_size = node->prev_by_size;
    node->next_by_size = nullptr;
    node->prev_by_size = nullptr;
}
void MemoryList3::enter_to_size_list(MemoryList3::MallocMetadataNode *node){
    MallocMetadataNode *prev_ptr = &head_size_list;
    MallocMetadataNode *next_ptr = prev_ptr->next_by_size;
    for(; next_ptr != &end_size_list; next_ptr = next_ptr->next_by_size)
    {
        if(next_ptr->size() > node->size()){
            break;
        }
        prev_ptr = next_ptr;
    }

    node->next_by_size = next_ptr;
    node->prev_by_size = prev_ptr;
    prev_ptr->next_by_size = node;
    next_ptr->prev_by_size = node;

}
void MemoryList3::remove_from_size_list(MemoryList3::MallocMetadataNode &node) {
    remove_from_size_list(&node);
}
void MemoryList3::enter_to_size_list(MemoryList3::MallocMetadataNode &node) {
    enter_to_size_list(&node);
}
void MemoryList3::merge_nodes(MemoryList3::MallocMetadataNode &node) {
    merge_nodes(&node);
}

void MemoryList3::merge_with_next_node(MemoryList3::MallocMetadataNode *node) {
    if(node->next_by_address != &end_address_list && node->next_by_address->is_free())
    {
        MallocMetadataNode* next = node->next_by_address;
        node->size() += next->total_size();
        next = next->next_by_address;
        next->prev_by_address = node;
        remove_from_size_list(next);
        remove_from_size_list(node);
        enter_to_size_list(node);
    }
}
void MemoryList3::merge_nodes(MemoryList3::MallocMetadataNode *node) {
    merge_with_next_node(node);
    merge_with_next_node(node->prev_by_address);


}

void * MemoryList3::reallocate_block(MallocMetadataNode* ptr, size_t size )
{
    //case a
    if(ptr->size() >= size)
    {
        ptr->size() = size;
        split_node(*ptr, size);
        return ptr->address();
    }
    
    //case b
    auto prev = ptr->prev_by_address;
    auto next = ptr->next_by_address;
    if(prev != &head_address_list && prev->is_free() && ptr->size() + prev->size() >= size)
    {
        prev->size() += ptr->total_size();
        prev->next_by_address = next;
        next->prev_by_address = prev;
        prev->is_free() = false;
        std::memmove(prev->address(), ptr->address(), ptr->size());
        split_node(*prev,size);
        remove_from_size_list(ptr);
        remove_from_size_list(prev);
        enter_to_size_list(prev);
        return prev->address();
    }

    if(ptr == end_address_list.prev_by_address && prev != &head_address_list && prev->is_free()) {
        void *extension = sbrk(size - prev->size() - ptr->size() - sizeof(MallocMetadataNode));
        if (extension == (void *) -1) {
            return nullptr;
        }
        prev->size() = size;
        prev->is_free() = false;
        prev->next_by_address = &end_address_list;
        end_address_list.prev_by_address = prev;
        //? free_bytes -= ptr->prev_by_address->size();
        std::memmove(prev->address(), ptr->address(), ptr->size());
        remove_from_size_list(ptr);
        remove_from_size_list(prev);
        enter_to_size_list(prev);
        return prev->address();
    }

    //case c
    if(ptr == end_address_list.prev_by_address)
    {
        void *extension = sbrk(size - ptr->size());
        if (extension == (void *) -1)
            return nullptr;
        ptr->size() = size;
        ptr->is_free() = false;
        remove_from_size_list(ptr);
        enter_to_size_list(ptr);
        return ptr;
    }

    //case d
    if(next != &end_address_list && size <= next->size() + ptr->size() + sizeof(MallocMetadataNode) && next->is_free()){
        merge_with_next_node(ptr);
        remove_from_size_list(next);
        remove_from_size_list(ptr);
        enter_to_size_list(ptr);
        split_node(*ptr, size);
        return ptr;
    }

    //case e
    if(next != &end_address_list && prev != &head_address_list && size <= next->size() + prev->size() + ptr->size() + 2*sizeof(MallocMetadataNode)
        && next->is_free() && prev->is_free()){
        prev->is_free() = false;
        merge_with_next_node(ptr);
        merge_with_next_node(prev);
        std::memmove(prev->address(), ptr->address(), ptr->size());
        split_node(*prev, size);
        return prev;
    }

    //case f
    if (next == end_address_list.prev_by_address && next->is_free()){
        //sub case i
        if(prev != &head_address_list && prev->is_free()) {
            prev->is_free() = false;
            prev->size() = size;
            void *extension = sbrk(size -prev->size()- ptr->size()- next->size() - sizeof(MallocMetadataNode) * 2);
            if (extension == (void *) -1)
                return nullptr;
            merge_with_next_node(ptr);
            merge_with_next_node(prev);
            std::memmove(prev->address(), ptr->address(), ptr->size());
            ptr = prev;
        }
        //sub case ii
        else
        {
            ptr->size() = size;
            void *extension = sbrk(size - ptr->size()- next->total_size());
            if (extension == (void *) -1)
                return nullptr;
            merge_with_next_node(ptr);
        }
        return ptr->address();
    }

    //case g
    MallocMetadataNode* new_node = nullptr;
    for(auto node_ptr = head_size_list.next_by_size; node_ptr != &end_size_list; node_ptr = node_ptr->next_by_size){
        if(node_ptr->is_free() && node_ptr->size() >= size){
            new_node = node_ptr;
            break;
        }
    }
    if(new_node != nullptr){
        std::memmove(new_node->address(), ptr->address(), ptr->size());
        new_node->is_free() = false;
        dealocate(ptr->address());
//        remove_from_size_list(new_node);
//        enter_to_size_list(new_node);
        split_node(*new_node, size);
        return new_node->address();
    }

    // h case:
    auto ret_address = allocate(size);
    if(ret_address == nullptr)
        return nullptr;
    std::memmove(ret_address, ptr->address(), ptr->size());
    ptr->is_free() = true;
    dealocate(ptr->address());
    return ret_address;
}

void *MemoryList3::reallocate_mmap(MemoryList3::MmapMetadataNode *node, size_t size) {
    if(size == node->size()){
        return node->address();
    }
    if(size < MIN_MMAP){
        EXIT_MESSAGE(1);
    }
    void* address = mmap(nullptr, size + sizeof(MmapMetadataNode), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if(address == MAP_FAILED)
        EXIT_MESSAGE(1);
    node->next->prev = node->prev->next;
    node->prev->next = node->next->prev;
    auto new_node = (MmapMetadataNode *) address;
    *new_node = MmapMetadataNode(size);
    memmove(new_node, node, size);
    munmap(node, sizeof(MmapMetadataNode) + node->size());
    node = nullptr;
    return address;
}




// ****************************** malloc_3.cpp file: ******************************

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
    MemoryList3::get().dealocate(p);
}

//TODO
//  1) allingment
//  2)
//
//
//
//