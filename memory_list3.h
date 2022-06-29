//
// Created by alonb on 29/06/2022.
//

#ifndef HW4_MEMORY_LIST3_H
#define HW4_MEMORY_LIST3_H


using SearchDirection = enum SearchDirection {BY_SIZE, BY_ADDRESS};

class MemoryList {
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

    MemoryList();
    void * add_node(size_t size);
public:
    static MemoryList& get(){
        static MemoryList list;
        return list;
    }

    MemoryList(MemoryList&) = delete;
    MemoryList operator=(MemoryList&) = delete;
    void * allocate(size_t size, enum SearchDirection direction);
    void free(void* address);
    void * reallocate(void* address, size_t size, enum SearchDirection direction);
};




#endif //HW4_MEMORY_LIST3_H
