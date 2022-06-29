//
// Created by alonb on 22/06/2022.
//

#ifndef OS_HW4_MEMORY_LIST_2_H
#define OS_HW4_MEMORY_LIST_2_H

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
                prev(nullptr)
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



#endif //OS_HW4_MEMORY_LIST_2_H
