#include <stdlib.h>
#include <cmath>
#include <unistd.h>
#include <iostream>

static constexpr unsigned int MAX_SIZE = 1E8;

void* smalloc(size_t size){
    if(size == 0 || size > MAX_SIZE)
    {
        return nullptr;
    }
    void* start_of_alloc = sbrk((long) size);
    if(start_of_alloc == (void *) -1)
    {
        return nullptr;
    }
    return start_of_alloc;
}

