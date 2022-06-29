#include <stdlib.h>
#include <cmath>
#include <unistd.h>
#include <iostream>

constexpr unsigned int MAX_SIZE = pow(10, 8);

void* smalloc(size_t size){
    if(size == 0 || size > MAX_SIZE)
    {
        return nullptr;
    }
    void* start_of_alloc = sbrk((long) size);
    if(start_of_alloc < 0)
    {
        return nullptr;
    }
    return start_of_alloc;
}


