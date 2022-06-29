#include <iostream>
#include <unistd.h>
#include "smalloc.h"

inline void run_malloc_1();

int main() {
    run_malloc_1();
    return 0;
}

inline void run_malloc_1(){
    std::cout << sbrk(0) << std::endl;
    size_t size = sizeof(int) * 10;
    void* biny = smalloc(size);
    std::cout <<"I'm gonna increase " << size <<std::endl;
    *((int*)biny ) = 2;
    *((int*)biny + 1) = 3;
    //int num = 5;

    std::cout <<*(int*)biny +1<< std::endl;
    std::cout << sbrk(0) << std::endl;
    std::cout << "Hello, World!" << std::endl;
}