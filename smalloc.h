//
// Created by alonb on 29/06/2022.
//

#ifndef HW4_SMALLOC_H
#define HW4_SMALLOC_H

void* smalloc(size_t size);
void* scalloc(size_t num, size_t size);
void* srealloc(void * oldp, size_t size);
void* sfree(void* p);

#endif //HW4_SMALLOC_H
