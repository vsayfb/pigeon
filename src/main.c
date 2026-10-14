#include <stdio.h>

#ifndef PIGEON_VERSION
#define PIGEON_VERSION "dev"
#endif

int main(void) {
    printf("pigeon %s\n", PIGEON_VERSION);
    return 0;
}