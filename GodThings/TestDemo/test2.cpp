#include "test2.h"

int abc;
void testStatic() {
	abc = 10;
	printf("%p\n", &abc);
}