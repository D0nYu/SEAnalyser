#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(){
	char *ptr1 = getenv("PATH");
	char* ptr2 = getenv("PATH");
	printf("%p,%8x,%s\n%p,%8x,%s",ptr1,ptr1,ptr1,ptr2,ptr2,ptr2);
}