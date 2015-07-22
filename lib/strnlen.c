
#include <sys/types.h>

size_t strnlen (__const char *__string, size_t __maxlen)
{
	size_t len;
	
	for(len = 0; len < __maxlen && __string[len]; len++);
	
	return len;
}

