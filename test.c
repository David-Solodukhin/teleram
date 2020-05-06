#include <fcntl.h>  
#include <unistd.h>  
#include <sys/mman.h>  
#include <stdio.h>
#include <string.h>
#include<errno.h>
  
#define DEVICE_FILENAME "/dev/mchar"  
  
int main()  
{  
    int fd;  
    int ret;
    char *p = NULL;
    char *p2 = NULL;
    char buff[64];    
  
    fd = open(DEVICE_FILENAME, O_RDWR|O_NDELAY);  
    if (fd < 0) {
        printf("failed to open device file");
        goto out;
    }
    p = (char*)mmap(NULL,  
                    4096,  
                    PROT_READ | PROT_WRITE,  
                    MAP_SHARED,  
                    fd,  
                    0);

    printf("%p", p);
    printf("attempting to write to page\n");
    *p = 'A';
    printf("%s", p);
    //create another ram map?
    p2 = (char*)mmap(NULL,  
                    4096,  
                    PROT_READ | PROT_WRITE,  
                    MAP_SHARED,  
                    fd,  
                    0);
    printf("%s", p2);


        //munmap(p, 4096);  
  
    close(fd);
out:
    return ret;  
}  