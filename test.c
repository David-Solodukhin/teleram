#include <fcntl.h>  
#include <unistd.h>  
#include <sys/mman.h>  
#include <stdio.h>
#include <string.h>
#include<errno.h>
#include <sys/types.h>

#define DEVICE_FILENAME "/dev/tram"  


int init_ram_server(unsigned long int ip, unsigned int port) {
    //write to the /dev file
}
char* download_more_ram() {
    int fd;
    char *p = NULL;
    fd = open(DEVICE_FILENAME, O_RDWR|O_NDELAY);  
    
    if (fd < 0) {
        printf("failed to open ram file\n");
        goto out;
    }
    p = (char*)mmap(NULL,  
                    4096, //constant one page for now
                    PROT_READ | PROT_WRITE,  
                    MAP_SHARED,  
                    fd,  
                    0);
    if (!p) {
        printf("failed to get more ram\n");
        goto out;
    }
    close(fd);

    out:
        return p;
}
int main()  
{  
    printf("pid: %d\n", getpid());
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
    printf("allocating a page\n");
    p = (char*)mmap(NULL,  
                    4096,  
                    PROT_READ | PROT_WRITE,  
                    MAP_SHARED,  
                    fd,  
                    0);
    p2 = p;
    printf("page %p contains: %s\n", p, *p);

    printf("attempting to write to page %p\n", p);
    *p = 'A';
    printf("page %p contains: %s\n", p, *p);
    //printf("here");
    //if (*p == 'A') { //so that compiler doesn't optimize second access out
    //    printf("yolo\n");
    //    *p = 'Q';
    //}
    
    printf("allocating another page\n");
    p = (char*)mmap(NULL,  
                    4096,  
                    PROT_READ | PROT_WRITE,  
                    MAP_SHARED,  
                    fd,  
                    0);
    printf("attempting to write to page %p\n", p);
    *p = 'B';
    printf("page %p contains: %s\n", p, *p);
    printf("attempting to write to first allocated page\n");
    *p2 = 'A';
    printf("page %p contains: %s", p2, *p2);
    close(fd);
out:
    return ret;  
}  