#include <fcntl.h>  
#include <unistd.h>  
#include <sys/mman.h>  
#include <stdio.h>
#include <string.h>
#include<errno.h>
#include <sys/types.h>

#define DEVICE_FILENAME "/dev/tram"  

static char *mem = NULL;
static int ramfd;

int init_ram_server(unsigned long int ip, unsigned int port) {
    //write to the /dev file
}
char* download_more_ram() {
    if (ramfd == 0)
        ramfd = open(DEVICE_FILENAME, O_RDWR|O_NDELAY);  
    
    if (ramfd < 0) {
        printf("failed to open ram file\n");
        goto out;
    }
    munmap(mem, 4096); //unmap previous since internal buffer should only be one page
    mem = (char*)mmap(NULL,  
                    4096, //constant one page for now
                    PROT_READ | PROT_WRITE,  
                    MAP_SHARED,  
                    ramfd,  
                    0);
    if (!mem) {
        printf("failed to get more ram\n");
        goto out;
    }

    out:
        return mem;
}
int main()  
{  
    printf("pid: %d\n", getpid());
    int fd;  
    int ret;
    char *p = NULL;
    char *p2 = NULL;
    char buff[64];    
    p = download_more_ram();
    
    p2 = p;
    printf("page %p contains: %s\n", p, p);

    printf("attempting to write to page %p\n", p);
    *p = 'A';
    printf("page %p contains: %s\n", p, p);
    //printf("here");
    //if (*p == 'A') { //so that compiler doesn't optimize second access out
    //    printf("yolo\n");
    //    *p = 'Q';
    //}
    
    printf("allocating another page\n");
    p = download_more_ram();
    printf("attempting to write to page %p\n", p);
    *p = 'B';
    printf("page %p contains: %s\n", p, p);
    printf("attempting to write to first allocated page\n");
    *p2 = 'A';
    printf("page %p contains: %s\n", p2, p2);
    //close(fd);
out:
    return ret;  
}  