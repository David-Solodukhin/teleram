#include <fcntl.h>  
#include <unistd.h>  
#include <sys/mman.h>  
#include <stdio.h>
#include <string.h>
#include<errno.h>
  
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