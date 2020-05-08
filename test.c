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
void delete_ram(char* addr) {
    if (mem == addr) {
        mem = NULL;
    }
    munmap(addr, 4096);
    //TODO: somehow tell module to send delete request to remote page

}
/*returns one allocated page*/
char* download_more_ram() {
    if (ramfd == 0)
        ramfd = open(DEVICE_FILENAME, O_RDWR|O_NDELAY);  
    
    if (ramfd < 0) {
        printf("failed to open ram file\n");
        goto out;
    }


    /*allocate new block*/
     char* memt = (char*)mmap(NULL,  
                    4096, //constant one page for now
                    PROT_READ | PROT_WRITE,  
                    MAP_SHARED | MAP_NORESERVE,  
                    ramfd,  
                    0);
    if (!memt) {
        printf("failed to get more ram\n");
        goto out;
    }
    if (mem != NULL) {
        printf("previous mapping exists: %p\n", mem);
        /*hard invalidate old mapping*/
        munmap(mem, 4096);
        /*remap so that vma_ops are kept and old stuff can be paged back in with the fault op*/
        char *t = mmap(mem,
             4096,
             PROT_READ | PROT_WRITE,  
             MAP_SHARED | MAP_NORESERVE,  
             ramfd,  
             0);
        printf("remapped %p to %p\n", mem, t);
    }
    
    /*set new current mapping*/
    mem = memt;
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