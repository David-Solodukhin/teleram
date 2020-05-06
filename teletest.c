#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/init.h> 
#include <linux/fs.h> 
#include <linux/mm.h> 
#include <linux/uaccess.h>
#include <linux/slab.h>


#include <linux/net.h>
#include <linux/in.h>
#include <linux/netpoll.h>
#define MESSAGE_SIZE 1024
#define INADDR_SEND ((unsigned long int) (0x7f000001)) //127.0.0.1
static struct socket *sock;
static struct sockaddr_in sin;
static struct msghdr msg;
static struct iovec iov;

static int error, len;
static mm_segment_t old_fs;
static char message[MESSAGE_SIZE];

#define MAX_SIZE (PAGE_SIZE)   /* max size mmaped to userspace */
#define DEVICE_NAME "mchar"
#define  CLASS_NAME "mogu"

static struct class*  class;
static struct device*  device;
static int major;
static char *sh_mem = NULL; 

static DEFINE_MUTEX(mchar_mutex);

/*  executed once the device is closed or releaseed by userspace
 *  @param inodep: pointer to struct inode
 *  @param filep: pointer to struct file 
 */
static int mchar_release(struct inode *inodep, struct file *filep)
{    
    mutex_unlock(&mchar_mutex);
    pr_info("mchar: Device successfully closed\n");

    return 0;
}

/* executed once the device is opened.
 *
 */
static int mchar_open(struct inode *inodep, struct file *filep)
{
    int ret = 0; 
    if(!mutex_trylock(&mchar_mutex)) {
        pr_alert("mchar: device busy!\n");
        ret = -EBUSY;
        goto out;
    }
    
    pr_info("mchar: Device opened\n");

out:
    return ret;
}

static void send_dank_msg(void) {
    error = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
    if (error<0)
        printk(KERN_DEBUG "socket create failed :( Error %d\n",error);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(1337);
    sin.sin_addr.s_addr = htonl(INADDR_SEND);
    error = sock->ops->connect(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr), 0);
    if (error<0)
        printk(KERN_DEBUG "socket connect failed. Error %d\n",error);
    sprintf(message, "there is no documentation anywhere");
    len = strlen(message);
    printk("%d", len);
    printk("%s", message);
    //msg.msg_flags = 0;
    //msg.msg_iocb = NULL;
    msg.msg_name = &sin;
    msg.msg_namelen  = sizeof(struct sockaddr_in);
    //msg.msg_control = NULL;
    //msg.msg_controllen = 0;
    iov.iov_base = message;
    iov.iov_len = len;
    iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, len); //last arg is length??
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    error = sock_sendmsg(sock,&msg);
    set_fs(old_fs);
    pr_info("error: %d", error); //errors are <0, # bytes sent are >0
}

void simple_vma_open(struct vm_area_struct *vma)
{
    printk(KERN_NOTICE "VMA open, virt %lx, phys %lx\n",
    vma->vm_start, vma->vm_pgoff << PAGE_SHIFT);
}
void simple_vma_close(struct vm_area_struct *vma)
{
    printk(KERN_NOTICE "VMA close.\n");
}


unsigned int simple_vma_fault(struct vm_fault *vmf)
{

    struct vm_area_struct *vma = vmf->vma;
    struct page *page = NULL;
    unsigned long offset;
    printk(KERN_NOTICE "MWR: simple_vma_fault\n");
    offset = (((unsigned long)vmf->address - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT));
    if (offset > PAGE_SIZE << 4) {
        goto nopage_out;  
    }
    printk("virt to page? %lx", vmf->address);  
    page = virt_to_page((unsigned long)sh_mem + offset);
    pr_info("page addr: %p", page);
    get_page(page); //refcount, update page metadata
    vmf->page = page;
    printk("vm:%p ",sh_mem);  


    send_dank_msg();

nopage_out:
    return 0;
}

static struct vm_operations_struct simple_remap_vm_ops = {
.open = simple_vma_open,
.close = simple_vma_close,
.fault = simple_vma_fault,
};
static int mchar_mmap(struct file *filp, struct vm_area_struct *vma)
{
    printk(KERN_INFO "Device simple_vma_ops_mmap\n");
    vma->vm_private_data = sh_mem;
    vma->vm_ops = &simple_remap_vm_ops;
    simple_vma_open(vma);
    printk(KERN_INFO "Device mmap OK\n");
    return 0;
}



static const struct file_operations mchar_fops = {
    .open = mchar_open,
    //.read = mchar_read,
    //.write = mchar_write,
    .release = mchar_release,
    .mmap = mchar_mmap,
    /*.unlocked_ioctl = mchar_ioctl,*/
    .owner = THIS_MODULE,
};

static char *devnode(struct device *dev, umode_t *mode)
{
    printk("setting permissions for device");
    if (!mode)
        return NULL;
    *mode = 0666;
    return NULL;
}

static int __init mchar_init(void)
{
    int ret = 0;    
    major = register_chrdev(0, DEVICE_NAME, &mchar_fops);

    if (major < 0) {
        pr_info("failed to register major");
        ret = major;
        goto out;
    }

    class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(class)){ 
        unregister_chrdev(major, DEVICE_NAME);
        pr_info("failed to register device class");
        ret = PTR_ERR(class);
        goto out;
    }

    class->devnode=devnode;
    device = device_create(class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(device)) {
        class_destroy(class);
        unregister_chrdev(major, DEVICE_NAME);
        ret = PTR_ERR(device);
        goto out;
    }



    /* init this mmap area */
    sh_mem = kzalloc(MAX_SIZE, GFP_KERNEL); 
    if (sh_mem == NULL) {
        ret = -ENOMEM; 
        goto out;
    }
    printk("init");
    sprintf(sh_mem, "xyz\n"); 
    struct page* page;
    page = virt_to_page(sh_mem);
    pr_info("device internal buffer: %p, page addr: %p", sh_mem, page);
    mutex_init(&mchar_mutex);



    send_dank_msg();
    send_dank_msg();
    pr_info("finished set up");
out: 
    return ret;
}

static void __exit mchar_exit(void)
{
    mutex_destroy(&mchar_mutex); 
    device_destroy(class, MKDEV(major, 0));  
    class_unregister(class);
    class_destroy(class); 
    unregister_chrdev(major, DEVICE_NAME);
    kfree(sh_mem);
    
    pr_info("mchar: unregistered!");
}

module_init(mchar_init);
module_exit(mchar_exit);
MODULE_LICENSE("GPL");