#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <../../mm/internal.h>
#include <../../include/disagg/cnthread_disagg.h>
#include <../../include/disagg/exec_disagg.h>
#include <../../include/disagg/fault_disagg.h>
#include <../../include/disagg/network_rdma_disagg.h>
#include <../../mm/internal.h>
#include <../../roce_modules/roce_for_disagg/roce_disagg.h>
#include <asm/traps.h>
#include <../include/disagg/kshmem_disagg.h>

#include <linux/init.h>

#include "simplefs.h"


unsigned long sharedaddress;
unsigned long shmem_address[10];
unsigned long inode_address[10];
unsigned long combined_address[20];
static int readAddress = 0;
//https://lynxbee.com/passing-command-line-arguments-parameters-to-linux-kernel-module/#.ZAUI5oDMKCg
//https://tldp.org/LDP/lkmpg/2.4/html/x354.htm (also used this for printing longs)
module_param(readAddress,int, 0);
module_param_array(combined_address, long, NULL, 0);

/* Mount a simplefs partition */
struct dentry *simplefs_mount(struct file_system_type *fs_type,
                              int flags,
                              const char *dev_name,
                              void *data)
{
    struct dentry *dentry =
        mount_bdev(fs_type, flags, dev_name, data, simplefs_fill_super);
    if (IS_ERR(dentry))
        pr_err("'%s' mount failure\n", dev_name);
    else
        pr_info("'%s' mount success\n", dev_name);

    return dentry;
}

/* Unmount a simplefs partition */
void simplefs_kill_sb(struct super_block *sb)
{
    kill_block_super(sb);

    pr_info("unmounted disk\n");
}

static struct file_system_type simplefs_file_system_type = {
    .owner = THIS_MODULE,
    .name = "simplefs",
    .mount = simplefs_mount,
    .kill_sb = simplefs_kill_sb,
    .fs_flags = FS_REQUIRES_DEV,
    .next = NULL,
};

static int __init simplefs_init(void)
{
    set_invalidate_page_callback(testing_invalidate_page_callback);
    set_shmem_address_check(shmem_address_check);
    int i;
    int ret;
    u64 alloc_size = sizeof(3 * PAGE_SIZE);

    pr_info("loading simplefs\n");
    pr_info("value of readAddress %d", readAddress);
    sharedaddress = 18446718784707231744llu;   //-234881024; //alloc_kshmem(alloc_size, DISAGG_KSHMEM_SERV_FS_ID);

    if(!readAddress){
	    pr_info("addresses:");
	    for(i = 0; i < 10; i++){
		    shmem_address[i] = (uintptr_t)alloc_kshmem(alloc_size, DISAGG_KSHMEM_SERV_FS_ID);
		    pr_info("%ld, ", shmem_address[i]);
	    }
            
	    pr_info("single print addresses %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld", shmem_address[0],
				shmem_address[1],
				shmem_address[2],
				shmem_address[3],
				shmem_address[4],
				shmem_address[5],
				shmem_address[6],
				shmem_address[7],
				shmem_address[8],
				shmem_address[9]
				);

	    pr_info("\n");

	    pr_info("inode addresses:");
            for(i = 0; i < 10; i++){
                    inode_address[i] = (uintptr_t)alloc_kshmem(PAGE_SIZE, DISAGG_KSHMEM_SERV_FS_ID);
                    pr_info("%ld, ", inode_address[i]);
            }
            
	    pr_info("single print inode addresses %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld", inode_address[0],
                                inode_address[1],
                                inode_address[2],
                                inode_address[3],
                                inode_address[4],
                                inode_address[5],
                                inode_address[6],
                                inode_address[7],
                                inode_address[8],
                                inode_address[9]
                                );

            pr_info("\n");
    }else{
	    for(i = 0; i < 10; i++){
	    	shmem_address[i] = combined_address[i];
	    }

	    for(i = 10; i < 20; i++){
	    	inode_address[i-10] = combined_address[i];
	    }

	    pr_info("read addresses:");
	    for(i = 0; i < 10; i++){
		    pr_info("%ld, ", shmem_address[i]);
	    }
	    pr_info("\n");

            pr_info("inode addresses:");
            for(i = 0; i < 10; i++){
                    pr_info("%ld, ", inode_address[i]);
            }
            pr_info("\n");
    }
   
    /*
    for(i = 0; i < 10; i++){
	    pr_info("alloc kshmem address %ld", sharedaddress); 
	    unsigned long test_address =  64 * PAGE_SIZE + (i+1) * (unsigned long)(0x200000);
	    unsigned long test_size = 3 * PAGE_SIZE;

	    unsigned long temp = alloc_kshmem_va(test_address, test_size, DISAGG_KSHMEM_SERV_FS_ID);
	    pr_info("KernShmem: alloc with VA result Requested [0x%lx] <-> Received [0x%lx]\n", test_address, temp);
    }*/

    ret = simplefs_init_inode_cache();
    if (ret) {
        pr_err("inode cache creation failed\n");
        goto end;
    }

    ret = register_filesystem(&simplefs_file_system_type);
    if (ret) {
        pr_err("register_filesystem() failed\n");
        goto end;
    }

    pr_info("module loaded\n");

end:
    return ret;
}

static void __exit simplefs_exit(void)
{
    int ret = unregister_filesystem(&simplefs_file_system_type);
    if (ret)
        pr_err("unregister_filesystem() failed\n");

    simplefs_destroy_inode_cache();

    pr_info("module unloaded\n");
}

module_init(simplefs_init);
module_exit(simplefs_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");
MODULE_DESCRIPTION("a simple file system");
