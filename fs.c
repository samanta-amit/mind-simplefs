#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#include "simplefs.h"

/* spin locks for hashtable */
struct spinlock *test_spin_lock;



/* Mount a simplefs partition */
struct dentry *simplefs_mount(struct file_system_type *fs_type,
                              int flags,
                              const char *dev_name,
                              void *data)
{
    struct dentry *dentry =
        mount_bdev(fs_type, flags, dev_name, data, simplefs_fill_super);
    if (IS_ERR(dentry)){
        pr_err("'%s' mount failure\n", dev_name);
    }else{
        pr_info("'%s' mount success\n", dev_name);
	
	//on mount success tell the switch what stuff we want initialized
	//I think that we want to make the writeable_file_map input 1, because above the call
	//to do_disagg_mmap_owner it is set to 1 "to make switch think writable filemappings are anonymous" 
	int ownership = 0
	//can we just come up with a garbage name for file? Or does it have to actually be connected
	//to a file on the compute node?
	//I assume we want pgoff to be zero (start at the first byte in the first page)
	//not sure what flags or prot we would use, looks like they are used to determine 
	//the value of writeable_file_map and the vm_flags
	//
	//
	//mm_addr = do_disagg_mmap_owner(current, (inode << 16), page_size * 10, 0, 0, 0, 0, "file", &ownership, writable_file_map );
	
	
	/*
        for(int i = 0; i < 10; i ++){
        	mm_addr = do_disagg_mmap_owner(current, (i << 16), PAGE_SIZE * 10, 0, 0, 0, 0, NULL, &ownership, 1);
		//ownership might need to be checked here.
	}
	*/


    }



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
	pr_info("loading simplefs\n");

	test_spin_lock = kmalloc(sizeof(struct spinlock), GFP_KERNEL);
	/* initializes the spin lock */
	spin_lock_init(test_spin_lock);

	int ret = simplefs_init_inode_cache();
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
