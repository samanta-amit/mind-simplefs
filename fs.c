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
unsigned long shmem_address[FILE_SIZE];
unsigned long inode_address[FILE_COUNT];
unsigned long inode_size_address[FILE_COUNT];

unsigned long size_lock_address;
unsigned long inode_lock_address;
unsigned long new_inode_lock_address[FILE_COUNT];
//unsigned long combined_address[52];
unsigned long combined_address[1];
unsigned int remote_lock_status[FILE_COUNT]; 
unsigned int inode_size_status[FILE_COUNT];//0 not held, 1 read mode, 2 write mode


//struct spinlock_t size_locks[10];
//struct rw_semaphore size_locks[20];
//struct rw_semaphore remote_inode_locks[20];
struct lock_class_key i_size_key;
struct lock_class_key i_remote_key;

/*
DEFINE_SPINLOCK(s0);DEFINE_SPINLOCK(s1);DEFINE_SPINLOCK(s2);DEFINE_SPINLOCK(s3);
DEFINE_SPINLOCK(s4);DEFINE_SPINLOCK(s5);DEFINE_SPINLOCK(s6);DEFINE_SPINLOCK(s7);
DEFINE_SPINLOCK(spin8);DEFINE_SPINLOCK(s9);
DEFINE_SPINLOCK(s10);DEFINE_SPINLOCK(s11);DEFINE_SPINLOCK(s12);DEFINE_SPINLOCK(s13);
DEFINE_SPINLOCK(s14);DEFINE_SPINLOCK(s15);DEFINE_SPINLOCK(spin16);DEFINE_SPINLOCK(s17);
DEFINE_SPINLOCK(spin18);DEFINE_SPINLOCK(s19);
*/

//spinlock_t * spin_size_lock[20] = {&s0, &s1, &s2, &s3, &s4,&s5,&s6,&s7,&spin8,&s9,&s10, &s11, &s12, &s13, &s14,&s15,&spin16,&s17,&spin18,&s19}; 

/*
DECLARE_RWSEM(srw0);
DECLARE_RWSEM(srw1);
DECLARE_RWSEM(srw2);
DECLARE_RWSEM(srw3);
DECLARE_RWSEM(srw4);
DECLARE_RWSEM(srw5);
DECLARE_RWSEM(srw6);
DECLARE_RWSEM(srw7);
DECLARE_RWSEM(srw8);
DECLARE_RWSEM(srw9);
DECLARE_RWSEM(srw10);
DECLARE_RWSEM(srw11);
DECLARE_RWSEM(srw12);
DECLARE_RWSEM(srw13);
DECLARE_RWSEM(srw14);
DECLARE_RWSEM(srw15);
DECLARE_RWSEM(srw16);
DECLARE_RWSEM(srw17);
DECLARE_RWSEM(srw18);
DECLARE_RWSEM(srw19);
*/
struct rw_semaphore size_test_rwlock[20];
struct rw_semaphore * size_rwlock[20]; //= {&srw0,&srw1,&srw2,&srw3,&srw4,&srw5,&srw6,&srw7,&srw8,&srw9, &srw10,&srw11,&srw12,&srw13,&srw14,&srw15,&srw16,&srw17,&srw18,&srw19};


/*
DEFINE_SPINLOCK(l0);DEFINE_SPINLOCK(l1);DEFINE_SPINLOCK(l2);DEFINE_SPINLOCK(l3);
DEFINE_SPINLOCK(l4);DEFINE_SPINLOCK(l5);DEFINE_SPINLOCK(l6);DEFINE_SPINLOCK(l7);
DEFINE_SPINLOCK(l8);DEFINE_SPINLOCK(l9);

spinlock_t * spin_inode_lock[10] = {&l0, &l1, &l2, &l3, &l4,&l5,&l6,&l7,&l8,&l9}; 
*/
/*DECLARE_RWSEM(l0);
DECLARE_RWSEM(l1);
DECLARE_RWSEM(l2);
DECLARE_RWSEM(l3);
DECLARE_RWSEM(l4);
DECLARE_RWSEM(l5);
DECLARE_RWSEM(l6);
DECLARE_RWSEM(l7);
DECLARE_RWSEM(l8);
DECLARE_RWSEM(l9);
DECLARE_RWSEM(l10);
DECLARE_RWSEM(l11);
DECLARE_RWSEM(l12);
DECLARE_RWSEM(l13);
DECLARE_RWSEM(l14);
DECLARE_RWSEM(l15);
DECLARE_RWSEM(l16);
DECLARE_RWSEM(l17);
DECLARE_RWSEM(l18);
DECLARE_RWSEM(l19);
*/
struct rw_semaphore inode_test_rwlock[20];
struct rw_semaphore * inode_rwlock[20];// = {&l0,&l1,&l2,&l3,&l4,&l5,&l6,&l7,&l8,&l9, &l10,&l11,&l12,&l13,&l14,&l15,&l16,&l17,&l18,&l19};




struct rw_semaphore hash_page_rwsem;

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
   pr_info("test invalidate page callback %d", testing_invalidate_page_callback);
	pr_info("test shmem_address check %d", shmem_address_check);
    set_invalidate_page_callback(testing_invalidate_page_callback);
    set_shmem_address_check(shmem_address_check);
    int i;
    int ret;
    u64 page_alloc_size = sizeof(FILE_SIZE * PAGE_SIZE);
    u64 alloc_size = sizeof(1 * PAGE_SIZE);

    pr_info("loading simplefs\n");
    pr_info("value of readAddress %d", readAddress);
    sharedaddress = 18446718784707231744llu;   //-234881024; //alloc_kshmem(alloc_size, DISAGG_KSHMEM_SERV_FS_ID);


    //lock and status init
    init_rwsem(&hash_page_rwsem);
    for(i = 0; i < FILE_COUNT; i++){
	    //init_rwsem(&(size_locks[i]));
	    //lockdep_set_class(&(size_locks[i]), i_size_key);
	    //init_rwsem(&(remote_inode_locks[i]));
	    //lockdep_set_class(&(remote_inode_locks[i]), i_remote_key);
	    //spin_lock_init((spin_inode_lock[i]));
	    //spin_lock_init((spin_size_lock[i]));
	    //init_rwsem((inode_rwlock[i]));
	    //init_rwsem((size_rwlock[i]));
	    
	    
	    //testing dynamic allocation (again)
    	    init_rwsem(&(size_test_rwlock[i]));
	    size_rwlock[i] = &(size_test_rwlock[i]);
    	    init_rwsem(&(inode_test_rwlock[i]));
	    inode_rwlock[i] = &(inode_test_rwlock[i]);
	    remote_lock_status[i] = 0; 
	    inode_size_status[i] = 0;

    }

	//end of lock and status init


    if(!readAddress){
	    pr_info("test allocation");
            uintptr_t start_address = (uintptr_t)alloc_kshmem(5000 * PAGE_SIZE, DISAGG_KSHMEM_SERV_FS_ID);
	    uintptr_t current_address = start_address; 
	    pr_info("finished test allocation %ld", current_address);

	    pr_info("addresses:");
	    for(i = 0; i < FILE_COUNT; i++){
		    shmem_address[i] = current_address; 
		    current_address += FILE_SIZE * PAGE_SIZE;
		    pr_info("%ld, ", shmem_address[i]);
	    }
            
	    pr_info("single print addresses %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld", shmem_address[0],
				shmem_address[1],
				shmem_address[2],
				shmem_address[3],
				shmem_address[4],
				shmem_address[5],
				shmem_address[6],
				shmem_address[7],
				shmem_address[8],
				shmem_address[9],
				shmem_address[10],
				shmem_address[11],
				shmem_address[12],
				shmem_address[13],
				shmem_address[14],
				shmem_address[15],
				shmem_address[16],
				shmem_address[17],
				shmem_address[18],
				shmem_address[19]
				);

	    pr_info("\n");

	    pr_info("inode addresses:");
            for(i = 0; i < FILE_COUNT; i++){
                    inode_address[i] = current_address;  //(uintptr_t)alloc_kshmem(alloc_size, DISAGG_KSHMEM_SERV_FS_ID);
		    current_address += PAGE_SIZE;
                    pr_info("%ld, ", inode_address[i]);
            }
            

	    pr_info("single print inode addresses %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld", inode_address[0],
                                inode_address[1],
                                inode_address[2],
                                inode_address[3],
                                inode_address[4],
                                inode_address[5],
                                inode_address[6],
                                inode_address[7],
                                inode_address[8],
                                inode_address[9],
				inode_address[10],
				inode_address[11],
                                inode_address[12],
                                inode_address[13],
                                inode_address[14],
                                inode_address[15],
                                inode_address[16],
                                inode_address[17],
                                inode_address[18],
                                inode_address[19]

                                );


	size_lock_address = current_address;//(uintptr_t)alloc_kshmem(alloc_size, DISAGG_KSHMEM_SERV_FS_ID);
	current_address += PAGE_SIZE;
	inode_lock_address = current_address;//(uintptr_t)alloc_kshmem(alloc_size, DISAGG_KSHMEM_SERV_FS_ID);
	current_address += PAGE_SIZE;
	pr_info("size lock and inode lock %ld %ld", size_lock_address, inode_lock_address);


	pr_info("inode size addresses:");
	for(i = 0; i < FILE_COUNT; i++){
		inode_size_address[i] = current_address;//(uintptr_t)alloc_kshmem(alloc_size, DISAGG_KSHMEM_SERV_FS_ID);
		current_address += PAGE_SIZE;
		pr_info("%ld, ", inode_size_address[i]);
	}




	pr_info("single print inode size addresses %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld", inode_size_address[0],
			inode_size_address[1],
			inode_size_address[2],
			inode_size_address[3],
			inode_size_address[4],
			inode_size_address[5],
			inode_size_address[6],
			inode_size_address[7],
			inode_size_address[8],
			inode_size_address[9],
			inode_size_address[10],
			inode_size_address[11],
			inode_size_address[12],
			inode_size_address[13],
			inode_size_address[14],
			inode_size_address[15],
			inode_size_address[16],
			inode_size_address[17],
			inode_size_address[18],
			inode_size_address[19]
	       );

	pr_info("new inode lock addresses:");
	for(i = 0; i < FILE_COUNT; i++){
		new_inode_lock_address[i] = inode_address[i];
		//new_inode_lock_address[i] = (uintptr_t)alloc_kshmem(alloc_size, DISAGG_KSHMEM_SERV_FS_ID);
		pr_info("%ld, ", new_inode_lock_address[i]);
	}

	pr_info("single print new inode size addresses %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld", 
			new_inode_lock_address[0],
			new_inode_lock_address[1],
			new_inode_lock_address[2],
			new_inode_lock_address[3],
			new_inode_lock_address[4],
			new_inode_lock_address[5],
			new_inode_lock_address[6],
			new_inode_lock_address[7],
			new_inode_lock_address[8],
			new_inode_lock_address[9],
			new_inode_lock_address[10],
			new_inode_lock_address[11],
			new_inode_lock_address[12],
			new_inode_lock_address[13],
			new_inode_lock_address[14],
			new_inode_lock_address[15],
			new_inode_lock_address[16],
			new_inode_lock_address[17],
			new_inode_lock_address[18],
			new_inode_lock_address[19]


	       );





            pr_info("\n");
    }else{

            uintptr_t start_address = combined_address[0]; 
	    uintptr_t current_address = start_address; 
	    for(i = 0; i < FILE_COUNT; i++){
	    	shmem_address[i] = current_address;
	       current_address += FILE_SIZE * PAGE_SIZE;	
	    }

	    for(i = 0; i < FILE_COUNT; i++){
	    	inode_address[i] = current_address;
		current_address += PAGE_SIZE;	

	    }

	    for(i = 0; i < FILE_COUNT; i++){
		inode_size_address[i] = current_address; 
		current_address += PAGE_SIZE;	

	    }
	    size_lock_address = current_address;
	    current_address += PAGE_SIZE;	
	    inode_lock_address = current_address;
	    current_address += PAGE_SIZE;	

	    for(i = 0; i < FILE_COUNT; i++){
		//new_inode_lock_address[i-32] = combined_address[i];
		new_inode_lock_address[i] = inode_address[i];
	    }


	    pr_info("read addresses:");
	    for(i = 0; i < FILE_SIZE; i++){
		    pr_info("%ld, ", shmem_address[i]);
	    }
	    pr_info("\n");

            pr_info("inode addresses:");
            for(i = 0; i < FILE_COUNT; i++){
                    pr_info("%ld, ", inode_address[i]);
            }
            pr_info("\n");


	    pr_info("size lock address %ld, inode lock address %ld", size_lock_address, inode_lock_address);

            pr_info("inode size addresses:");
            for(i = 0; i < FILE_COUNT; i++){
                    pr_info("%ld, ", inode_size_address[i]);
            }

            pr_info("new inode lock addresses:");
            for(i = 0; i < FILE_COUNT; i++){
                    pr_info("%ld, ", new_inode_lock_address[i]);
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

	//set up the rw_sem for the page pointer hash table
	//from rwsem.h
	//init_rwsem(&hash_page_rwsem);
	//init_rwsem(&hash_inode_rwsem);

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
