#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/*
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include "bitmap.h"
#include "simplefs.h"
*/



#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/uio.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include "bitmap.h"
#include <../../include/disagg/cnthread_disagg.h>
#include <../../include/disagg/exec_disagg.h>
#include <../../include/disagg/fault_disagg.h>
#include <../../mm/internal.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/init.h>
#include <linux/threads.h>
#include <linux/mm.h>		/* for struct page */
#include <linux/pagemap.h>
#include <asm/paravirt.h>

//for inode_to_bdi
#include<linux/backing-dev.h>

#include <../../roce_modules/roce_for_disagg/roce_disagg.h>
#include <asm/traps.h>
#include <../include/disagg/kshmem_disagg.h>
#include <linux/swap.h> /* for the mark_page_accessed function*/

#include "simplefs.h"

#include <linux/time.h>



static const struct inode_operations simplefs_inode_ops;
static const struct inode_operations symlink_inode_ops;
extern int iterate_root;
extern int clone_remote_dir;
extern void request_remote_dir(void);

//extern unsigned long shmem_address[20];
//extern unsigned long inode_address[20];
extern unsigned long size_lock_address; 
//extern unsigned long inode_lock_address; 
extern unsigned long new_inode_lock_address[FILE_COUNT];

extern unsigned long inode_size_address[FILE_COUNT];
extern struct super_block * super_block;
extern spinlock_t cnthread_inval_send_ack_lock[DISAGG_NUM_CPU_CORE_IN_COMPUTING_BLADE];


struct rw_semaphore testsem;
struct rw_semaphore testlock;
//DEFINE_SPINLOCK(inode_dummy_page_lock);
//extern spinlock_t dummy_page_lock; 
//DEFINE_SPINLOCK(spin_inode_lock);
//extern struct rw_semaphore remote_inode_locks[10];
//struct rw_semaphore rw_inode_lock;
//DECLARE_RWSEM(rw_inode_lock);

extern unsigned int remote_lock_status[FILE_COUNT];
extern unsigned int inode_size_status[FILE_COUNT]; //0 not held, 1 read mode, 2 write mode



//extern struct rw_semaphore size_locks[10];
//extern spinlock_t * spin_size_lock[20];
extern struct rw_semaphore * size_rwlock[FILE_COUNT];
//extern spinlock_t * spin_inode_lock[10];
extern struct rw_semaphore * inode_rwlock[FILE_COUNT];


//DECLARE_RWSEM(rw_size_lock);

int remote_size_status = 0; //0 not held, 1 read mode, 2 write mode

//this is protected by the testsem
int initialized = 0;
//static spinlock_t cnthread_inval_send_ack_lock[DISAGG_NUM_CPU_CORE_IN_COMPUTING_BLADE];
struct inode *simplefs_iget(struct super_block *sb, unsigned long ino);
int REC_NACK = -1024;

static int mind_fetch_page_write(
        uintptr_t shmem_address, void *page_dma_address, size_t *data_size, bool write) 
{
        struct fault_reply_struct ret_buf;
        struct cache_waiting_node *wait_node = NULL;
        int r;
        unsigned long start_time = jiffies;


	//this might cause double lock acquiring
	//spin_lock(&dummy_page_lock);

        ret_buf.data_size = PAGE_SIZE;
        ret_buf.data = page_dma_address;


        wait_node = add_waiting_node(DISAGG_KERN_TGID, shmem_address, NULL);
        BUG_ON(!wait_node);
	
	//spin_unlock(&dummy_page_lock);

        //mind_pr_cache_dir_state(
        //        "BEFORFE PFAULT ACK/NACK",
        //        start_time, shmem_address,
        //        atomic_read(&wait_node->ack_counter),
        //        atomic_read(&wait_node->target_counter));

        BUG_ON(!is_kshmem_address(shmem_address));
        // NULL struct task_struct* is okay here because
        // if is_kshmem_address(shmem_address) then task_struct is never
        // derefenced.
	if(write){ 
	r = send_pfault_to_mn(NULL, X86_PF_WRITE, shmem_address, 0, &ret_buf);
	}else{
	r = send_pfault_to_mn(NULL, 0, shmem_address, 0, &ret_buf);
	}

        wait_node->ack_buf = ret_buf.ack_buf;


        //pr_pgfault("CN [%d]: start waiting 0x%lx\n", get_cpu(), shmem_address);
        if(r <= 0){
                cancel_waiting_for_nack(wait_node);
		pr_info("RECEIVED NACK");

		//return -1;
	}
	r = wait_ack_from_ctrl(wait_node, NULL, NULL, NULL);

        data_size = ret_buf.data_size;
	if(r){
		//cancel_waiting_for_nack(wait_node);
		return -1;
	}else{
		return 1;
	}
        //mind_pr_cache_dir_state(
        //        "AFTER PFAULT ACK/NACK",
        //        start_time, shmem_address,
        //        atomic_read(&wait_node->ack_counter),
        //        atomic_read(&wait_node->target_counter));
}







static bool get_remote_lock_access(int inode_ino, unsigned long lock_address, bool write){

        uintptr_t inode_pages_address;
        int r;
        struct mm_struct *mm;
        mm = get_init_mm();
        spinlock_t *ptl_ptr = NULL;
        pte_t *temppte;
        void *ptrdummy;
        static struct cnthread_inv_msg_ctx send_ctx;
        loff_t test = 20; 


        inode_pages_address = lock_address;

	int cpu_id = get_cpu();

        //spin_lock(&dummy_page_lock);
	spin_lock(&cnthread_inval_send_ack_lock[cpu_id]);


        size_t data_size;
        void *buf = get_dummy_page_dma_addr(cpu_id);
        r = mind_fetch_page_write(inode_pages_address, buf, &data_size, write);
        //BUG_ON(r);
	if(r <= 0){
		spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);
	        //spin_unlock(&dummy_page_lock);
		//BUG_ON(1);
        	return false;
	}

        temppte = ensure_pte(mm, (uintptr_t)get_dummy_page_buf_addr(cpu_id), &ptl_ptr);

        ptrdummy = get_dummy_page_buf_addr(cpu_id);

        //writes data to that page
        //copy data into dummy buffer, and send to switch
        //simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(get_cpu()), PAGE_SIZE, &test);
        
	//int i;
        //for(i = 0; i < 20; i++){
        //}


        //spin_lock(ptl_ptr);

        //cn_copy_page_data_to_mn(DISAGG_KERN_TGID, mm, inode_pages_address,
        //temppte, CN_OTHER_PAGE, 0, buf);

        //cnthread_send_finish_ack(DISAGG_KERN_TGID, inode_pages_address, &send_ctx, 0);

        // spin_unlock(ptl_ptr);
	spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);
        //spin_unlock(&dummy_page_lock);
        //spin_unlock_irq(&mapping->tree_lock);

        return true;
}




static bool invalidate_size_write(struct inode * inode, int inode_ino, void *inv_argv){
        uintptr_t inode_pages_address;
        int r;
        struct mm_struct *mm;
        mm = get_init_mm();
        spinlock_t *ptl_ptr = NULL;
        pte_t *temppte;
        void *ptrdummy;
        static struct cnthread_inv_msg_ctx send_ctx;
        loff_t test = 20; 
	int i;
        inode_pages_address = inode_size_address[inode_ino];
	
	int cpu_id = get_cpu();

        //spin_lock(&dummy_page_lock);

       	spin_lock(&cnthread_inval_send_ack_lock[cpu_id]);

        size_t data_size;
        void *buf = get_dummy_page_dma_addr(cpu_id);
        //r = mind_fetch_page_write(inode_pages_address, buf, &data_size);
        //BUG_ON(r);

        temppte = ensure_pte(mm, (uintptr_t)get_dummy_page_buf_addr(cpu_id), &ptl_ptr);

        ptrdummy = get_dummy_page_buf_addr(cpu_id);
	if(temppte == NULL){	
		pr_info("WHAT SHOULD WE DO IN THIS CASE?");
	}else{
        	//simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(cpu_id), PAGE_SIZE, &test);
	}
        //writes data to that page
        //copy data into dummy buffer, and send to switch
        //simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(get_cpu()), PAGE_SIZE, &test);


	//can't use global inode lock to sync since it would deadlock

	//already have inode size lock held so it should be synced 
	//naked reads only occur in writes, so there wouldn't be stale reads
	//since we don't have concurrent writes
	((int *)get_dummy_page_buf_addr(cpu_id))[0] = inode->i_size;//NEED to have inode lock for this 
	//can't use i_size_read since it will be an infinite loop

        //for(i = 0; i < 20; i++){
        //}


        //spin_lock(ptl_ptr);

	struct cnthread_rdma_msg_ctx *rdma_ctx = NULL;
        struct cnthread_inv_msg_ctx *inv_ctx = &((struct cnthread_inv_argv *)inv_argv)->inv_ctx;
	
	rdma_ctx = &inv_ctx->rdma_ctx;
	inv_ctx->original_qp = (rdma_ctx->ret & CACHELINE_ROCE_RKEY_QP_MASK) >> CACHELINE_ROCE_RKEY_QP_SHIFT;
       
	create_invalidation_rdma_ack(inv_ctx->inval_buf, rdma_ctx->fva, rdma_ctx->ret, rdma_ctx->qp_val);
        *((u32 *)(&(inv_ctx->inval_buf[CACHELINE_ROCE_VOFFSET_TO_IP]))) = rdma_ctx->ip_val;

	
	u32 req_qp = (get_id_from_requester(inv_ctx->rdma_ctx.requester) * DISAGG_QP_PER_COMPUTE) + inv_ctx->original_qp;
	
	cn_copy_page_data_to_mn(DISAGG_KERN_TGID, mm, inode_pages_address,
        temppte, CN_TARGET_PAGE, req_qp, buf);
	
        _cnthread_send_inval_ack(DISAGG_KERN_TGID, inode_pages_address, inv_ctx->inval_buf);
        
        cnthread_send_finish_ack(DISAGG_KERN_TGID, inode_pages_address, inv_ctx, 1);



	//spin_unlock(ptl_ptr);
	spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);
	//spin_unlock(&dummy_page_lock);
	//spin_unlock_irq(&mapping->tree_lock);
	return true;
}



static bool invalidate_lock_write(int inode_ino, void *inv_argv, unsigned long lock_address){

        uintptr_t inode_pages_address;
        int r;
        struct mm_struct *mm;
        mm = get_init_mm();
        spinlock_t *ptl_ptr = NULL;
        pte_t *temppte;
        void *ptrdummy;
        static struct cnthread_inv_msg_ctx send_ctx;
        loff_t test = 20; 
	int i;
        inode_pages_address = lock_address;
	
	int cpu_id = get_cpu();
        //spin_lock(&dummy_page_lock);

	spin_lock(&cnthread_inval_send_ack_lock[cpu_id]);

        size_t data_size;
        void *buf = get_dummy_page_dma_addr(cpu_id);
        //r = mind_fetch_page_write(inode_pages_address, buf, &data_size);
        //BUG_ON(r);

        temppte = ensure_pte(mm, (uintptr_t)get_dummy_page_buf_addr(cpu_id), &ptl_ptr);

        ptrdummy = get_dummy_page_buf_addr(cpu_id);

        //writes data to that page
        //copy data into dummy buffer, and send to switch
        //simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(get_cpu()), PAGE_SIZE, &test);

	//((char*)get_dummy_page_buf_addr(get_cpu()))[0] = 'h'; //this could be causing issues
	//((char*)get_dummy_page_buf_addr(get_cpu()))[1] = 'i';

        //for(i = 0; i < 20; i++){
        //}


        //spin_lock(ptl_ptr);

	struct cnthread_rdma_msg_ctx *rdma_ctx = NULL;
        struct cnthread_inv_msg_ctx *inv_ctx = &((struct cnthread_inv_argv *)inv_argv)->inv_ctx;
	
	rdma_ctx = &inv_ctx->rdma_ctx;
	inv_ctx->original_qp = (rdma_ctx->ret & CACHELINE_ROCE_RKEY_QP_MASK) >> CACHELINE_ROCE_RKEY_QP_SHIFT;
        create_invalidation_rdma_ack(inv_ctx->inval_buf, rdma_ctx->fva, rdma_ctx->ret, rdma_ctx->qp_val);
        *((u32 *)(&(inv_ctx->inval_buf[CACHELINE_ROCE_VOFFSET_TO_IP]))) = rdma_ctx->ip_val;

	
	u32 req_qp = (get_id_from_requester(inv_ctx->rdma_ctx.requester) * DISAGG_QP_PER_COMPUTE) + inv_ctx->original_qp;
	
	cn_copy_page_data_to_mn(DISAGG_KERN_TGID, mm, inode_pages_address,
        temppte, CN_TARGET_PAGE, req_qp, buf);
	
        _cnthread_send_inval_ack(DISAGG_KERN_TGID, inode_pages_address, inv_ctx->inval_buf);
        
        cnthread_send_finish_ack(DISAGG_KERN_TGID, inode_pages_address, inv_ctx, 1);
	
	//spin_unlock(ptl_ptr);
	spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);
	//spin_unlock(&dummy_page_lock);
	//spin_unlock_irq(&mapping->tree_lock);
	return true;
}




u64 shmem_address_check(void *addr, unsigned long size)
{

/*extern unsigned long shmem_address[10];
extern unsigned long inode_address[10];
extern unsigned long size_lock_address; 
extern unsigned long inode_lock_address; 
*/
	int i;
	/*
	for(i = 0; i < 10; i++){
		if(addr == inode_address[i]){
			return 1;

		}
	}
	*/
	if(addr == file_address){
		pr_info("INVALIDATING FILE");
		return 1;
	}
	for(i = 0; i < FILE_COUNT; i++){
		if(addr == inode_size_address[i]){

			return 1;

		}
	}
	if(addr == size_lock_address){
		return 1;
	}

	for(i = 0; i < FILE_COUNT; i++){
		if(addr == new_inode_lock_address[i]){
			return 1;
		}
	}

	//check to see if this is a page address
	return page_shmem_address_check(addr, size);
}

static bool invalidate_file_write(void *inv_argv){
        uintptr_t inode_pages_address;
        int r;
        struct mm_struct *mm;
        mm = get_init_mm();
        spinlock_t *ptl_ptr = NULL;
        pte_t *temppte;
        void *ptrdummy;
        static struct cnthread_inv_msg_ctx send_ctx;
        loff_t test = 20; 
	int i;
        inode_pages_address = file_address; 
	
	int cpu_id = get_cpu();

        //spin_lock(&dummy_page_lock);

       	spin_lock(&cnthread_inval_send_ack_lock[cpu_id]);

        size_t data_size;
        void *buf = get_dummy_page_dma_addr(cpu_id);
        //r = mind_fetch_page_write(inode_pages_address, buf, &data_size);
        //BUG_ON(r);

        temppte = ensure_pte(mm, (uintptr_t)get_dummy_page_buf_addr(cpu_id), &ptl_ptr);

        ptrdummy = get_dummy_page_buf_addr(cpu_id);
	if(temppte == NULL){	
		pr_info("WHAT SHOULD WE DO IN THIS CASE?");
	}else{
        	//simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(cpu_id), PAGE_SIZE, &test);
	}
	for(i = 0; i < 10; i++){	
		((struct fake_file_dir *)get_dummy_page_buf_addr(cpu_id))[i] = fake_block[i];
		pr_info("writing name %s", ((struct fake_file_dir *)get_dummy_page_buf_addr(cpu_id))[i].name);
	}


        //for(i = 0; i < 20; i++){
        //}


        //spin_lock(ptl_ptr);

	struct cnthread_rdma_msg_ctx *rdma_ctx = NULL;
        struct cnthread_inv_msg_ctx *inv_ctx = &((struct cnthread_inv_argv *)inv_argv)->inv_ctx;
	
	rdma_ctx = &inv_ctx->rdma_ctx;
	inv_ctx->original_qp = (rdma_ctx->ret & CACHELINE_ROCE_RKEY_QP_MASK) >> CACHELINE_ROCE_RKEY_QP_SHIFT;
       
	create_invalidation_rdma_ack(inv_ctx->inval_buf, rdma_ctx->fva, rdma_ctx->ret, rdma_ctx->qp_val);
        *((u32 *)(&(inv_ctx->inval_buf[CACHELINE_ROCE_VOFFSET_TO_IP]))) = rdma_ctx->ip_val;

	
	u32 req_qp = (get_id_from_requester(inv_ctx->rdma_ctx.requester) * DISAGG_QP_PER_COMPUTE) + inv_ctx->original_qp;
	
	cn_copy_page_data_to_mn(DISAGG_KERN_TGID, mm, inode_pages_address,
        temppte, CN_TARGET_PAGE, req_qp, buf);
	
        _cnthread_send_inval_ack(DISAGG_KERN_TGID, inode_pages_address, inv_ctx->inval_buf);
        
        cnthread_send_finish_ack(DISAGG_KERN_TGID, inode_pages_address, inv_ctx, 1);



	//spin_unlock(ptl_ptr);
	spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);
	//spin_unlock(&dummy_page_lock);
	//spin_unlock_irq(&mapping->tree_lock);
	return true;
}







atomic_t count=ATOMIC_INIT(10); 
//int testcount = 0;
u64 testing_invalidate_page_callback(void *addr, void *inv_argv)
{
	
	atomic_inc(&count);
	int cpu_id = get_cpu();
	//pr_info("start inv cpu is %d", cpu_id);
	//testcount++;
	//int temp = testcount;
	//pr_info("start %d", temp);
    int i;
    
    /*
    for(i = 0; i < 10; i++){
	    if(addr == inode_address[i]){
		    return 1;

	    }
    }
	*/
   if(addr == file_address){
	pr_info("INVALIDATING FILE");
	pr_info("INVALIDATING FILE");
	pr_info("INVALIDATING FILE");
	pr_info("INVALIDATING FILE");
	pr_info("INVALIDATING FILE");

	//copy the data from the directory block into shared memory
	//and write that data back
	
	//set this to force revalidate directory entry for root
	test_dentry_revalidate = 1;
	clone_remote_dir = 1;
	//force future directory read to iterate
	iterate_root = 1;

	//write the directory data to the shared memory
	invalidate_file_write(inv_argv);
	return 1;
   }

   for(i = 0; i < FILE_COUNT; i++){
	    if(addr == inode_size_address[i]){
		    //pr_info("size was invalidated");
			//struct timespec time = current_kernel_time();
		
			
			//acquire inode unlocked 	
			//size is synced on size lock
			struct inode * inode = ilookup(super_block, i);
			//while(spin_trylock(&size_lock) == 0){
			//}
			//spin_lock((spin_size_lock[i]));	
			down_write(size_rwlock[i]);
			//down_write(&(size_locks[i]));
			//down_write(&rw_size_lock);

			//time = current_kernel_time();
	
			invalidate_size_write(inode, i, inv_argv);
			inode_size_status[i] = 0;

			//fast path setup
			inode->i_size = -1234;

			//pr_info("invalidated status %d", inode_size_status[i]);
			//up_write(&(size_locks[i]));  
			//spin_unlock((spin_size_lock[i]));	
			up_write(size_rwlock[i]);
			rwsem_wake(size_rwlock[i]);


			//up_write(&rw_size_lock);

			//unlock_inode(inode);	don't need since we don't acquire locked version
			//time = current_kernel_time();

			//inside of invalidate_size_write	
		//	pr_info("end %d", temp);
		//pr_info("end inv cpu is %d", cpu_id);
	
		    return 1;

	    }
   }

    if(addr == size_lock_address){
		//pr_info("end %d", temp);
		//pr_info("end inv cpu is %d", cpu_id);

	    return 1;
    }

    for(i = 0; i < FILE_COUNT; i ++){    
	    if(addr == new_inode_lock_address[i]){
		    //pr_info("inode lock invalidated");
		    //down_write(&(remote_inode_locks[i]));  
		    //spin_lock(spin_inode_lock[i]);
		    down_write(inode_rwlock[i]);
		    //down_write(&rw_inode_lock); 
		    invalidate_lock_write(0, inv_argv, new_inode_lock_address[i]);

		    //downgrade copy (need to separate for invalid and shared)
		    remote_lock_status[i] = 0;
		    //removed to test for deadlock
		    //spin_unlock(spin_inode_lock[i]);
		   	up_write(inode_rwlock[i]); 
		    //up_write(&rw_inode_lock); 

//up_write(&(remote_inode_locks[i]));  
		   	//pr_info("end %d", temp); 
		//pr_info("end inv cpu is %d", cpu_id);

			return 1;
	    }
    }
    //do page sync (in file.c)
    page_testing_invalidate_page_callback(addr, inv_argv);
    //pr_info("end %d", temp);

    		//pr_info("end inv cpu is %d", cpu_id);

    return 1024;
}




/* Get inode ino from disk */
struct inode *simplefs_iget(struct super_block *sb, unsigned long ino)
{
	pr_info("getting inode %d", ino);
    struct inode *inode = NULL;
    struct simplefs_inode *cinode = NULL;
    struct simplefs_inode_info *ci = NULL;
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
    struct buffer_head *bh = NULL;
    uint32_t inode_block = (ino / SIMPLEFS_INODES_PER_BLOCK) + 1;
    uint32_t inode_shift = ino % SIMPLEFS_INODES_PER_BLOCK;
    int ret;

    /* Fail if ino is out of range */
    if (ino >= sbi->nr_inodes){
	    pr_info("inode out of range");
        return ERR_PTR(-EINVAL);
    }

    /* Get a locked inode from Linux */
    inode = iget_locked(sb, ino);
    if (!inode){
	    pr_info("no inode");
        return ERR_PTR(-ENOMEM);
    }

    int test = rwsem_is_locked(&inode->i_rwsem);

    /* If inode is in cache, return it */
    if (!(inode->i_state & I_NEW)){
	    pr_info("inode in cache");
        return inode;
    }

    ci = SIMPLEFS_INODE(inode);
    /* Read inode from disk and initialize */
    bh = sb_bread(sb, inode_block);
    if (!bh) {
	    pr_info("FAILED TO READ FROM DISK");
        ret = -EIO;
        goto failed;
    }
    cinode = (struct simplefs_inode *) bh->b_data;
    cinode += inode_shift;

    inode->i_ino = ino;
    inode->i_sb = sb;
    inode->i_op = &simplefs_inode_ops;

    inode->i_mode = le32_to_cpu(cinode->i_mode);
    i_uid_write(inode, le32_to_cpu(cinode->i_uid));
    i_gid_write(inode, le32_to_cpu(cinode->i_gid));
    inode->i_size = -1234;
    i_size_read(inode);
    inode->i_blocks = inode->i_size / SIMPLEFS_BLOCK_SIZE + 2;

    //inode->i_size = le32_to_cpu(cinode->i_size);
    inode->i_ctime.tv_sec = (time64_t) le32_to_cpu(cinode->i_ctime);
    inode->i_ctime.tv_nsec = 0;
    inode->i_atime.tv_sec = (time64_t) le32_to_cpu(cinode->i_atime);
    inode->i_atime.tv_nsec = 0;
    inode->i_mtime.tv_sec = (time64_t) le32_to_cpu(cinode->i_mtime);
    inode->i_mtime.tv_nsec = 0;
    //inode->i_blocks = le32_to_cpu(cinode->i_blocks);
    set_nlink(inode, le32_to_cpu(cinode->i_nlink));

    if (S_ISDIR(inode->i_mode)) {
        ci->ei_block = le32_to_cpu(cinode->ei_block);
        inode->i_fop = &simplefs_dir_ops;
    } else if (S_ISREG(inode->i_mode)) {
        ci->ei_block = le32_to_cpu(cinode->ei_block);
        inode->i_fop = &simplefs_file_ops;
        inode->i_mapping->a_ops = &simplefs_aops;
    } else if (S_ISLNK(inode->i_mode)) {
        strncpy(ci->i_data, cinode->i_data, sizeof(ci->i_data));
        inode->i_link = ci->i_data;
        inode->i_op = &symlink_inode_ops;
    }

    brelse(bh);

    /* Unlock the inode to make it usable */

    //only for the i_lock not the rwsem lock
    unlock_new_inode(inode);
	pr_info("returning inode");
    return inode;

failed:
    brelse(bh);
    iget_failed(inode);
    pr_info("inode failed");
    return ERR_PTR(ret);
}

/*
 * Look for dentry in dir.
 * Fill dentry with NULL if not in dir, with the corresponding inode if found.
 * Returns NULL on success.
 */
static struct dentry *simplefs_lookup(struct inode *dir,
                                      struct dentry *dentry,
                                      unsigned int flags)
{
    struct super_block *sb = dir->i_sb;
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);

    struct simplefs_inode_info *ci;
    struct simplefs_inode_info *ci_dir = SIMPLEFS_INODE(dir);
    struct inode *inode = NULL;
    struct buffer_head *bh = NULL, *bh2 = NULL;
    struct simplefs_file_ei_block *eblock = NULL;
    struct simplefs_dir_block *dblock = NULL;
    struct simplefs_file *f = NULL;
    int ei, bi, fi;
    uint32_t ino, bno;
    int i;
    int j;

    pr_info("file lookup %s", dentry->d_name.name);
    for(i = 0; i < 10; i++){
	    pr_info("trying fake index %d", i);
	    //this picks the file
	int found = 1;
	for(j = 0; j < 4; j++){
		if(fake_block[i].name[j] != dentry->d_name.name[j]){
			found = 0;
			pr_info("failed on %s", fake_block[i].name);
			break;
		}

	}
	if(!found){
		continue;
	}

	inode = simplefs_iget(sb, fake_block[i].inode_num);
	inode->i_mode = 33188;

	ci = SIMPLEFS_INODE(inode);

	/* Get a free block for this new inode's index */
	bno = get_free_blocks(sbi, 1);
	if (!bno) {
		pr_info("FAILED TO GET FREE BLOCK");
	}

	/* Initialize inode */
#if USER_NS_REQUIRED()
	inode_init_owner(&init_user_ns, inode, dir, 33188);
#else
	inode_init_owner(inode, dir, 33188);
#endif
	//inode->i_blocks = 2;//?
	ci->ei_block = bno;
	//inode->i_size = 0;
	//probably should read the size?
	//pr_info("writing i_size on new inode");	
	//i_size_write(inode, 0);
	inode->i_fop = &simplefs_file_ops;
	inode->i_mapping->a_ops = &simplefs_aops;
	inode->i_size = i_size_read(inode);
	inode->i_blocks = inode->i_size / SIMPLEFS_BLOCK_SIZE + 2;
	pr_info("-------------------");
	pr_info("inode lookup size %d for inode %d", inode->i_size, inode->i_ino);
	pr_info("-------------------");


	set_nlink(inode, 1);

	inode->i_ctime = inode->i_atime = inode->i_mtime = current_time(inode);





	//initialize "new" inode

//	brelse(bh);

	/* Update directory access time */
	dir->i_atime = current_time(dir);
	mark_inode_dirty(dir);

	/* Fill the dentry with the inode */
	d_add(dentry, inode);
	pr_info("file found: %s", fake_block[i].name);
	pr_info("found fake index %d", i);
	pr_info("found fake index %d", i);

	return NULL;

    }






    /* Check filename length */
    if (dentry->d_name.len > SIMPLEFS_FILENAME_LEN)
        return ERR_PTR(-ENAMETOOLONG);

    /* Read the directory block on disk */
    bh = sb_bread(sb, ci_dir->ei_block);
    if (!bh)
        return ERR_PTR(-EIO);
    eblock = (struct simplefs_file_ei_block *) bh->b_data;

    /* Search for the file in directory */
    for (ei = 0; ei < SIMPLEFS_MAX_EXTENTS; ei++) {
        if (!eblock->extents[ei].ee_start)
            break;

        /* Iterate blocks in extent */
        for (bi = 0; bi < eblock->extents[ei].ee_len; bi++) {
            bh2 = sb_bread(sb, eblock->extents[ei].ee_start + bi);
            if (!bh2)
                return ERR_PTR(-EIO);
            dblock = (struct simplefs_dir_block *) bh2->b_data;
            /* Search file in ei_block */
            for (fi = 0; fi < SIMPLEFS_FILES_PER_BLOCK; fi++) {
                f = &dblock->files[fi];
                if (!f->inode) {
                    brelse(bh2);
                    goto search_end;
                }
                if (!strncmp(f->filename, dentry->d_name.name, SIMPLEFS_FILENAME_LEN)) {
                    inode = simplefs_iget(sb, f->inode);
                    brelse(bh2);
                    goto search_end;
                }
            }
            brelse(bh2);
            bh2 = NULL;
        }
    }

search_end:
    brelse(bh);

    /* Update directory access time */
    dir->i_atime = current_time(dir);
    mark_inode_dirty(dir);

    /* Fill the dentry with the inode */
    d_add(dentry, inode);

    return NULL;
}

/* Create a new inode in dir */
static struct inode *simplefs_new_inode(struct inode *dir, mode_t mode)
{
pr_info("new inode being created mode %d", mode);
	iterate_root = 1;

    struct inode *inode;
    struct simplefs_inode_info *ci;
    struct super_block *sb;
    struct simplefs_sb_info *sbi;
    uint32_t ino, bno;
    int ret;

    /* Check mode before doing anything to avoid undoing everything */
    if (!S_ISDIR(mode) && !S_ISREG(mode) && !S_ISLNK(mode)) {
        pr_err(
            "File type not supported (only directory, regular file and symlink "
            "supported)\n");
        return ERR_PTR(-EINVAL);
    }

    /* Check if inodes are available */
    sb = dir->i_sb;
    sbi = SIMPLEFS_SB(sb);
    if (sbi->nr_free_inodes == 0 || sbi->nr_free_blocks == 0)
        return ERR_PTR(-ENOSPC);

    /* Get a new free inode */
    ino = get_free_inode(sbi);
    if (!ino)
        return ERR_PTR(-ENOSPC);

    inode = simplefs_iget(sb, ino);
    if (IS_ERR(inode)) {
        ret = PTR_ERR(inode);
        goto put_ino;
    }

    if (S_ISLNK(mode)) {
#if USER_NS_REQUIRED()
        inode_init_owner(&init_user_ns, inode, dir, mode);
#else
        inode_init_owner(inode, dir, mode);
#endif
        set_nlink(inode, 1);
        inode->i_ctime = inode->i_atime = inode->i_mtime = current_time(inode);
        inode->i_op = &symlink_inode_ops;
        return inode;
    }

    ci = SIMPLEFS_INODE(inode);

    /* Get a free block for this new inode's index */
    bno = get_free_blocks(sbi, 1);
    if (!bno) {
        ret = -ENOSPC;
        goto put_inode;
    }

    /* Initialize inode */
#if USER_NS_REQUIRED()
    inode_init_owner(&init_user_ns, inode, dir, mode);
#else
    inode_init_owner(inode, dir, mode);
#endif
    inode->i_blocks = 1;
    if (S_ISDIR(mode)) {
        ci->ei_block = bno;
        inode->i_size = SIMPLEFS_BLOCK_SIZE;
        inode->i_fop = &simplefs_dir_ops;
        set_nlink(inode, 2); /* . and .. */
    } else if (S_ISREG(mode)) {
        ci->ei_block = bno;
        inode->i_size = 0;
//pr_info("writing i_size on new inode");	
	i_size_write(inode, 0);
        inode->i_fop = &simplefs_file_ops;
        inode->i_mapping->a_ops = &simplefs_aops;
        set_nlink(inode, 1);
    }

    inode->i_ctime = inode->i_atime = inode->i_mtime = current_time(inode);

    return inode;

put_inode:
    iput(inode);
put_ino:
    put_inode(sbi, ino);

    return ERR_PTR(ret);
}

/*
 * Create a file or directory in this way:
 *   - check filename length and if the parent directory is not full
 *   - create the new inode (allocate inode and blocks)
 *   - cleanup index block of the new inode
 *   - add new file/directory in parent index
 */
#if USER_NS_REQUIRED()
static int simplefs_create(struct user_namespace *ns,
                           struct inode *dir,
                           struct dentry *dentry,
                           umode_t mode,
                           bool excl)
#else
static int simplefs_create(struct inode *dir,
                           struct dentry *dentry,
                           umode_t mode,
                           bool excl)
#endif
{
    struct super_block *sb;
    struct inode *inode;
    struct simplefs_inode_info *ci_dir;
    struct simplefs_file_ei_block *eblock;
    struct simplefs_dir_block *dblock;
    char *fblock;
    struct buffer_head *bh, *bh2;
    int ret = 0, alloc = false, bno = 0;
    int ei = 0, bi = 0, fi = 0;
	int x;

	if(clone_remote_dir){
		request_remote_dir();
		clone_remote_dir = 0;
	}


    /* Check filename length */
    if (strlen(dentry->d_name.name) > SIMPLEFS_FILENAME_LEN)
        return -ENAMETOOLONG;

    /* Read parent directory index */
    ci_dir = SIMPLEFS_INODE(dir);
    sb = dir->i_sb;
    bh = sb_bread(sb, ci_dir->ei_block);
    if (!bh)
        return -EIO;

    eblock = (struct simplefs_file_ei_block *) bh->b_data;
    /* Check if parent directory is full */
    if (eblock->nr_files == SIMPLEFS_MAX_SUBFILES) {
        ret = -EMLINK;
        goto end;
    }

    /* Get a new free inode */
    inode = simplefs_new_inode(dir, mode);
    if (IS_ERR(inode)) {
        ret = PTR_ERR(inode);
        goto end;
    }

    /*
     * Scrub ei_block for new file/directory to avoid previous data
     * messing with new file/directory.
     */
    bh2 = sb_bread(sb, SIMPLEFS_INODE(inode)->ei_block);
    if (!bh2) {
        ret = -EIO;
        goto iput;
    }
    fblock = (char *) bh2->b_data;
    memset(fblock, 0, SIMPLEFS_BLOCK_SIZE);
    mark_buffer_dirty(bh2);
    brelse(bh2);

    /* Find first free slot in parent index and register new inode */
    ei = eblock->nr_files / SIMPLEFS_FILES_PER_EXT;
    bi = eblock->nr_files % SIMPLEFS_FILES_PER_EXT
         / SIMPLEFS_FILES_PER_BLOCK;
    fi = eblock->nr_files % SIMPLEFS_FILES_PER_BLOCK;

    if (!eblock->extents[ei].ee_start) {
        bno = get_free_blocks(SIMPLEFS_SB(sb), 8);
        if (!bno) {
            ret = -ENOSPC;
            goto iput;
        }
        eblock->extents[ei].ee_start = bno;
        eblock->extents[ei].ee_len = 8;
        eblock->extents[ei].ee_block =
            ei ? eblock->extents[ei - 1].ee_block +
                     eblock->extents[ei - 1].ee_len
               : 0;
        alloc = true;
    }
    bh2 = sb_bread(sb, eblock->extents[ei].ee_start + bi);
    if (!bh2) {
        ret = -EIO;
        goto put_block;
    }
    dblock = (struct simplefs_dir_block *) bh2->b_data;

    dblock->files[fi].inode = inode->i_ino;
    strncpy(dblock->files[fi].filename, dentry->d_name.name,
            SIMPLEFS_FILENAME_LEN);

    eblock->nr_files++;
    mark_buffer_dirty(bh2);
    mark_buffer_dirty(bh);
    brelse(bh2);
    brelse(bh);

    /* Update stats and mark dir and new inode dirty */
    mark_inode_dirty(inode);
    dir->i_mtime = dir->i_atime = dir->i_ctime = current_time(dir);
    if (S_ISDIR(mode))
        inc_nlink(dir);
    mark_inode_dirty(dir);

    /* setup dentry */
    d_instantiate(dentry, inode);

    //write data to the fake block 
    //this is what is used in lookup
    fake_block[inode->i_ino].inode_num = inode->i_ino;
    for(x = 0; x < 10; x++){
	if(dentry->d_name.name[x] == '\0'){
		break;
	}
	fake_block[inode->i_ino].name[x] = dentry->d_name.name[x];
    } 
    pr_info("ADDED NEW FILE TO THE FAKE BLOCK %d %s", inode->i_ino, dentry->d_name.name);



    return 0;

put_block:
    if (alloc && eblock->extents[ei].ee_start) {
        put_blocks(SIMPLEFS_SB(sb), eblock->extents[ei].ee_start,
                   eblock->extents[ei].ee_len);
        memset(&eblock->extents[ei], 0, sizeof(struct simplefs_extent));
    }
iput:
    put_blocks(SIMPLEFS_SB(sb), SIMPLEFS_INODE(inode)->ei_block, 1);
    put_inode(SIMPLEFS_SB(sb), inode->i_ino);
    iput(inode);
end:
    brelse(bh);
    return ret;
}

static int simplefs_remove_from_dir(struct inode *dir, struct dentry *dentry)
{
    struct super_block *sb = dir->i_sb;
    struct inode *inode = d_inode(dentry);
    struct buffer_head *bh = NULL, *bh2 = NULL, *bh_prev = NULL;
    struct simplefs_file_ei_block *eblock = NULL;
    struct simplefs_dir_block *dblock = NULL, *dblock_prev = NULL;
    int ei = 0, bi = 0, fi = 0;
    int ret = 0, found = false;

    /* Read parent directory index */
    bh = sb_bread(sb, SIMPLEFS_INODE(dir)->ei_block);
    if (!bh)
        return -EIO;
    eblock = (struct simplefs_file_ei_block *) bh->b_data;
    for (ei = 0; ei < SIMPLEFS_MAX_EXTENTS; ei++) {
        if (!eblock->extents[ei].ee_start)
            break;

        for (bi = 0; bi < eblock->extents[ei].ee_len; bi++) {
            bh2 = sb_bread(sb, eblock->extents[ei].ee_start + bi);
            if (!bh2) {
                ret = -EIO;
                goto release_bh;
            }
            dblock = (struct simplefs_dir_block *) bh2->b_data;
            if (!dblock->files[0].inode)
                break;

            if (found) {
                memmove(dblock_prev->files + SIMPLEFS_FILES_PER_BLOCK - 1,
                        dblock->files, sizeof(struct simplefs_file));
                brelse(bh_prev);

                memmove(dblock->files, dblock->files + 1,
                        (SIMPLEFS_FILES_PER_BLOCK - 1) * sizeof(struct simplefs_file));
                memset(dblock->files + SIMPLEFS_FILES_PER_BLOCK - 1,
                       0, sizeof(struct simplefs_file));
                mark_buffer_dirty(bh2);

                bh_prev = bh2;
                dblock_prev = dblock;
                continue;
            }
            /* Remove file from parent directory */
            for (fi = 0; fi < SIMPLEFS_FILES_PER_BLOCK; fi++) {
                if (dblock->files[fi].inode == inode->i_ino) {
                    found = true;
                    if (fi != SIMPLEFS_FILES_PER_BLOCK - 1) {
                        memmove(dblock->files + fi, dblock->files + fi + 1,
                                (SIMPLEFS_FILES_PER_BLOCK - fi - 1) * sizeof(struct simplefs_file));
                    }
                    memset(dblock->files + SIMPLEFS_FILES_PER_BLOCK - 1,
                           0, sizeof(struct simplefs_file));
                    mark_buffer_dirty(bh2);
                    bh_prev = bh2;
                    dblock_prev = dblock;
                    break;
                }
            }
            if (!found)
                brelse(bh2);
        }
    }
    if (found) {
        if (bh_prev) {
            brelse(bh_prev);
        }
        eblock->nr_files--;
        mark_buffer_dirty(bh);
    }
release_bh:
    brelse(bh);
    return ret;
}
/*
 * Remove a link for a file including the reference in the parent directory.
 * If link count is 0, destroy file in this way:
 *   - remove the file from its parent directory.
 *   - cleanup blocks containing data
 *   - cleanup file index block
 *   - cleanup inode
 */
static int simplefs_unlink(struct inode *dir, struct dentry *dentry)
{
    struct super_block *sb = dir->i_sb;
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
    struct inode *inode = d_inode(dentry);
    struct buffer_head *bh = NULL, *bh2 = NULL;
    struct simplefs_file_ei_block *file_block = NULL;
    int ei = 0, bi = 0;
    int ret = 0;

    uint32_t ino = inode->i_ino;
    uint32_t bno = 0;

    ret = simplefs_remove_from_dir(dir, dentry);
    if (ret != 0)
        return ret;

    if (S_ISLNK(inode->i_mode))
        goto clean_inode;

    /* Update inode stats */
    dir->i_mtime = dir->i_atime = dir->i_ctime = current_time(dir);
    if (S_ISDIR(inode->i_mode)) {
        drop_nlink(dir);
        drop_nlink(inode);
    }
    mark_inode_dirty(dir);

    if (inode->i_nlink > 1) {
        inode_dec_link_count(inode);
        return ret;
    }

    /*
     * Cleanup pointed blocks if unlinking a file. If we fail to read the
     * index block, cleanup inode anyway and lose this file's blocks
     * forever. If we fail to scrub a data block, don't fail (too late
     * anyway), just put the block and continue.
     */
    bno = SIMPLEFS_INODE(inode)->ei_block;
    bh = sb_bread(sb, bno);
    if (!bh)
        goto clean_inode;
    file_block = (struct simplefs_file_ei_block *) bh->b_data;
    if (S_ISDIR(inode->i_mode))
        goto scrub;
    for (ei = 0; ei < SIMPLEFS_MAX_EXTENTS; ei++) {
        char *block;

        if (!file_block->extents[ei].ee_start)
            break;

        put_blocks(sbi, file_block->extents[ei].ee_start,
                   file_block->extents[ei].ee_len);

        /* Scrub the extent */
        for (bi = 0; bi < file_block->extents[ei].ee_len; bi++) {
            bh2 = sb_bread(sb, file_block->extents[ei].ee_start + bi);
            if (!bh2)
                continue;
            block = (char *) bh2->b_data;
            memset(block, 0, SIMPLEFS_BLOCK_SIZE);
            mark_buffer_dirty(bh2);
            brelse(bh2);
        }
    }

scrub:
    /* Scrub index block */
    memset(file_block, 0, SIMPLEFS_BLOCK_SIZE);
    mark_buffer_dirty(bh);
    brelse(bh);

clean_inode:
    /* Cleanup inode and mark dirty */
    inode->i_blocks = 0;
    SIMPLEFS_INODE(inode)->ei_block = 0;
    inode->i_size = 0;
    i_uid_write(inode, 0);
    i_gid_write(inode, 0);
    inode->i_mode = 0;
    inode->i_ctime.tv_sec = inode->i_mtime.tv_sec = inode->i_atime.tv_sec = 0;
    drop_nlink(inode);
    mark_inode_dirty(inode);

    /* Free inode and index block from bitmap */
    put_blocks(sbi, bno, 1);
    put_inode(sbi, ino);

    return ret;
}

#if USER_NS_REQUIRED()
static int simplefs_rename(struct user_namespace *ns,
                           struct inode *old_dir,
                           struct dentry *old_dentry,
                           struct inode *new_dir,
                           struct dentry *new_dentry,
                           unsigned int flags)
#else
static int simplefs_rename(struct inode *old_dir,
                           struct dentry *old_dentry,
                           struct inode *new_dir,
                           struct dentry *new_dentry,
                           unsigned int flags)
#endif
{
    struct super_block *sb = old_dir->i_sb;
    struct simplefs_inode_info *ci_new = SIMPLEFS_INODE(new_dir);
    struct inode *src = d_inode(old_dentry);
    struct buffer_head *bh_new = NULL, *bh2 = NULL;
    struct simplefs_file_ei_block *eblock_new = NULL;
    struct simplefs_dir_block *dblock = NULL;
    int new_pos = -1, ret = 0;
    int ei = 0 , bi = 0, fi = 0, bno = 0;

    /* fail with these unsupported flags */
    if (flags & (RENAME_EXCHANGE | RENAME_WHITEOUT))
        return -EINVAL;

    /* Check if filename is not too long */
    if (strlen(new_dentry->d_name.name) > SIMPLEFS_FILENAME_LEN)
        return -ENAMETOOLONG;

    /* Fail if new_dentry exists or if new_dir is full */
    bh_new = sb_bread(sb, ci_new->ei_block);
    if (!bh_new)
        return -EIO;

    eblock_new = (struct simplefs_file_ei_block *) bh_new->b_data;
    for (ei = 0; new_pos < 0 && ei < SIMPLEFS_MAX_EXTENTS; ei++) {
        if (!eblock_new->extents[ei].ee_start)
            break;

        for (bi = 0; new_pos < 0 && bi < eblock_new->extents[ei].ee_len; bi++) {
            bh2 = sb_bread(sb, eblock_new->extents[ei].ee_start + bi);
            if (!bh2) {
                ret = -EIO;
                goto release_new;
            }

            dblock = (struct simplefs_dir_block *) bh2->b_data;
            for (fi = 0; fi < SIMPLEFS_FILES_PER_BLOCK; fi++) {
                if (new_dir == old_dir) {
                    if (!strncmp(dblock->files[fi].filename, old_dentry->d_name.name,
                                SIMPLEFS_FILENAME_LEN)) {
                        strncpy(dblock->files[fi].filename, new_dentry->d_name.name,
                                SIMPLEFS_FILENAME_LEN);
                        mark_buffer_dirty(bh2);
                        brelse(bh2);
                        goto release_new;
                    }
                }
                if (!strncmp(dblock->files[fi].filename, new_dentry->d_name.name,
                            SIMPLEFS_FILENAME_LEN)) {
                    brelse(bh2);
                    ret = -EEXIST;
                    goto release_new;
                }
                if (new_pos < 0 && !dblock->files[fi].inode) {
                    new_pos = fi;
                    break;
                }
            }
            if (new_pos < 0)
                brelse(bh2);
        }
    }

    /* If new directory is full, fail */
    if (new_pos < 0 && eblock_new->nr_files == SIMPLEFS_FILES_PER_EXT) {
        ret = -EMLINK;
        goto release_new;
    }

    /* insert in new parent directory */
    /* Get new freeblocks for extent if needed*/
    if (new_pos < 0) {
        bno = get_free_blocks(SIMPLEFS_SB(sb), 8);
        if (!bno) {
            ret = -ENOSPC;
            goto release_new;
        }
        eblock_new->extents[ei].ee_start = bno;
        eblock_new->extents[ei].ee_len = 8;
        eblock_new->extents[ei].ee_block =
            ei ? eblock_new->extents[ei - 1].ee_block +
                     eblock_new->extents[ei - 1].ee_len
               : 0;
        bh2 = sb_bread(sb, eblock_new->extents[ei].ee_start + 0);
        if (!bh2) {
            ret = -EIO;
            goto put_block;
        }
        dblock = (struct simplefs_dir_block *) bh2->b_data;
        mark_buffer_dirty(bh_new);
        new_pos = 0;
    }
    dblock->files[new_pos].inode = src->i_ino;
    strncpy(dblock->files[new_pos].filename, new_dentry->d_name.name,
            SIMPLEFS_FILENAME_LEN);
    mark_buffer_dirty(bh2);
    brelse(bh2);

    /* Update new parent inode metadata */
    new_dir->i_atime = new_dir->i_ctime = new_dir->i_mtime =
        current_time(new_dir);
    if (S_ISDIR(src->i_mode))
        inc_nlink(new_dir);
    mark_inode_dirty(new_dir);

    /* remove target from old parent directory */
    ret = simplefs_remove_from_dir(old_dir, old_dentry);
    if (ret != 0)
        goto release_new;

    /* Update old parent inode metadata */
    old_dir->i_atime = old_dir->i_ctime = old_dir->i_mtime =
        current_time(old_dir);
    if (S_ISDIR(src->i_mode))
        drop_nlink(old_dir);
    mark_inode_dirty(old_dir);

    return ret;

put_block:
    if (eblock_new->extents[ei].ee_start) {
        put_blocks(SIMPLEFS_SB(sb), eblock_new->extents[ei].ee_start,
                   eblock_new->extents[ei].ee_len);
        memset(&eblock_new->extents[ei], 0, sizeof(struct simplefs_extent));
    }
release_new:
    brelse(bh_new);
    return ret;
}

#if USER_NS_REQUIRED()
static int simplefs_mkdir(struct user_namespace *ns,
                          struct inode *dir,
                          struct dentry *dentry,
                          umode_t mode)
{
    return simplefs_create(ns, dir, dentry, mode | S_IFDIR, 0);
}
#else
static int simplefs_mkdir(struct inode *dir,
                          struct dentry *dentry,
                          umode_t mode)
{
    return simplefs_create(dir, dentry, mode | S_IFDIR, 0);
}
#endif

static int simplefs_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct super_block *sb = dir->i_sb;
    struct inode *inode = d_inode(dentry);
    struct buffer_head *bh;
    struct simplefs_file_ei_block *eblock;

    /* If the directory is not empty, fail */
    if (inode->i_nlink > 2)
        return -ENOTEMPTY;
    bh = sb_bread(sb, SIMPLEFS_INODE(inode)->ei_block);
    if (!bh)
        return -EIO;
    eblock = (struct simplefs_file_ei_block *) bh->b_data;
    if (eblock->nr_files != 0) {
        brelse(bh);
        return -ENOTEMPTY;
    }
    brelse(bh);

    /* Remove directory with unlink */
    return simplefs_unlink(dir, dentry);
}

static int simplefs_link(struct dentry *old_dentry,
                         struct inode *dir,
                         struct dentry *dentry)
{
    struct inode *inode = d_inode(old_dentry);
    struct super_block *sb = inode->i_sb;
    struct simplefs_inode_info *ci_dir = SIMPLEFS_INODE(dir);
    struct simplefs_file_ei_block *eblock = NULL;
    struct simplefs_dir_block *dblock;
    struct buffer_head *bh = NULL, *bh2 = NULL;
    int ret = 0, alloc = false, bno = 0;
    int ei = 0, bi = 0, fi = 0;

    bh = sb_bread(sb, ci_dir->ei_block);
    if (!bh)
        return -EIO;
    eblock = (struct simplefs_file_ei_block *) bh->b_data;

    if (eblock->nr_files == SIMPLEFS_MAX_SUBFILES) {
        ret = -EMLINK;
        printk(KERN_INFO "directory is full");
        goto end;
    }

    ei = eblock->nr_files / SIMPLEFS_FILES_PER_EXT;
    bi = eblock->nr_files % SIMPLEFS_FILES_PER_EXT
         / SIMPLEFS_FILES_PER_BLOCK;
    fi = eblock->nr_files % SIMPLEFS_FILES_PER_BLOCK;

    if (eblock->extents[ei].ee_start == 0) {
        bno = get_free_blocks(SIMPLEFS_SB(sb), 8);
        if (!bno) {
            ret = -ENOSPC;
            goto end;
        }
        eblock->extents[ei].ee_start = bno;
        eblock->extents[ei].ee_len = 8;
        eblock->extents[ei].ee_block =
            ei ? eblock->extents[ei - 1].ee_block +
                     eblock->extents[ei - 1].ee_len
               : 0;
        alloc = true;
    }
    bh2 = sb_bread(sb, eblock->extents[ei].ee_start + bi);
    if (!bh2) {
        ret = -EIO;
        goto put_block;
    }
    dblock = (struct simplefs_dir_block *) bh2->b_data;

    dblock->files[fi].inode = inode->i_ino;
    strncpy(dblock->files[fi].filename, dentry->d_name.name,
            SIMPLEFS_FILENAME_LEN);

    eblock->nr_files++;
    mark_buffer_dirty(bh2);
    mark_buffer_dirty(bh);
    brelse(bh2);
    brelse(bh);

    inode_inc_link_count(inode);
    d_instantiate(dentry, inode);
    return ret;

put_block:
    if (alloc && eblock->extents[ei].ee_start) {
        put_blocks(SIMPLEFS_SB(sb), eblock->extents[ei].ee_start,
                   eblock->extents[ei].ee_len);
        memset(&eblock->extents[ei], 0, sizeof(struct simplefs_extent));
    }
end:
    brelse(bh);
    return ret;
}

#if USER_NS_REQUIRED()
static int simplefs_symlink(struct user_namespace *ns,
                            struct inode *dir,
                            struct dentry *dentry,
                            const char *symname)
#else
static int simplefs_symlink(struct inode *dir,
                            struct dentry *dentry,
                            const char *symname)
#endif
{
    struct super_block *sb = dir->i_sb;
    unsigned int l = strlen(symname) + 1;
    struct inode *inode = simplefs_new_inode(dir, S_IFLNK | S_IRWXUGO);
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    struct simplefs_inode_info *ci_dir = SIMPLEFS_INODE(dir);
    struct simplefs_file_ei_block *eblock = NULL;
    struct simplefs_dir_block *dblock = NULL;
    struct buffer_head *bh = NULL, *bh2 = NULL;
    int ret= 0, alloc = false, bno = 0;
    int ei = 0, bi = 0, fi = 0;

    /* Check if symlink content is not too long */
    if (l > sizeof(ci->i_data))
        return -ENAMETOOLONG;

    /* fill directory data block */
    bh = sb_bread(sb, ci_dir->ei_block);
    if (!bh)
        return -EIO;
    eblock = (struct simplefs_file_ei_block *) bh->b_data;

    if (eblock->nr_files == SIMPLEFS_MAX_SUBFILES) {
        ret = -EMLINK;
        printk(KERN_INFO "directory is full");
        goto end;
    }

    ei = eblock->nr_files / SIMPLEFS_FILES_PER_EXT;
    bi = eblock->nr_files % SIMPLEFS_FILES_PER_EXT
         / SIMPLEFS_FILES_PER_BLOCK;
    fi = eblock->nr_files % SIMPLEFS_FILES_PER_BLOCK;

    if (eblock->extents[ei].ee_start == 0) {
        bno = get_free_blocks(SIMPLEFS_SB(sb), 8);
        if (!bno) {
            ret = -ENOSPC;
            goto end;
        }
        eblock->extents[ei].ee_start = bno;
        eblock->extents[ei].ee_len = 8;
        eblock->extents[ei].ee_block =
            ei ? eblock->extents[ei - 1].ee_block +
                     eblock->extents[ei - 1].ee_len
               : 0;
        alloc = true;
    }
    bh2 = sb_bread(sb, eblock->extents[ei].ee_start + bi);
    if (!bh2) {
        ret = -EIO;
        goto put_block;
    }
    dblock = (struct simplefs_dir_block *) bh2->b_data;

    dblock->files[fi].inode = inode->i_ino;
    strncpy(dblock->files[fi].filename, dentry->d_name.name,
            SIMPLEFS_FILENAME_LEN);

    eblock->nr_files++;
    mark_buffer_dirty(bh2);
    mark_buffer_dirty(bh);
    brelse(bh2);
    brelse(bh);

    inode->i_link = (char *) ci->i_data;
    memcpy(inode->i_link, symname, l);
    inode->i_size = l - 1;
    mark_inode_dirty(inode);
    d_instantiate(dentry, inode);
    return 0;

put_block:
    if (alloc && eblock->extents[ei].ee_start) {
        put_blocks(SIMPLEFS_SB(sb), eblock->extents[ei].ee_start,
                   eblock->extents[ei].ee_len);
        memset(&eblock->extents[ei], 0, sizeof(struct simplefs_extent));
    }

end:
    brelse(bh);
    return ret;
}

static const char *simplefs_get_link(struct dentry *dentry,
                                     struct inode *inode,
                                     struct delayed_call *done)
{
    return inode->i_link;
}
int test_inode_lock_simple(void){
	return 0;
}


void lock_loop(int ino, bool write){
	//return;
	if(write){
		//pr_info("acquiring %d in write", ino);
	}
	while(1){

		//down_write(&testsem);
		//down_write(&(remote_inode_locks[ino]));  
		down_write(inode_rwlock[ino]);
		//spin_lock(spin_inode_lock[ino]);
		//down_write(&rw_inode_lock);	
		if((write && remote_lock_status[ino] == 2) || (!write && remote_lock_status[ino] >= 1)){
			//pr_info("already had lock access");
			return;
		}else{
			//pr_info("didn't have lock access");

			bool acquired = get_remote_lock_access(0, new_inode_lock_address[ino], write);
			if(!acquired){
				//up_write(&(remote_inode_locks[ino]));
				up_write(inode_rwlock[ino]);
				//usleep_range(1000,2000);
				//spin_unlock(spin_inode_lock[ino]);
				//up_write(&rw_inode_lock);	
				//BUG_ON(1);
				msleep(1);	
				continue; //force retry
			}
			if(write){
				remote_lock_status[ino] = 2; //write
			}else{
				remote_lock_status[ino] = 1; //read

			}
			return;
		}

		//try to acquire remote lock
		//	check to see if we have access to it already in the hashtable
		//	if we don't, then attempt to grab it
		//if failed release lock and goto start
		//if success then return from this function
	}

}

void simple_dfs_inode_lock(struct inode *inode){
	down_write(&inode->i_rwsem);
	//loop to retry remote access
	lock_loop(inode->i_ino, true);
}

void simple_dfs_inode_unlock(struct inode *inode){
	int i = 0;
	//release remote lock
	//up_write(&(remote_inode_locks[inode->i_ino]));  
	up_write(inode_rwlock[inode->i_ino]);	
	//spin_unlock(spin_inode_lock[inode->i_ino]);	
	//up_write(&rw_inode_lock);	
	up_write(&inode->i_rwsem);
	//up_write(&testsem);
}

void simple_dfs_inode_lock_shared(struct inode *inode){
	pr_info("shared lock");	
	pr_info("shared lock");	
	pr_info("shared lock");	
	pr_info("shared lock");	
	pr_info("shared lock");	
	pr_info("shared lock");	

	down_write(&inode->i_rwsem);
	lock_loop(inode->i_ino, true);
	//down_read(&inode->i_rwsem);
}

void simple_dfs_inode_unlock_shared(struct inode *inode){
	int i = 0;	
	up_write(inode_rwlock[inode->i_ino]);
	//spin_unlock(spin_inode_lock[inode->i_ino]);
	//up_write(&rw_inode_lock);	
	//up_write(&(remote_inode_locks[inode->i_ino]));  
	up_write(&inode->i_rwsem);

}
int simple_dfs_inode_trylock(struct inode *inode){
	
	int acquired = down_write_trylock(&inode->i_rwsem);
	if(!acquired){
		return acquired;//return down_write_trylock(&testsem);
	}
	lock_loop(inode->i_ino, true);


}
int simple_dfs_inode_trylock_shared(struct inode *inode){

	pr_info("shared lock");	
	pr_info("shared lock");	
	pr_info("shared lock");	
	pr_info("shared lock");	
	pr_info("shared lock");	
	pr_info("shared lock");	


	int acquired = down_write_trylock(&inode->i_rwsem);
	if(!acquired){
		return acquired;//return down_write_trylock(&testsem);
	}
	lock_loop(inode->i_ino, true);

}

int simple_dfs_inode_is_locked(struct inode *inode){

	return rwsem_is_locked(&inode->i_rwsem);
	//return rwsem_is_locked(&testsem);

}

void simple_dfs_inode_lock_nested(struct inode *inode, unsigned subclass){

	down_write_nested(&inode->i_rwsem, subclass);
	lock_loop(inode->i_ino, true);

}


static int get_remote_size_access(int inode_ino, bool write){

	pr_info("get remote size access");
        uintptr_t inode_pages_address;
        int r;
        struct mm_struct *mm;
        mm = get_init_mm();
        spinlock_t *ptl_ptr = NULL;
        pte_t *temppte;
        void *ptrdummy;
        static struct cnthread_inv_msg_ctx send_ctx;
        loff_t test = 20; 


        inode_pages_address = inode_size_address[inode_ino];

	int cpu_id = get_cpu();

        //spin_lock(&dummy_page_lock);

	spin_lock(&cnthread_inval_send_ack_lock[cpu_id]);


        size_t data_size;
        void *buf = get_dummy_page_dma_addr(cpu_id);
        r = mind_fetch_page_write(inode_pages_address, buf, &data_size, write);
        //BUG_ON(r);
	if(r <= 0){
		spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);
		//spin_unlock(&dummy_page_lock);
		//BUG_ON(1);

        	return -1;
	}

        temppte = ensure_pte(mm, (uintptr_t)get_dummy_page_buf_addr(cpu_id), &ptl_ptr);

        ptrdummy = get_dummy_page_buf_addr(cpu_id);



       	int result = ((int *)get_dummy_page_buf_addr(cpu_id))[0];

        //writes data to that page
        //copy data into dummy buffer, and send to switch
        //simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(get_cpu()), PAGE_SIZE, &test);

	//int i;
        //for(i = 0; i < 20; i++){
        //}


        //spin_lock(ptl_ptr);

        //cn_copy_page_data_to_mn(DISAGG_KERN_TGID, mm, inode_pages_address,
        //temppte, CN_OTHER_PAGE, 0, buf);

        //cnthread_send_finish_ack(DISAGG_KERN_TGID, inode_pages_address, &send_ctx, 0);

        // spin_unlock(ptl_ptr);
	spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);
        //spin_unlock(&dummy_page_lock);
        //spin_unlock_irq(&mapping->tree_lock);

        return result;
}



//returns -1 if we already have the status
//loops until access is gained
//will return new size when accessed
int size_loop(int ino, bool write){
	//return -1; //testing removing this

	pr_info("requesting i size for inode %d", ino);
	//first try to see if we can get away with not acquring lock in write mode
	down_read(size_rwlock[ino]);
	if((write && inode_size_status[ino] == 2) || (!write && inode_size_status[ino] >= 1)){
	pr_info("already had it");

		return -2;
	}
	up_read(size_rwlock[ino]);
	rwsem_wake(size_rwlock[ino]);
	
	//if that failed then try to fetch it 

	while(1){

		//down_write(&testsem);
		//while(spin_trylock(&size_lock) == 0){
		//}
		//down_write(&(size_locks[ino]));	
		//spin_lock((spin_size_lock[ino]));	
		down_write(size_rwlock[ino]);

		//down_write(&rw_size_lock);

		if((write && inode_size_status[ino] == 2) || (!write && inode_size_status[ino] >= 1)){
	pr_info("someone else got it");

			return -1;
		}else{

			int result = get_remote_size_access(ino, write);
			if(result == -1){
				//up_write(&(size_locks[ino]));
				//spin_unlock((spin_size_lock[ino]));	
				up_write(size_rwlock[ino]);

				//up_write(&rw_size_lock);

				//BUG_ON(1);
				//return -1; //force retry
				continue;
			}
			if(write){
				inode_size_status[ino] = 2; //write
			}else{
				inode_size_status[ino] = 1; //read

			}
	pr_info("finished request");


			return result;
		}

		//try to acquire remote lock
		//	check to see if we have access to it already in the hashtable
		//	if we don't, then attempt to grab it
		//if failed release lock and goto start
		//if success then return from this function
	}

}



int  test_counter = 0;

loff_t simple_i_size_read(const struct inode *inode){
	pr_info("requesting i_size_read inode %d", inode->i_ino);

	int tempsize = inode->i_size;
	if(tempsize != -1234){
		return tempsize;
	}
	if(inode->i_ino != 0){
		pr_info("requesting i_size_read");
		pr_info("requesting i_size_read");
		pr_info("requesting i_size_read");
		pr_info("requesting i_size_read");
		pr_info("requesting i_size_read");
		pr_info("requesting i_size_read");

		int size = -1;
		//spin_lock(&size_lock);


		size = size_loop(inode->i_ino, false);	
		//lock acquired in size loop

		if(size == -2){
			//we already had access
			loff_t temp = inode->i_size;
			//up_write(&(size_locks[inode->i_ino]));  
			//spin_unlock((spin_size_lock[inode->i_ino]));	
			up_read(size_rwlock[inode->i_ino]);
			rwsem_wake(size_rwlock[inode->i_ino]);
			return temp;
		}else if(size == -1){
			//this means gained access from another thread 
			loff_t temp = inode->i_size;
			//up_write(&(size_locks[inode->i_ino]));  
			//spin_unlock((spin_size_lock[inode->i_ino]));	
			up_write(size_rwlock[inode->i_ino]);
			rwsem_wake(size_rwlock[inode->i_ino]);

			//up_write(&rw_size_lock);
			return temp; 
		}else{
			//have to remove const here
			struct inode * non_const_inode = (struct inode *)inode;

			loff_t temp = inode->i_size;
			non_const_inode->i_size = size;
			temp = non_const_inode->i_size;
			//up_write(&(size_locks[inode->i_ino]));  
			//spin_unlock((spin_size_lock[inode->i_ino]));	
			up_write(size_rwlock[inode->i_ino]);
			rwsem_wake(size_rwlock[inode->i_ino]);

			//up_write(&rw_size_lock);

			return temp; 

		}
	}else{
		return inode->i_size;
	}



	//acquire lock in read mode
	//
	//
	//maybe we could put it somewhere else?
	//probably have to put it elsewhere due to const getting
	//in the way
	//down_read(inode->i_size_rwsem); //NOTE THIS HAS TO BE INITIALIZED in inode_init_always(?)
	//also has to be a pointer to get around the const stuff

	//rwsem has to be separate from the inode due to the const stuff making things break?
	//down_read(&testsem);
	//check to see if we have remote access
	//	cases are either we do, don't, or someone else started the waiting process
	//	either:
	//	request access
	//	wait for current request to finish
	//	already have it, proceed to read
	//	release locks before returning
	//up_read(inode->i_size_rwsem); //NOTE THIS HAS TO BE INITIALIZED in inode_init_always(?)

	//up_read(&testsem);

}

void simple_i_size_write(struct inode *inode, loff_t i_size){

	if(inode->i_ino != 0){
		//spin_lock(&size_lock);
		int size = -1;
		size = size_loop(inode->i_ino, true);	
		//lock acquired in size loop
	
		if(size == -2){
			//we already had access
			inode->i_size = i_size;
			//up_write(&(size_locks[inode->i_ino]));  
			//spin_unlock((spin_size_lock[inode->i_ino]));	
			up_read(size_rwlock[inode->i_ino]);
			rwsem_wake(size_rwlock[inode->i_ino]);

			return;
		}else if(size == -1){
			//this means that we gained access from another thread 
			inode->i_size = i_size;
			//up_write(&(size_locks[inode->i_ino]));  
			//spin_unlock((spin_size_lock[inode->i_ino]));	
			up_write(size_rwlock[inode->i_ino]);
			rwsem_wake(size_rwlock[inode->i_ino]);

			//up_write(&rw_size_lock);

			return; 
		}else{
			inode->i_size = i_size;
			//up_write(&(size_locks[inode->i_ino]));  
			//spin_unlock((spin_size_lock[inode->i_ino]));	
			up_write(size_rwlock[inode->i_ino]);
			rwsem_wake(size_rwlock[inode->i_ino]);


			//up_write(&rw_size_lock);

			return; 

		}
	}else{
		inode->i_size = i_size;

	}



	//down_write(inode->i_size_rwsem); //note this has to be initialized in inode_init_always(?)
	//down_write(&testsem);
	//acquire lock in write mode (blocking local access)
	//acquire remote access in write mode
	//update size locally then remotely
	//inode_sizes[inode->i_ino] = i_size;
	//release locks before returning
	//up_write(inode->i_size_rwsem); //note this has to be initialized in inode_init_always(?)

//	up_write(&testsem);
}

int simple_inode_down_read_killable(struct inode * inode){
		int result = down_write_killable(&inode->i_rwsem);
	if(result == 0){ //0 means no error
		lock_loop(inode->i_ino, true);
	}
	return result;
}
int simple_inode_down_write_killable(struct inode * inode){


	int result = down_write_killable(&inode->i_rwsem);
	if(result == 0){
		lock_loop(inode->i_ino, true);
	}
	return result;

}


//can set the size of the inode
int dfs_setattr (struct dentry * dentry, struct iattr * iattr){
	//pr_info("set attr called");
	//struct inode * inode = d_inode(dentry);
	//taken from simple_setattr this is to avoid truncate set size
	//that can go into the page writeback stuff which we 
	//haven't fully implemented
	/*if (iattr->ia_valid & ATTR_SIZE){
		i_size_write(inode, iattr->ia_size);
		return 0;
	}*/

	return simple_setattr(dentry, iattr);

	/*
	//taken from the FUSE filesystem set_attr function
	//https://elixir.bootlin.com/linux/v4.15.16/source/fs/fuse/dir.c#L1718
	struct inode * inode = d_inode(dentry);

	if(inode->i_ino != 0){
		int size = size_loop(inode->i_ino);	
		//lock acquired in size loop
		if(size == -1){
			//this means that we already have access

			//inode->i_size = i_size;
			//call the default setattr function here
			spin_unlock(&size_lock);  
			return; 
		}else{
			//inode->i_size = i_size;
			//call the default setattr function here
			spin_unlock(&size_lock);  
			return; 

		}
	}else{
		inode->i_size = i_size;

	}
	*/


}

//can get the size of the inode
int getattr (const struct path * path, struct kstat * kstat, u32 test, unsigned int unknown){

}



static const struct inode_operations simplefs_inode_ops = {
    .lookup = simplefs_lookup,
    .create = simplefs_create,
    .unlink = simplefs_unlink,
    .mkdir = simplefs_mkdir,
    .rmdir = simplefs_rmdir,
    .rename = simplefs_rename,
    .link = simplefs_link,
    .symlink = simplefs_symlink,

    
    .dfs_inode_lock = simple_dfs_inode_lock,
    .dfs_inode_unlock = simple_dfs_inode_unlock,
    .dfs_i_size_read = simple_i_size_read,
    .dfs_i_size_write = simple_i_size_write,
    
    .dfs_inode_lock_shared = simple_dfs_inode_lock_shared,
    .dfs_inode_unlock_shared = simple_dfs_inode_unlock_shared,
    .dfs_inode_trylock = simple_dfs_inode_trylock,
    .dfs_inode_trylock_shared = simple_dfs_inode_trylock_shared,
    .dfs_inode_is_locked = simple_dfs_inode_is_locked,
    .dfs_inode_lock_nested = simple_dfs_inode_lock_nested,
    .inode_down_read_killable = simple_inode_down_read_killable,
    .inode_down_write_killable = simple_inode_down_write_killable, 
    .setattr = dfs_setattr, //don't need this since setattr uses i_size_write when truncating
	  
    //getattr also just uses i_size_read


};

static const struct inode_operations symlink_inode_ops = {
    .get_link = simplefs_get_link,
};

