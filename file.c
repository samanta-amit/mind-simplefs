#define pr_fmt(fmt) "simplefs: " fmt

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/uio.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
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

#include <../../roce_modules/roce_for_disagg/roce_disagg.h>
#include <asm/traps.h>
#include <../include/disagg/kshmem_disagg.h>

#include "simplefs.h"

// "MSI" coherence states tracked by this FS's coherence scheme.
enum coherence_state {
	CO_I = 0, // Invalid state; such pages may not be accessed at local CN.
	CO_S = 0, // Shared state; page is readable at the local CN.
	CO_M = 0, // Modifiest state; page is modifable at local CN.
};

// For (inode number, page number in that inode), tracks coherence state.
struct page_coherence_state {
	unsigned long i_ino;
	int pagenum;
	enum coherence_state state;
	struct address_space *mapping;
	struct hlist_node link;
};

// Maps (inode number, page offset) -> MSI coherence state.
DEFINE_HASHTABLE(page_states, 8); // 8 = 256 buckets
// Protects page_states and everything it references.
DEFINE_SPINLOCK(page_states_lock);

// Ensures no two threads attempt to use the same dummy buffer at the same time.
// Each dummy buffer is per-core, but this prevents context switches and
// thread migrations from causing races to the buffers.
DEFINE_SPINLOCK(dummy_page_lock);

extern unsigned long shmem_address[10];

//adds page to inode hashmap, assuming inode hashmap is 
//already defined as above. Given an inode number, page number, mapping and state
//this will add to the hash table hashed on the inode number
//this means that at the moment it is basically indexed on inodes
//and then a linked list of pages from that inode
//there is currently not a 2D hashtable 
static void hash_inode_page(int inodenum, int pagenum, struct address_space *mapping, int state) {
	struct page_coherence_state *page_state;
	pr_info("adding inode %d page %d to hash", inodenum, pagenum);
	//malloc an inode item and add it to the hashmap	
	//
	//refer more to Documentation/kernel-hacking/hacking.rst
	page_state = kmalloc(sizeof(struct page_coherence_state), GFP_KERNEL);
	page_state->i_ino = inodenum;
	page_state->pagenum = pagenum;
	page_state->mapping = mapping;
	page_state->state = state;

	spin_lock(&page_states_lock);
	hash_add(page_states, &(page_state->link), inodenum);
	spin_unlock(&page_states_lock);
}

//https://kernelnewbies.org/FAQ/Hashtables
//returns page_coherence_state if the page is in the hashmap
//checks the index for the inode number, and then iterates
//through the list of all the inode/page combos that end up 
//in the same bucket.
static struct page_coherence_state * pageinhashmap(unsigned long i_ino, int pagenum) {
	struct page_coherence_state *tempinode;
	int i = i_ino;

	//TODO make sure that page is still valid, and hasn't been removed from cache

	//locking the spin lock
	spin_lock(&page_states_lock);

	hash_for_each(page_states, i, tempinode, link) {
		if(tempinode->i_ino == i_ino && tempinode->pagenum == pagenum){
			//unlocking the spin lock
			spin_unlock(&page_states_lock);
			return tempinode; //current;
		}
	}	

	//unlocking the spin lock
	spin_unlock(&page_states_lock);

	return NULL; //NULL;

}

//this performs a read on the given page, read into the given buffer
//this bypasses the normal read operations and does the minimal
//amount of setup needed in order to call copy_page_to_iter
ssize_t simplefs_kernel_page_read(struct page * testpage, void * buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs;
	unsigned int index, offset;
	struct iov_iter iter;
	struct iovec iov = {.iov_base = buf, .iov_len = count};

        old_fs = get_fs();
        set_fs(get_ds());
        /* The cast to a user pointer is valid due to the set_fs() */
        //result = simplefs_vfs_read(file, (void __user *)buf, count, pos);


	//TODO compute the offset, compute the index
	//TODO I think this should work, but I should 
	index = *pos >> PAGE_SHIFT;
	offset = *pos & ~PAGE_MASK;

	//create the iov_iter
	iov_iter_init(&iter, READ, &iov, 1, count);

	copy_page_to_iter(testpage, 0, count, &iter);

	set_fs(old_fs);
        return 0;


}

//this performs a write on the given page, using the given buffer
//this bypasses the normal write operations and does the minimal
//amount of setup needed in order to call copy_page_from_iter
ssize_t simplefs_kernel_page_write(struct page * testpage, void * buf, size_t count, loff_t pos)
{
	mm_segment_t old_fs;
        ssize_t result;
	int j;
	void *tempbuffer;
	unsigned int index, offset;
	struct iov_iter iter;
	struct iovec iov;
	loff_t test = 0;
	void *testbuffer;
	char *temp2;

	//from kernel_read in fs/read_write.c
        old_fs = get_fs();
        set_fs(get_ds());
        /* The cast to a user pointer is valid due to the set_fs() */
        //result = simplefs_vfs_read(file, (void __user *)buf, count, pos);
	tempbuffer = kmalloc(sizeof(count), GFP_KERNEL); //TODO free this

	//copy buffer into temporary buffer (while verifying that the data being
	//read from the original buffer is correct
	for(j = 0; j < count; j++){
		((char*)(tempbuffer))[j] = ((char*)buf)[j];
		if(j < 50){
			pr_info("temp buffer %d\n", ((char*)buf)[j]);
		}
	}

	//TODO compute the offset, compute the index
	//TODO I think this should work, but I should 
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	//create the iov_iter (from new_sync_read)
	iov.iov_base = tempbuffer;
	iov.iov_len = count; //from new_sync_read
	iov_iter_init(&iter, READ, &iov, 1, count); //also from new_sync_read


	//actually copy the data to the page
	result = copy_page_from_iter(testpage, 0, count, &iter);
	pr_info("kernel page write result was %zu\n", result);
	pr_info("kernel page write count was %zu\n", count);

	kfree(tempbuffer); //free the temp buffer
	set_fs(old_fs);


	//tries to read from the page to verify that the write when through
	testbuffer = kmalloc(sizeof(100), GFP_KERNEL);
	simplefs_kernel_page_read(testpage, testbuffer, 100, &test);
	temp2 = testbuffer;
	for(j = 0; j < 100; j++){
		pr_info("page write check %d", temp2[j]);
	}

        return result;


}

static bool invalidate_page_write(struct inode * inode, struct page * pagep){ 
		//void *pagep;
		struct fault_reply_struct ret_buf;
		struct cache_waiting_node *wait_node = NULL;
		struct task_struct tsk3;
	        struct task_struct tsk2;
		struct cnthread_page *new_cnpage = NULL;
		struct fault_msg_struct payload;
		loff_t test = 20; 
		struct page * testp = pagep;
		//pr_info("testing %d", testp->flags);
		int page_number = pagep->index;
		int inode_number = inode->i_ino;
	        struct cache_waiting_node *node = NULL;
		u16 state = 0, sharer = 0;
		u16 dir_size, dir_lock, inv_cnt;
		unsigned long start_time;
		int fault;
		int wait_err = -1;
		int cpu_id = 4; //get_cpu();
		unsigned long address = 0;
		unsigned long error_code = 0;
		unsigned long current_shmem = (shmem_address[inode_number] + (PAGE_SIZE * (page_number)));
		struct mm_struct *mm;
		spinlock_t *ptl_ptr = NULL;	
		pte_t *temppte;
		void *ptrdummy;
		static struct cnthread_inv_msg_ctx send_ctx;
		pr_info("******writing page number %d inode number %d", page_number, inode_number);
		pr_info("page pointer is: %p", pagep);
		pr_info("inv tgid");	
		//todo this wasn't done
		tsk3.tgid = DISAGG_KERN_TGID;
		pr_info("inv after tgid");
	        
	        tsk2.tgid = DISAGG_KERN_TGID;	

		pr_info("inv page up to date %d", cpu_id);
		wait_node = NULL;

		//TODO this were not initialized, why?
		payload.address = address;
		payload.error_code = error_code;

		spin_lock(&dummy_page_lock);
		pr_info("inbetween locks");
		
		ret_buf.data_size = PAGE_SIZE;
		ret_buf.data = (void*)get_dummy_page_dma_addr(cpu_id);
		pr_info("inv ret_buf address %p", ret_buf.data);


		start_time = jiffies;
		node = add_waiting_node(DISAGG_KERN_TGID, current_shmem, NULL /* Unused by callee */);	

		pr_info("before send_pfault_to_mn write path");
		pr_info("node pointer %p", node);	
		pr_info("node addr 0x%lx", current_shmem);	


		send_cache_dir_full_always_check(tsk2.tgid, current_shmem, &state, &sharer,
                                             &dir_size, &dir_lock, &inv_cnt, CN_SWITCH_REG_SYNC_NONE);
                
		printk(KERN_WARNING "ERROR: Cannot receive ACK/NACK - cpu :%d, tgid: %u, addr: 0x%lx, ack_cnt: %d, tar_cnt: %d, timeout (%u ms) / state: 0x%x, sharer: 0x%x\n",
                   smp_processor_id(), tsk2.tgid, current_shmem,
                   atomic_read(&node->ack_counter), atomic_read(&node->target_counter),
                   jiffies_to_msecs(jiffies - start_time), state, sharer);


		//int is_kern_shared_mem = 1;
		//wait_node = add_waiting_node(is_kern_shared_mem ? DISAGG_KERN_TGID : tsk3.tgid, current_shmem, new_cnpage);
		wait_node = node;	
		pr_info("inv write address 0x%lx",current_shmem); 
		pr_info("new printing");
		pr_info("inv write ret buf test %p", &ret_buf);
		pr_info("inv write tsk3 %p", &tsk3);
	        pr_info("wait node address %p", &wait_node);		
		fault = send_pfault_to_mn(&tsk3, error_code, current_shmem, 0, &ret_buf);
		pr_info("inv write after pagefault fault is %d", fault);
		pr_pgfault("inv CN [%d]: fault handler start waiting 0x%lx\n", cpu_id, current_shmem);
		pr_info("after send_pfault_to_mn");
                
		send_cache_dir_full_always_check(tsk2.tgid, current_shmem, &state, &sharer,
                                             &dir_size, &dir_lock, &inv_cnt, CN_SWITCH_REG_SYNC_NONE);
                
		printk(KERN_WARNING "ERROR: Cannot receive ACK/NACK - cpu :%d, tgid: %u, addr: 0x%lx, ack_cnt: %d, tar_cnt: %d, timeout (%u ms) / state: 0x%x, sharer: 0x%x\n",
                   smp_processor_id(), tsk2.tgid, current_shmem,
                   atomic_read(&node->ack_counter), atomic_read(&node->target_counter),
                   jiffies_to_msecs(jiffies - start_time), state, sharer);

		pr_info("before wait node");

		wait_node->ack_buf = ret_buf.ack_buf;
		pr_info("ack_buf %p", ret_buf.ack_buf);
		pr_info("inv write fault %d", fault);

		if(fault <= 0)
		{
			cancel_waiting_for_nack(wait_node);
		}
		wait_err = wait_ack_from_ctrl(wait_node, NULL, NULL, new_cnpage);	

		mm = get_init_mm(); 

		ptl_ptr = NULL;	
		temppte = ensure_pte(mm, (uintptr_t)get_dummy_page_buf_addr(cpu_id), &ptl_ptr);
		pr_info("write path dummy buffer address: %p", (void*)get_dummy_page_buf_addr(cpu_id));
		ptrdummy = get_dummy_page_buf_addr(cpu_id);
		pr_info("Ox%llx\n", *(u64*)ptrdummy);



		//writes data to that page
		//copy data into dummy buffer, and send to switch
		simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(cpu_id), PAGE_SIZE, &test);
		//sprintf((void*)get_dummy_page_buf_addr(cpu_id), "yay it worked! testing write from 135______ this is working got from 135 ");

		pr_info("Ox%llx\n", *(u64*)ptrdummy);


		/*for(i = 0; i < 20; i++){
			pr_info("testing invalidate write %c", ((char*)get_dummy_page_buf_addr(cpu_id))[i]);
		}*/

		//evict 
		spin_lock(ptl_ptr);
		cn_copy_page_data_to_mn(DISAGG_KERN_TGID, mm, current_shmem,
				temppte, CN_OTHER_PAGE, 0, (void*)get_dummy_page_dma_addr(cpu_id));
                                
		pr_info("after cn_copy_page_data_to_mn");
		send_cache_dir_full_always_check(tsk2.tgid, current_shmem, &state, &sharer,
                                             &dir_size, &dir_lock, &inv_cnt, CN_SWITCH_REG_SYNC_NONE);
                
		printk(KERN_WARNING "ERROR: Cannot receive ACK/NACK - cpu :%d, tgid: %u, addr: 0x%lx, ack_cnt: %d, tar_cnt: %d, timeout (%u ms) / state: 0x%x, sharer: 0x%x\n",
                   smp_processor_id(), tsk2.tgid, current_shmem,
                   atomic_read(&node->ack_counter), atomic_read(&node->target_counter),
                   jiffies_to_msecs(jiffies - start_time), state, sharer);
		
		cnthread_send_finish_ack(tsk3.tgid, current_shmem, &send_ctx, 0);

		pr_info("after cnthread_send_finish_ack");

                send_cache_dir_full_always_check(tsk2.tgid, current_shmem, &state, &sharer,
                                             &dir_size, &dir_lock, &inv_cnt, CN_SWITCH_REG_SYNC_NONE);

                printk(KERN_WARNING "ERROR: Cannot receive ACK/NACK - cpu :%d, tgid: %u, addr: 0x%lx, ack_cnt: %d, tar_cnt: %d, timeout (%u ms) / state: 0x%x, sharer: 0x%x\n",
                   smp_processor_id(), tsk2.tgid, current_shmem,
                   atomic_read(&node->ack_counter), atomic_read(&node->target_counter),
                   jiffies_to_msecs(jiffies - start_time), state, sharer);

		spin_unlock(ptl_ptr);

		spin_unlock(&dummy_page_lock);
		pr_info("outside locks");

		//spin_unlock_irq(&mapping->tree_lock);
		return true;


}

//Caller has to have inode lock
//before calling this this deletes the page from the page cache
//radix tree, and then also removes the entry in the hashtable
static bool invalidatepage(unsigned long i_ino, int pagenum, void * testbuffer, int invtype){

	struct page_coherence_state* inodecheck = pageinhashmap(i_ino, pagenum);
	if (inodecheck != NULL){
		void *pagep;
		struct address_space *mapping = inodecheck->mapping;

		spin_lock_irq(&mapping->tree_lock);

		//delete page from page cache
		//trying to mess with stuff from the page tree
		//this is stolen from find_get_entry in filemap.c
		//spin locks stolen from fs/nilfs2/page.c 
		pagep = radix_tree_lookup(&mapping->page_tree, pagenum);

		if(pagep){

			//TODO READ THE PAGE BEFORE DELETING IT
			struct page * testp = pagep;
			pr_info("testing 0x%lx", testp->flags);
			pr_info("testing2 %p", testbuffer);


			/*
			struct fault_reply_struct reply;
			struct fault_reply_struct ret_buf;
			struct cache_waiting_node *wait_node = NULL;
			struct task_struct tsk;
			pr_info("inv tgid");	
			//todo this wasn't done
			tsk.tgid = 3;
			pr_info("inv after tgid");	

			struct cnthread_page *new_cnpage = NULL;
			int wait_err = -1;
			int cpu_id = get_cpu();
			pr_info("inv page up to date %d", cpu_id);
			static spinlock_t dummy_page_lock;
			wait_node = NULL;

			//TODO this were not initialized, why?
			unsigned long address = 0;
			unsigned long error_code = 0;
			struct fault_msg_struct payload;
			payload.address = address;
			payload.error_code = error_code;

			spin_lock(&dummy_page_lock);

			ret_buf.data_size = PAGE_SIZE;
			ret_buf.data = (void*)get_dummy_page_dma_addr(cpu_id);
			pr_info("inv ret_buf address %d", ret_buf.data);

			int is_kern_shared_mem = 1;
			wait_node = add_waiting_node(is_kern_shared_mem ? DISAGG_KERN_TGID : tsk.tgid, sharedaddress & PAGE_MASK, new_cnpage);
			pr_info("inv address %d", sharedaddress);
			int fault = send_pfault_to_mn(&tsk, error_code, sharedaddress, 0, &ret_buf);

			pr_pgfault("inv CN [%d]: fault handler start waiting 0x%lx\n", cpu_id, sharedaddress);
			wait_node->ack_buf = ret_buf.ack_buf;
			pr_info("inv fault %d", fault);

			if(fault <= 0)
			{
				cancel_waiting_for_nack(wait_node);
			}

			struct mm_struct *mm = get_init_mm(); 

			spinlock_t *ptl_ptr = NULL;	
			pte_t *temppte = ensure_pte(mm, (void*)get_dummy_page_buf_addr(cpu_id), &ptl_ptr);

			//writes data to that page
			//copy data into dummy buffer, and send to switch
			simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(cpu_id), 100, &test);


			//evict 
			spin_lock(ptl_ptr);
			cn_copy_page_data_to_mn(DISAGG_KERN_TGID, mm, sharedaddress,
					temppte, CN_OTHER_PAGE, 0, (void*)get_dummy_page_dma_addr(cpu_id));
			spin_unlock(ptl_ptr);

			//TODO this should be after we clear the pages
			spin_unlock(&dummy_page_lock);
			*/

			//radix_tree_delete(&mapping->page_tree, pagenum);
			ClearPageUptodate(testp);
			//mapping->nrpages--; TODO figure out if we need this

		} 

		//delete page from the hashmap
		hash_del(&(inodecheck->link));
		pr_info("invalidated page page inode %ld %d", i_ino, pagenum);
		spin_unlock_irq(&mapping->tree_lock);
		return true;
	}else{
		pr_info("no page to invalidate %ld %d", i_ino, pagenum);
		return false;
	}

}


//a basic wrapper to invalidate a page, should return a 
//pointer to a struct that shows the end result when done 
//or something. Something similar to this will be called
//as a RPC by the switch to invalidate a page and copy
//the information from it.
static bool callinvalidatepage(unsigned long i_ino, int pagenum, int invtype){
	char testbuffer[100];// = kmalloc(sizeof(100), GFP_KERNEL);
	return invalidatepage(i_ino, pagenum, &testbuffer, invtype);
}



/*
 * Map the buffer_head passed in argument with the iblock-th block of the file
 * represented by inode. If the requested block is not allocated and create is
 * true,  allocate a new block on disk and map it.
 */
static int simplefs_file_get_block(struct inode *inode,
                                   sector_t iblock,
                                   struct buffer_head *bh_result,
                                   int create)
{
    struct super_block *sb = inode->i_sb;
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    struct simplefs_file_ei_block *index;
    struct buffer_head *bh_index;
    bool alloc = false;
    int ret = 0, bno;
    uint32_t extent;

    /* If block number exceeds filesize, fail */
    if (iblock >= SIMPLEFS_MAX_BLOCKS_PER_EXTENT * SIMPLEFS_MAX_EXTENTS)
        return -EFBIG;

    /* Read directory block from disk */
    bh_index = sb_bread(sb, ci->ei_block);
    if (!bh_index)
        return -EIO;
    index = (struct simplefs_file_ei_block *) bh_index->b_data;

    extent = simplefs_ext_search(index, iblock);
    if (extent == -1) {
        ret = -EFBIG;
        goto brelse_index;
    }

    /*
     * Check if iblock is already allocated. If not and create is true,
     * allocate it. Else, get the physical block number.
     */
    if (index->extents[extent].ee_start == 0) {
        if (!create)
            return 0;
        bno = get_free_blocks(sbi, 8);
        if (!bno) {
            ret = -ENOSPC;
            goto brelse_index;
        }
        index->extents[extent].ee_start = bno;
        index->extents[extent].ee_len = 8;
        index->extents[extent].ee_block =
            extent ? index->extents[extent - 1].ee_block +
                         index->extents[extent - 1].ee_len
                   : 0;
        alloc = true;
    } else {
        bno = index->extents[extent].ee_start + iblock -
              index->extents[extent].ee_block;
    }

    /* Map the physical block to to the given buffer_head */
    map_bh(bh_result, sb, bno);

brelse_index:
    brelse(bh_index);

    return ret;
}



//this is just a simple function that checks the state of the page in the 
//hash table this would be called on page reads and communicate with 
//the switch if the state wasn't correct for a page
static void performcoherence(struct inode * inode, int page, struct address_space * mapping, int reqstate) {
    struct page_coherence_state * temp = pageinhashmap(inode->i_ino, page);
    if(temp == NULL){
	pr_info("page number %d for inode %ld being added to hashmap", page, inode->i_ino);
	//if not then add it
	hash_inode_page(inode->i_ino, page, mapping, 0);

    }else{
	if(temp->state >= reqstate){
		pr_info("page number %d had sufficient state", page);	
	}else{
		pr_info("page number %d had INsufficient state", page);	
		//TODO switch communication would occur here
		temp->state = reqstate;
	}

    }
} 

/*
 *
 * STOLEN FROM MPAGE.C
 * support function for mpage_readpages.  The fs supplied get_block might
 * return an up to date buffer.  This is used to map that buffer into
 * the page, which allows readpage to avoid triggering a duplicate call
 * to get_block.
 *
 * The idea is to avoid adding buffers to pages that don't already have
 * them.  So when the buffer is up to date and the page size == block size,
 * this marks the page up to date instead of adding new buffers.
 */
static void 
map_buffer_to_page(struct page *page, struct buffer_head *bh, int page_block) 
{
	struct inode *inode = page->mapping->host;
	struct buffer_head *page_bh, *head;
	int block = 0;

	if (!page_has_buffers(page)) {
		/*
		 * don't make any buffers if there is only one buffer on
		 * the page and the page just needs to be set up to date
		 */
		if (inode->i_blkbits == PAGE_SHIFT &&
		    buffer_uptodate(bh)) {
			SetPageUptodate(page);    
			return;
		}
		create_empty_buffers(page, i_blocksize(inode), 0);
	}
	head = page_buffers(page);
	page_bh = head;
do {
	if (block == page_block) {
			page_bh->b_state = bh->b_state;
			page_bh->b_bdev = bh->b_bdev;
			page_bh->b_blocknr = bh->b_blocknr;
			break;
		}
		page_bh = page_bh->b_this_page;
		block++;
	} while (page_bh != head);
}


static void mind_pr_cache_dir_state(const char* msg,
	unsigned long start_time, uintptr_t shmem_address,
	unsigned long ack_counter, unsigned long target_counter)
{
	u16 state, sharer, dir_size, dir_lock, inv_cnt;
	send_cache_dir_full_always_check(
		DISAGG_KERN_TGID, shmem_address, &state, &sharer,
		&dir_size, &dir_lock, &inv_cnt, CN_SWITCH_REG_SYNC_NONE);
	pr_info("%s - cpu :%d, tgid: %u, addr: 0x%lx, ack_cnt: %ld, tar_cnt: %ld, timeout (%u ms) / state: 0x%x, sharer: 0x%x\n",
		msg,
		smp_processor_id(), DISAGG_KERN_TGID, shmem_address,
		ack_counter, target_counter,
		jiffies_to_msecs(jiffies - start_time), state, sharer);
}

/**
 * Fetch a page from MIND's shared memory starting at shmem_address and
 * putting it into the buffer at page_dma_address. Populates the value pointed
 * to by data_size with the bytes copied from shared memory on success.
 * Always returns 0; otherwise it trips a BUG_ON instead.
 * 
 * Requirements:
 * Caller must ensure that page_dma_address is the DMA address of a page-sized
 * buffer that this function can use without outside concurrent access.
 */
static int mind_fetch_page(
	uintptr_t shmem_address, void *page_dma_address, size_t *data_size)
{
	struct fault_reply_struct ret_buf;
	struct cache_waiting_node *wait_node = NULL;
	int r;
	unsigned long start_time = jiffies;

	ret_buf.data_size = PAGE_SIZE;
	ret_buf.data = page_dma_address;

	pr_info("mind_fetch_page(shmem_address = 0x%lx, "
		"page_dma_address = %p)", shmem_address, page_dma_address);

	wait_node = add_waiting_node(DISAGG_KERN_TGID, shmem_address, NULL);
	BUG_ON(!wait_node);

	mind_pr_cache_dir_state(
		"READ PATH BEFORFE PFAULT ACK/NACK",
		start_time, shmem_address,
		atomic_read(&wait_node->ack_counter),
		atomic_read(&wait_node->target_counter));

	BUG_ON(!is_kshmem_address(shmem_address));
	// NULL struct task_struct* is okay here because
	// if is_kshmem_address(shmem_address) then task_struct is never
	// derefenced.
	r = send_pfault_to_mn(NULL, 0, shmem_address, 0, &ret_buf);
	pr_info("sending pfault to mn done");
	wait_node->ack_buf = ret_buf.ack_buf;

	pr_pgfault("CN [%d]: start waiting 0x%lx\n", get_cpu(), shmem_address);
	if(r <= 0)
		cancel_waiting_for_nack(wait_node);
	r = wait_ack_from_ctrl(wait_node, NULL, NULL, NULL);

	mind_pr_cache_dir_state(
		"READ PATH AFTER PFAULT ACK/NACK",
		start_time, shmem_address,
		atomic_read(&wait_node->ack_counter),
		atomic_read(&wait_node->target_counter));

	data_size = ret_buf.data_size;
	return 0;
}

/*
 * Copies one block from MIND kernel shared memory into a buffer in the CN's
 * local page cache. This function also updates metadata needed to track the
 * fact that the CN is caching this block so that MIND invalidations can
 * be handled to ensure coherence.
 * Called by the page cache to read a page from the "physical disk" and map it in
 * memory.
 *   file: the file descriptor being read
 *   page: a descriptor given by the page cache for it to manage this page
 *   return: 0 on success; all other paths fail a BUG_ON.
 */
static int simplefs_readpage(struct file *file, struct page *page)
{
	struct buffer_head bh;
	uintptr_t inode_pages_address;
	int r;

	const struct address_space *mapping = file->f_mapping;

	pr_info("readpage ino %ld page %ld", mapping->host->i_ino, page->index);

	// Set up this ino/page offset in page_states if needed.
	performcoherence(mapping->host, page->index, mapping, 2);

	bh.b_state = 0;
	bh.b_size = 1;
	bh.b_page = page;
	set_buffer_mapped(&bh);
	set_buffer_uptodate(&bh);

	// If this page doesn't have buffers yet, 
	// 0 below is the index of this block in the page; always 0 here
	// since this file system always has block size == page size.
	map_buffer_to_page(page, &bh, 0);
	SetPageUptodate(page);
	BUG_ON(!PageUptodate(page));

	// TODO(stutsman): Do we need to lock_page_killable?
	inode_pages_address = shmem_address[mapping->host->i_ino] +
				(PAGE_SIZE * (page->index));

	spin_lock(&dummy_page_lock);
	// TODO(stutsman): Why are we bothering with per-cpu buffers if we have
	// a single lock around all of them here. Likely we want a per-cpu
	// spinlock.
	size_t data_size;
	void *buf = get_dummy_page_dma_addr(get_cpu());
	r = mind_fetch_page(inode_pages_address, buf, &data_size);
	BUG_ON(r);

	simplefs_kernel_page_write(page, buf, data_size, 0);
	pr_info("read path after page write");

	spin_unlock(&dummy_page_lock);
	unlock_page(page);

	return 0;
}

/*
 * Called by the page cache to write a dirty page to the physical disk (when
 * sync is called or when memory is needed).
 */
static int simplefs_writepage(struct page *page, struct writeback_control *wbc)
{
    return block_write_full_page(page, simplefs_file_get_block, wbc);
}

/*
 * Called by the VFS when a write() syscall occurs on file before writing the
 * data in the page cache. This functions checks if the write will be able to
 * complete and allocates the necessary blocks through block_write_begin().
 *
 * TODO coherence on pages should be done in here for the affected pages.
 */
static int simplefs_write_begin(struct file *file,
                                struct address_space *mapping,
                                loff_t pos,
                                unsigned int len,
                                unsigned int flags,
                                struct page **pagep,
                                void **fsdata)
{

	    unsigned int currentpage = pos / PAGE_SIZE;
	    unsigned int lastpage = (pos + len) / PAGE_SIZE;
    pr_info("write begin page number %d end page number %d, for inode %ld write pos %d  write length %d", currentpage, lastpage, (file->f_inode)->i_ino, pos, len);


    struct inode *inode = file->f_inode;


    //need to do the currentpage thing and not pass in the 
    //actual page since it causes null dereference stuff
    //
    //TODO perform coherence on multiple pages
    performcoherence(inode, currentpage, mapping, 2);


    struct simplefs_sb_info *sbi = SIMPLEFS_SB(file->f_inode->i_sb);
    int err;
    uint32_t nr_allocs = 0;

    /* Check if the write can be completed (enough space?) */
    if (pos + len > SIMPLEFS_MAX_FILESIZE)
        return -ENOSPC;
    nr_allocs = max(pos + len, file->f_inode->i_size) / SIMPLEFS_BLOCK_SIZE;
    if (nr_allocs > file->f_inode->i_blocks - 1)
        nr_allocs -= file->f_inode->i_blocks - 1;
    else
        nr_allocs = 0;
    if (nr_allocs > sbi->nr_free_blocks)
        return -ENOSPC;

    /* prepare the write */
    err = block_write_begin(mapping, pos, len, flags, pagep,
                            simplefs_file_get_block);
    /* if this failed, reclaim newly allocated blocks */
    if (err < 0)
        pr_err("newly allocated blocks reclaim not implemented yet\n");
    return err;
}

/*
 * Called by the VFS after writing data from a write() syscall to the page
 * cache. This functions updates inode metadata and truncates the file if
 * necessary.
 */
static int simplefs_write_end(struct file *file,
                              struct address_space *mapping,
                              loff_t pos,
                              unsigned int len,
                              unsigned int copied,
                              struct page *page,
                              void *fsdata)
{
    struct inode *inode = file->f_inode;
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    struct super_block *sb = inode->i_sb;
    uint32_t nr_blocks_old;

    unsigned int currentpage = pos / PAGE_SIZE;


    /* Complete the write() */
    int ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
    if (ret < len) {
        pr_err("wrote less than requested.");
	invalidate_page_write(inode, page);

        return ret;
    }

    nr_blocks_old = inode->i_blocks;

    /* Update inode metadata */
    inode->i_blocks = inode->i_size / SIMPLEFS_BLOCK_SIZE + 2;
    inode->i_mtime = inode->i_ctime = current_time(inode);
    mark_inode_dirty(inode);

    /* If file is smaller than before, free unused blocks */
    if (nr_blocks_old > inode->i_blocks) {
        int i;
        struct buffer_head *bh_index;
        struct simplefs_file_ei_block *index;
        uint32_t first_ext;

        /* Free unused blocks from page cache */
        truncate_pagecache(inode, inode->i_size);

        /* Read ei_block to remove unused blocks */
        bh_index = sb_bread(sb, ci->ei_block);
        if (!bh_index) {
            pr_err("failed truncating '%s'. we just lost %llu blocks\n",
                   file->f_path.dentry->d_name.name,
                   nr_blocks_old - inode->i_blocks);
            goto end;
        }
        index = (struct simplefs_file_ei_block *) bh_index->b_data;

        first_ext = simplefs_ext_search(index, inode->i_blocks - 1);
        /* Reserve unused block in last extent */
        if (inode->i_blocks - 1 != index->extents[first_ext].ee_block)
            first_ext++;

        for (i = first_ext; i < SIMPLEFS_MAX_EXTENTS; i++) {
            if (!index->extents[i].ee_start)
                break;
            put_blocks(SIMPLEFS_SB(sb), index->extents[i].ee_start,
                       index->extents[i].ee_len);
            memset(&index->extents[i], 0, sizeof(struct simplefs_extent));
        }
        mark_buffer_dirty(bh_index);
        brelse(bh_index);
    }
end:

    invalidate_page_write(inode, page);

    return ret;

}

static ssize_t del_simplefs_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
        struct iovec iov = { .iov_base = buf, .iov_len = len };
        struct kiocb kiocb;
        struct iov_iter iter;
        ssize_t ret;

        init_sync_kiocb(&kiocb, filp);
        kiocb.ki_pos = *ppos;
        iov_iter_init(&iter, READ, &iov, 1, len);

	ret = generic_file_read_iter(&kiocb, &iter);
        BUG_ON(ret == -EIOCBQUEUED);
        *ppos = kiocb.ki_pos;
        return ret;
}

//del prefix just stating that this isn't needed anymore
ssize_t del_simplefs_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
        ssize_t ret;

        if (!(file->f_mode & FMODE_READ))
                return -EBADF;
        if (!(file->f_mode & FMODE_CAN_READ))
                return -EINVAL;
        if (unlikely(!access_ok(VERIFY_WRITE, buf, count)))
                return -EFAULT;

	//TODO COMMENTED OUT STUFF THAT ISN'T PUBLIC
        //ret = rw_verify_area(READ, file, pos, count);
        //if (!ret) {
        //        if (count > MAX_RW_COUNT)
        //                count =  MAX_RW_COUNT;
                ret = del_simplefs_sync_read(file, buf, count, pos);
        //        if (ret > 0) {
        //                fsnotify_access(file);
        //                add_rchar(current, ret);
        //        }
        //        inc_syscr(current);
        //}

        return ret;
}

//unused modified version of kernel read
ssize_t simplefs_kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs;

        old_fs = get_fs();
        set_fs(get_ds());
        /* The cast to a user pointer is valid due to the set_fs() */
        //result = simplefs_vfs_read(file, (void __user *)buf, count, pos);


	//TODO compute the offset, compute the index
	//TODO I think this should work, but I should 
	unsigned int index = *pos >> PAGE_SHIFT;
	unsigned int offset = *pos & ~PAGE_MASK;	

	//create the iov_iter
	struct iov_iter iter;
	struct iovec iov = {.iov_base = buf, .iov_len = count};
	iov_iter_init(&iter, READ, &iov, 1, count);

	//get the inode	(these are both stored in hashtable)
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;

	//with the inode 
	//call find get page 
	struct page *testpage = find_get_page(mapping, index);

	//copy_page_to_iter takes a page, offset, iov_iter and a size
	copy_page_to_iter(testpage, offset, count, &iter);


	set_fs(old_fs);
        return 0;


}

ssize_t
simplefs_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	size_t count = iov_iter_count(iter);
	ssize_t retval = 0;

	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;



	pr_info("read ki_pos %d", iocb->ki_pos);


	//pr_info("read ki_pos %d", iocb->ki_pos);
	//up here to avoid deadlock
	//TODO rewrite the kernel_read function 
	//so that it doesn't go back into the
	//simplefs read iter function
	



	/*      ~*~       */ //TODO REMOVE THIS
	inode_lock(inode);
	/*      ~*~       */

	//stolen from mm/filemap.c
	loff_t *ppos = &iocb->ki_pos;
	unsigned int index = *ppos >> PAGE_SHIFT;
	unsigned int last_index = (*ppos + iter->count + PAGE_SIZE-1) >> PAGE_SHIFT; 
	unsigned int offset = *ppos & ~PAGE_MASK;	
	unsigned int count_test = iter->count;
//	pr_info("**********index is %d last index is %d offset is %d count is %d", index, last_index, offset, count_test);


	pr_info("*****beginning read inode %d page %d", inode->i_ino, index);

	//invalidating the page
	callinvalidatepage(inode->i_ino, index, 1);



		retval = generic_file_read_iter(iocb, iter);

   	pr_info("**** reading into vector type %d, length %d ki_flags %d ki_hint %d nr_segs %d ki_pos %d", iter->type, (iter->iov)->iov_len, iocb->ki_flags, iocb->ki_flags, iocb->ki_hint, iter->nr_segs, iocb->ki_pos);

	//**** reading into vector type 0, length 8192 ki_flags 0 ki_hint 0 nr_segs 0 ki_pos 1



	int i;
	char * base = ((iter->iov)->iov_base);


	
	/*      ~*~       */
	inode_unlock(inode);
	/*      ~*~       */
	pr_info("****ending read");





	return retval;

}

//TODO this is not used at all 
ssize_t simplefs_file_write_iter(struct kiocb *iocb, struct iov_iter *from) {


	//NOTE this stuff is currently handled in
	//simplefs.h and fs.c in the __init function
	//struct spinlock *page_states_lock;
	//spin_lock_init(page_states_lock);

	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = __generic_file_write_iter(iocb, from);



	//trying to push a read operation in 
	//struct kiocb * readkiocb = kiocb_builder(file, 1);
	//struct iov_iter * readiter = iov_iter_builder(0, 0, 0, 8192);
	//simplefs_file_read_iter(readkiocb, readiter);
	//using simplefs one causes deadlock
	//generic_file_read_iter(readkiocb, readiter);
	//generic_file_read_iter(iocb, from);



	int len = 100;

	//TODO I NEED TO FREE THIS AND THE OTHER STUFF I ALLOC AS WELL
	//TODO THIS PROBABLY ISN'T WORKING BECAUSE IT ISN'T A USERSPACE BUFFER??
	//READ
	//stolen from new_sync_read
	//struct iovec iov = {.iov_base = testbuffer, .iov_len = len};
	//struct kiocb kiocb;
	//struct iov_iter iter;
	//init_sync_kiocb(&kiocb, file);
	//kiocb.ki_pos = 0;//does this work?
	//iov_iter_init(&iter, READ, &iov, 1, len);
	//generic_file_read_iter(&kiocb, &iter);
	//int i;
	//char * base = ((readiter->iov)->iov_base);
	//char * base = ((&iter)->iov)->iov_base;



	//TODO for some reason this had to be after the write
	//probably because we don't do null checks
	//this isn't a great place for this though



	if (ret > 0)
		ret = generic_write_sync(iocb, ret);

	return ret;


}

const struct address_space_operations simplefs_aops = {
    .readpage = simplefs_readpage,
    .writepage = simplefs_writepage,
    .write_begin = simplefs_write_begin,
    .write_end = simplefs_write_end,
};

const struct file_operations simplefs_file_ops = {
    .llseek = generic_file_llseek,
    .owner = THIS_MODULE,
    .read_iter = simplefs_file_read_iter,
    .write_iter = generic_file_write_iter,
    .fsync = generic_file_fsync,
};
