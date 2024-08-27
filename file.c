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

// "MSI" coherence states tracked by this FS's coherence scheme.
/*
enum coherence_state {
	CO_I = 0, // Invalid state; such pages may not be accessed at local CN.
	CO_S = 0, // Shared state; page is readable at the local CN.
	CO_M = 0, // Modifiest state; page is modifable at local CN.
};*/

// Ensures no two threads attempt to use the same dummy buffer at the same time.
// thread migrations from causing races to the buffers.
//DEFINE_SPINLOCK(dummy_page_lock);

#define READ 1
#define WRITE 2

spinlock_t cnthread_inval_send_ack_lock[DISAGG_NUM_CPU_CORE_IN_COMPUTING_BLADE];


struct shmem_coherence_state {
    	unsigned long shmem_addr;
	unsigned long i_ino;
	struct inode * inode;
	int pagenum;
	int state;
	int page_locked_state;
	int table_locked_state;

	struct address_space *mapping;
	struct hlist_node link;
	struct rw_semaphore rwsem;
};

extern struct rw_semaphore hash_page_rwsem;
//extern spinlock_t * spin_inode_lock[10];
extern void lock_loop(int ino, bool write);
extern struct rw_semaphore * inode_rwlock[10];

DEFINE_HASHTABLE(shmem_states, 8); // 8 = 256 buckets
// Protects shmem_states and everything it references.
//DEFINE_SPINLOCK(shmem_states_lock);


static void hash_shmem(unsigned long shmem_addr, int inodenum, int pagenum, struct address_space *mapping, int state) {
	struct shmem_coherence_state *shmem_state;
	//refer more to Documentation/kernel-hacking/hacking.rst
	shmem_state = kmalloc(sizeof(struct shmem_coherence_state), GFP_KERNEL);
	shmem_state->i_ino = inodenum;
	shmem_state->pagenum = pagenum;
	shmem_state->mapping = mapping;
	shmem_state->state = state;
	shmem_state->shmem_addr = shmem_addr;
	shmem_state->page_locked_state = 0;
	shmem_state->table_locked_state = 0;

	//init the page lock
	init_rwsem(&(shmem_state->rwsem));

	//acquire the page in readmode	
	down_write(&(shmem_state->rwsem));

	//spin_lock(&shmem_states_lock);
	hash_add(shmem_states, &(shmem_state->link), shmem_addr);
	//spin_unlock(&shmem_states_lock);
}

//https://kernelnewbies.org/FAQ/Hashtables
//returns page_coherence_state if the page is in the hashmap
//checks the index for the inode number, and then iterates
//through the list of all the inode/page combos that end up 
//in the same bucket.
static struct shmem_coherence_state * shmem_in_hashmap(unsigned long shmem_addr) {
	struct shmem_coherence_state *tempshmem;
	int i = shmem_addr;

	//TODO make sure that page is still valid, and hasn't been removed from cache

	//locking the spin lock
	//spin_lock(&shmem_states_lock);

	hash_for_each(shmem_states, i, tempshmem, link) {
		if(tempshmem->shmem_addr == shmem_addr){ 
			//unlocking the spin lock
			//spin_unlock(&shmem_states_lock);
			return tempshmem; //current;
		}
	}	

	//unlocking the spin lock
	//spin_unlock(&shmem_states_lock);

	return NULL; //NULL;

}



extern unsigned long shmem_address[10];
extern unsigned long inode_address[10];
static bool invalidate_page_write(struct page * testp, struct file *file, struct inode * inode, int page, bool readpage);


struct page_lock_status {
	struct shmem_coherence_state * state;
	int page_lock;
	int table_lock;
	int old_state;
};

struct page_lock_status acquire_page_lock(struct file * file, struct inode * inode, int currentpage, uintptr_t inode_pages_address, struct address_space * mapping, int mode){
	//acquire read lock for the hashtable
	down_read(&hash_page_rwsem);

	//uintptr_t inode_pages_address = shmem_address[inode->i_ino] +
	//	(PAGE_SIZE * (page));

	int table_write_locked = 0;
	int page_write_locked = 0;
	int old_state = -1;
	//surrounded by hashmap readlock
	struct shmem_coherence_state * coherence_state = shmem_in_hashmap(inode_pages_address);

	if(coherence_state == NULL){

		up_read(&hash_page_rwsem);

		//acquire hashtable in write mode to add the new page
		down_write(&hash_page_rwsem);
		table_write_locked = 2;

		//surrounded by hashmap writelock
		coherence_state = shmem_in_hashmap(inode_pages_address);

		if(coherence_state == NULL){

			//page not in hashmap add it (and acquire write lock)
			//TODO make sure currentpage is correct
			hash_shmem(inode_pages_address, mapping->host->i_ino, currentpage, mapping, mode);
			page_write_locked = 1;

			coherence_state = shmem_in_hashmap(inode_pages_address);
			if(coherence_state == NULL){
			}
			//release hashtable so it doesn't have to wait any longer

			//TODO make sure current page is correct
			//invalidate_page_write(file, inode, currentpage);

		}else{
			//could think about acquiring it in read mode and doing the jumping around thing again
		
			down_write(&(coherence_state->rwsem));
			page_write_locked = 1;
			old_state = coherence_state->state;	
			if(coherence_state->state < mode){
				//TODO make sure current page is correct
				//invalidate_page_write(file, inode, currentpage);
				coherence_state->state = mode;

			}
		}
		up_write(&hash_page_rwsem);
	}else{
		down_write(&(coherence_state->rwsem));
		page_write_locked = 1;
		up_read(&hash_page_rwsem);
		old_state = coherence_state->state;
		if(coherence_state->state < mode){
			//TODO make sure current page is correct
			//invalidate_page_write(file, inode, currentpage);
			coherence_state->state = mode;
		}else{
		}
	}

	//TODO is this okay? 	
	struct page_lock_status temp;
	temp.state = coherence_state;
	temp.page_lock = page_write_locked;
	temp.table_lock = table_write_locked;
	temp.old_state = old_state;
	return temp; 
}



static void mind_pr_cache_dir_state(const char* msg,
	unsigned long start_time, uintptr_t shmem_address,
	unsigned long ack_counter, unsigned long target_counter)
{
	u16 state, sharer, dir_size, dir_lock, inv_cnt;
	send_cache_dir_full_always_check(
		DISAGG_KERN_TGID, shmem_address, &state, &sharer,
		&dir_size, &dir_lock, &inv_cnt, CN_SWITCH_REG_SYNC_NONE);
	//	msg,
	//	smp_processor_id(), DISAGG_KERN_TGID, shmem_address,
	//	ack_counter, target_counter,
	//	jiffies_to_msecs(jiffies - start_time), state, sharer);
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

	///removed since it was acquired in readpage
	//spin_lock(&dummy_page_lock);

	ret_buf.data_size = PAGE_SIZE;
	ret_buf.data = page_dma_address;

	//	"page_dma_address = %p)", shmem_address, page_dma_address);

	wait_node = add_waiting_node(DISAGG_KERN_TGID, shmem_address, NULL);
	BUG_ON(!wait_node);

	//spin_unlock(&dummy_page_lock);

	//mind_pr_cache_dir_state(
	//	"BEFORFE PFAULT ACK/NACK",
	//	start_time, shmem_address,
	//	atomic_read(&wait_node->ack_counter),
	//	atomic_read(&wait_node->target_counter));

	BUG_ON(!is_kshmem_address(shmem_address));
	// NULL struct task_struct* is okay here because
	// if is_kshmem_address(shmem_address) then task_struct is never
	// derefenced.
	r = send_pfault_to_mn(NULL, 0, shmem_address, 0, &ret_buf);

	wait_node->ack_buf = ret_buf.ack_buf;

	pr_pgfault("CN [%d]: start waiting 0x%lx\n", get_cpu(), shmem_address);
	if(r <= 0)
	{
		cancel_waiting_for_nack(wait_node);
		return -1;
		//BUG_ON(1);

	}
	r = wait_ack_from_ctrl(wait_node, NULL, NULL, NULL);
	if(r){
		return -1;
		//BUG_ON(1);
	}
	//mind_pr_cache_dir_state(
	//	"AFTER PFAULT ACK/NACK",
	//	start_time, shmem_address,
	//	atomic_read(&wait_node->ack_counter),
	//	atomic_read(&wait_node->target_counter));
	
	data_size = ret_buf.data_size;
	return 0;
}
//atomic_t page_req_count = ATOMIC_INIT(10); 

static int mind_fetch_page_write(
        uintptr_t shmem_address, void *page_dma_address, size_t *data_size)
{
        struct fault_reply_struct ret_buf;
        struct cache_waiting_node *wait_node = NULL;
        int r;
        unsigned long start_time = jiffies;

	//spin_lock(&dummy_page_lock);

        ret_buf.data_size = PAGE_SIZE;
        ret_buf.data = page_dma_address;

        //        "page_dma_address = %p)", shmem_address, page_dma_address);

        wait_node = add_waiting_node(DISAGG_KERN_TGID, shmem_address, NULL);
        BUG_ON(!wait_node);
	

        //mind_pr_cache_dir_state(
        //        "BEFORFE PFAULT ACK/NACK",
        //        start_time, shmem_address,
        //        atomic_read(&wait_node->ack_counter),
        //        atomic_read(&wait_node->target_counter));

        BUG_ON(!is_kshmem_address(shmem_address));
        // NULL struct task_struct* is okay here because
        // if is_kshmem_address(shmem_address) then task_struct is never
        // derefenced.
	r = send_pfault_to_mn(NULL, X86_PF_WRITE, shmem_address, 0, &ret_buf);
	//atomic_inc(&page_req_count);
	//pr_info("page requests %d", page_req_count.counter);
        wait_node->ack_buf = ret_buf.ack_buf;

        pr_pgfault("CN [%d]: start waiting 0x%lx\n", get_cpu(), shmem_address);
        if(r <= 0){
                cancel_waiting_for_nack(wait_node);
		BUG_ON(1);

	}
        r = wait_ack_from_ctrl(wait_node, NULL, NULL, NULL);
	if(r){
		cancel_waiting_for_nack(wait_node);
		return -1;
		//BUG_ON(1);
	}
        //mind_pr_cache_dir_state(
        //        "AFTER PFAULT ACK/NACK",
        //        start_time, shmem_address,
        //        atomic_read(&wait_node->ack_counter),
        //        atomic_read(&wait_node->target_counter));

        data_size = ret_buf.data_size;
	//spin_unlock(&dummy_page_lock);

        return 0;
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
	unsigned int index, offset;
	struct iov_iter iter;
	struct iovec iov;
	loff_t test = 0;

	//from kernel_read in fs/read_write.c
        old_fs = get_fs();
        set_fs(get_ds());
        /* The cast to a user pointer is valid due to the set_fs() */
        //result = simplefs_vfs_read(file, (void __user *)buf, count, pos);


	//TODO compute the offset, compute the index
	//TODO I think this should work, but I should 
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	//create the iov_iter (from new_sync_read)
        iov.iov_base = buf;
	iov.iov_len = count; //from new_sync_read
	iov_iter_init(&iter, READ, &iov, 1, count); //also from new_sync_read


	//actually copy the data to the page
        result = copy_page_from_iter(testpage, 0, count, &iter);

	set_fs(old_fs);

        return result;
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



static int check_coherence(struct inode * inode, int page, struct address_space * mapping, int reqstate) {
	uintptr_t inode_pages_address;
	inode_pages_address = shmem_address[inode->i_ino] +
	    (PAGE_SIZE * (page));

    //TODO add hashtable locks

    struct shmem_coherence_state * coherence_state = shmem_in_hashmap(inode_pages_address);
    if(coherence_state == NULL){
	return 0;
    }else{
        if(coherence_state->state == WRITE){
            return 1; 
        }else if(coherence_state->state == READ && reqstate == WRITE){
            return 0;        
	}
    }
	return 0;
}


//this is just a simple function that checks the state of the page in the 
//hash table this would be called on page reads and communicate with 
//the switch if the state wasn't correct for a page
static void update_coherence(struct inode * inode, int page, struct address_space * mapping, int reqstate) {
    uintptr_t inode_pages_address;
    inode_pages_address = shmem_address[inode->i_ino] +
	    (PAGE_SIZE * (page));

    //TODO add hashtable locks

    //TODO at the moment shmem_in_hashmap acquires the locks, we might just 
    //want to move that lock acquiring to be outside of that function so that
    //we can have it here so that we can read something from the hashmap and modify
    //it without another thread messing it up
    struct shmem_coherence_state * coherence_state = shmem_in_hashmap(inode_pages_address);
    if(coherence_state == NULL){
        //page not in hashmap
        hash_shmem(inode_pages_address, mapping->host->i_ino, page, mapping, reqstate);

    }else{

	    if(coherence_state->state == WRITE){
		    return;
	    }else{
		    if(reqstate == WRITE){
			    coherence_state->state = WRITE;
		    }
	    }
    }
} 

/*
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
	int i;
	const struct address_space *mapping = file->f_mapping;


	// TODO(stutsman): Do we need to lock_page_killable?
	inode_pages_address = shmem_address[mapping->host->i_ino] +
				(PAGE_SIZE * (page->index));

	//page is locked here in either read or write mode

	//page is locked for write now should always be locked for write
	//because we should always be updating the state when we get here

        //TODO insert into shmem_states

	bh.b_state = 0;
	bh.b_size = 1;
	bh.b_page = page;


	//spin_lock(&dummy_page_lock);
	int cpu = get_cpu();
	spin_lock(&cnthread_inval_send_ack_lock[cpu]);

	// TODO(stutsman): Why are we bothering with per-cpu buffers if we have
	// a single lock around all of them here. Likely we want a per-cpu
	// spinlock.
	size_t data_size;
	//void *buf = get_dummy_page_dma_addr(get_cpu());
	void *buf = get_dummy_page_dma_addr(cpu);


	r = mind_fetch_page(inode_pages_address, buf, &data_size);
	if(r == -1){
		spin_unlock(&cnthread_inval_send_ack_lock[cpu]);
		//spin_unlock(&dummy_page_lock);
		unlock_page(page);
		return -1337;
	}
	set_buffer_mapped(&bh);
	set_buffer_uptodate(&bh);

	// If this page doesn't have buffers yet, 
	// 0 below is the index of this block in the page; always 0 here
	// since this file system always has block size == page size.
	map_buffer_to_page(page, &bh, 0);
	SetPageUptodate(page);

	BUG_ON(!PageUptodate(page));
	
	//TODO handle failure case
	//on failure remove the remotevalid bit
	SetPageRemoteValid(page);
	
	simplefs_kernel_page_write(page, get_dummy_page_buf_addr(cpu), PAGE_SIZE, 0);
	//simplefs_kernel_page_write(page, buf, PAGE_SIZE, 0);


	//adds page to hashmap if not already in hashmap
	//update_coherence(mapping->host, page->index, mapping, READ);


	spin_unlock(&cnthread_inval_send_ack_lock[cpu]);
	//spin_unlock(&dummy_page_lock);
	unlock_page(page);

	//unlock page pointer
	
	return 0;
}


void simple_do_invalidatepage(struct page *page, unsigned int offset,
		       unsigned int length)
{
	void (*invalidatepage)(struct page *, unsigned int, unsigned int);

	invalidatepage = page->mapping->a_ops->invalidatepage;
#ifdef CONFIG_BLOCK
	if (!invalidatepage)
		invalidatepage = block_invalidatepage;
#endif
	if (invalidatepage)
		(*invalidatepage)(page, offset, length);
}




/*
 * The generic ->writepage function for buffer-backed address_spaces
 */
int simple_block_write_full_page(struct page *page, get_block_t *get_block,
			struct writeback_control *wbc)
{


	struct inode * const inode = page->mapping->host;
	loff_t i_size = i_size_read(inode);
	const pgoff_t end_index = i_size >> PAGE_SHIFT;
	unsigned offset;
	/* Is the page fully inside i_size? */
	if (page->index < end_index)
		return __block_write_full_page(inode, page, get_block, wbc,
					       end_buffer_async_write);

	/* Is the page fully outside i_size? (truncate in progress) */
	offset = i_size & (PAGE_SIZE-1);
	if (page->index >= end_index+1 || !offset) {
		/*
		 * The page may have dirty, unmapped buffers.  For example,
		 * they may have been added in ext3_writepage().  Make them
		 * freeable here, so the page does not leak.
		 */

		simple_do_invalidatepage(page, 0, PAGE_SIZE);

		unlock_page(page);
		return 0; /* don't care */
	}

	/*
	 * The page straddles i_size.  It must be zeroed out on each and every
	 * writepage invocation because it may be mmapped.  "A file is mapped
	 * in multiples of the page size.  For a file that is not a multiple of
	 * the  page size, the remaining memory is zeroed when mapped, and
	 * writes to that region are not written out to the file."
	 */
	zero_user_segment(page, offset, PAGE_SIZE);

	return __block_write_full_page(inode, page, get_block, wbc,
							end_buffer_async_write);
}

/*
 * Called by the page cache to write a dirty page to the physical disk (when
 * sync is called or when memory is needed).
 */
static int simplefs_writepage(struct page *page, struct writeback_control *wbc)
{

	//probably fix by acquiring in write mode here and releasing 
	//at end of this function

	//struct page_lock_status temp = acquire_page_lock(NULL, inode, currentpage, inode_pages_address, mapping, WRITE);

	//return simple_block_write_full_page(page, simplefs_file_get_block, wbc);

	//hack to try and prevent problems with page writeback	
	unlock_page(page);
	return 0; 
}


//TODO changed this so that it doesn't need page pointer
static bool invalidate_page_write(struct page * testp, struct file *file, struct inode * inode, int page, bool readpage){
	while(1){
		//struct page * testp = pagep;
		uintptr_t inode_pages_address;
		int r;
		struct mm_struct *mm;
		mm = get_init_mm();
		spinlock_t *ptl_ptr = NULL;
		pte_t *temppte;
		void *ptrdummy;
		static struct cnthread_inv_msg_ctx send_ctx;
		loff_t test = 20; 

		const struct address_space *mapping = file->f_mapping;

		inode_pages_address = shmem_address[mapping->host->i_ino] + (PAGE_SIZE * (page));

		int cpu_id = get_cpu();

		//spin_lock(&dummy_page_lock);
		spin_lock(&cnthread_inval_send_ack_lock[cpu_id]);


		size_t data_size;
		void *buf = get_dummy_page_dma_addr(cpu_id);
		r = mind_fetch_page_write(inode_pages_address, buf, &data_size);
		if(r == -1){
			spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);
			return -1;
		}

		temppte = ensure_pte(mm, (uintptr_t)get_dummy_page_buf_addr(cpu_id), &ptl_ptr);

		ptrdummy = get_dummy_page_buf_addr(cpu_id);

		//read the data from the page if we don't already have it
		if(readpage){	
			simplefs_kernel_page_write(testp, get_dummy_page_buf_addr(cpu_id), PAGE_SIZE, 0);
		}

		//writes data to that page
		//copy data into dummy buffer, and send to switch
		//simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(cpu_id), PAGE_SIZE, &test);
		
		

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
}

struct page *test_grab_cache_page_write_begin(struct address_space *mapping,
					pgoff_t index, unsigned flags)
{
	struct page *page;
	int fgp_flags = FGP_LOCK|FGP_WRITE|FGP_CREAT;
//removed lock requirement

	if (flags & AOP_FLAG_NOFS)
		fgp_flags |= FGP_NOFS;

	page = pagecache_get_page(mapping, index, fgp_flags,
			mapping_gfp_mask(mapping));


	if (page)
		wait_for_stable_page(page);

	//this is bad but I think it could show where the problem is
	//unlock_page(page);
	//lock_page(page);
	
	/*if (PageLocked(page)){
	}else{
		lock_page(page); //this appears to address the issue
	}*/
	return page;
}

int test_block_write_begin(struct address_space *mapping, loff_t pos, unsigned len,
		unsigned flags, struct page **pagep, get_block_t *get_block)
{
	pgoff_t index = pos >> PAGE_SHIFT;
	struct page *page;
	int status;
	page = test_grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	status = __block_write_begin(page, pos, len, get_block);
	if (unlikely(status)) {
		unlock_page(page);
		put_page(page);
		page = NULL;
	}

	*pagep = page;
	return status;
}

//atomic_t write_count = ATOMIC_INIT(10); 
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


    struct inode *inode = file->f_inode;
    //atomic_inc(&write_count);
    //TODO make sure that the current page thing is correct
    uintptr_t inode_pages_address = shmem_address[mapping->host->i_ino] + (PAGE_SIZE * (currentpage));
	int table_write_locked = 0;
	int page_write_locked = 0;
    //need to do the currentpage thing and not pass in the 
    //actual page since it causes null dereference stuff
    //
   
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(file->f_inode->i_sb);

    int err;
    uint32_t nr_allocs = 0;

    /* Check if the write can be completed (enough space?) */
    if (pos + len > SIMPLEFS_MAX_FILESIZE)
        return -ENOSPC;

    //shouldn't have to worry about size changing here
    nr_allocs = max(pos + len, file->f_inode->i_size) / SIMPLEFS_BLOCK_SIZE;

    if (nr_allocs > file->f_inode->i_blocks - 1)
        nr_allocs -= file->f_inode->i_blocks - 1;
    else
        nr_allocs = 0;
    if (nr_allocs > sbi->nr_free_blocks)
        return -ENOSPC;



    //TODO acquire page lock?	
    /*
    if(!check_coherence(inode, currentpage, mapping, WRITE)){
	    update_coherence(inode, currentpage, mapping, WRITE);
	    invalidate_page_write(file, inode, page);
    }*/


    /* prepare the write */
    err = test_block_write_begin(mapping, pos, len, flags, pagep,
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

    loff_t old_i_size = inode->i_size;
    uintptr_t inode_pages_address = shmem_address[mapping->host->i_ino] + (PAGE_SIZE * (page->index));

    /* Complete the write() */
    int ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);


    if (ret < len) {
	//TODO perform coherence on multiple pages


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

    //invalidate_page_write(file, inode, page);
    //inode_pages_address = shmem_address[mapping->host->i_ino] + (PAGE_SIZE * (page->index));
    //hash_shmem(inode_pages_address, mapping->host->i_ino, page->index, mapping, 1);
    //TODO perform coherence on multiple pages


    
    return ret;

}


/**
 * generic_file_buffered_read - generic file read routine
 * @iocb:       the iocb to read
 * @iter:       data destination
 * @written:    already copied
 *
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 */
static ssize_t simplefs_generic_file_buffered_read(struct kiocb *iocb,
                struct iov_iter *iter, ssize_t written)
{

	struct file *filp = iocb->ki_filp;
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct file_ra_state *ra = &filp->f_ra;
	loff_t *ppos = &iocb->ki_pos;
	pgoff_t index;
	pgoff_t last_index;
	pgoff_t prev_index;
	unsigned long offset;      /* offset into pagecache page */
	unsigned int prev_offset;
	uintptr_t inode_pages_address;
	int error = 0;
	struct page_lock_status temp_status;
	if (unlikely(*ppos >= inode->i_sb->s_maxbytes))
		return 0;
	iov_iter_truncate(iter, inode->i_sb->s_maxbytes);

	index = *ppos >> PAGE_SHIFT;
	prev_index = ra->prev_pos >> PAGE_SHIFT;
	prev_offset = ra->prev_pos & (PAGE_SIZE-1);
	last_index = (*ppos + iter->count + PAGE_SIZE-1) >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct page *page;
		pgoff_t end_index;
		loff_t isize;
		unsigned long nr, ret;

		cond_resched();
		inode_pages_address = shmem_address[mapping->host->i_ino] +
			(PAGE_SIZE * (index));
find_page:
		if (fatal_signal_pending(current)) {
			error = -EINTR;
			goto out;
		}

		page = find_get_page(mapping, index);
		if (!page) {
			if (iocb->ki_flags & IOCB_NOWAIT)
				goto would_block;
			page_cache_sync_readahead(mapping,
					ra, filp,
					index, last_index - index);
			page = find_get_page(mapping, index);
			if (unlikely(page == NULL))
				goto no_cached_page;
		}
		if (PageReadahead(page)) {
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}
		if(!PageRemoteValid(page)){
			//pr_info("page not in shared or modified mode");
			goto page_not_up_to_date;
			//follow steps here similar to PageUptodate
		}
		if (!PageUptodate(page)) {
			if (iocb->ki_flags & IOCB_NOWAIT) {
				put_page(page);
				goto would_block;
			}

			/*
			 * See comment in do_read_cache_page on why
			 * wait_on_page_locked is used to avoid unnecessarily
			 * serialisations and why it's safe.
			 */
			error = wait_on_page_locked_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if(!PageRemoteValid(page)){
				//pr_info("page now not valid");
			}
			if (PageUptodate(page))
				goto page_ok;

			if (inode->i_blkbits == PAGE_SHIFT ||
					!mapping->a_ops->is_partially_uptodate)
				//pr_info("page partially up to date");

				goto page_not_up_to_date;
			/* pipes can't handle partially uptodate pages */
			if (unlikely(iter->type & ITER_PIPE))
				//pr_info("pipes");

				goto page_not_up_to_date;
			if (!trylock_page(page))
				//pr_info("trylock failed");

				goto page_not_up_to_date;
			/* Did it get truncated before we got the lock? */
			if (!page->mapping)
				goto page_not_up_to_date_locked;
			if (!mapping->a_ops->is_partially_uptodate(page,
							offset, iter->count))
				goto page_not_up_to_date_locked;
			unlock_page(page);
		}
page_ok:
		/*
		 * i_size must be checked after we know the page is Uptodate.
		 *
		 * Checking i_size after the check allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */

		/*isize = i_size_read(inode);

		volatile int x = 0;
		volatile int y = 0;
		for(y=0; y < 160000000; y++){
			x += y + y;
		}	
		pr_info("x value is %d", x);
		isize = i_size_read(inode);
		pr_info("after i size read");
	*/	

		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_SHIFT;
		if (unlikely(!isize || index > end_index)) {
			put_page(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset) {
				put_page(page);
				goto out;
			}
		}
		nr = nr - offset;

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When a sequential read accesses a page several times,
		 * only mark it as accessed the first time.
		 */
		if (prev_index != index || offset != prev_offset)
			mark_page_accessed(page);
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 */

		ret = copy_page_to_iter(page, offset, nr, iter);
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
		prev_offset = offset;

		put_page(page);
		written += ret;
		if (!iov_iter_count(iter))
			goto out;
		if (ret < nr) {
			error = -EFAULT;
			goto out;
		}
		continue;

page_not_up_to_date:
		/* Get exclusive access to the page ... */

		//pr_info("acquire page lock 1");
		temp_status = acquire_page_lock(filp, mapping->host, index, inode_pages_address, mapping, READ);
		error = lock_page_killable(page);
		if (unlikely(error))
			goto readpage_error;

page_not_up_to_date_locked:
		/* Did it get truncated before we got the lock? */
		if (!page->mapping) {
			unlock_page(page);
			put_page(page);
			if(temp_status.page_lock){
				up_write(&(temp_status.state->rwsem));
			}else{
				up_read(&(temp_status.state->rwsem));
			}
			continue;
		}
		if(!PageRemoteValid(page)){
			//pr_info("not up to date lock not remote valid");
			goto readpage;
		}

		/* Did somebody else fill it already? */
		if (PageUptodate(page)) {

			unlock_page(page);
			if(temp_status.page_lock){
				up_write(&(temp_status.state->rwsem));
			}else{
				up_read(&(temp_status.state->rwsem));
			}
			goto page_ok;
		}

readpage:
		/*
		 * A previous I/O error may have been due to temporary
		 * failures, eg. multipath errors.
		 * PG_error will be set again if readpage fails.
		 */
		ClearPageError(page);
		/* Start the actual read. The read will unlock the page. */
		error = mapping->a_ops->readpage(filp, page);
		if(temp_status.page_lock){
			up_write(&(temp_status.state->rwsem));
		}else{
			up_read(&(temp_status.state->rwsem));
		}
		if(error == -1337){
			goto find_page;
		}
		if (unlikely(error)) {
			if (error == AOP_TRUNCATED_PAGE) {
				put_page(page);
				error = 0;
				goto find_page;
			}
			goto readpage_error;
		}

		if(!PageRemoteValid(page)){
			//pr_info("should we handle this case?");
			goto find_page;
			//TODO treat this as failing to gain remote access
			//go to the findpage thing and try again
		}

		if (!PageUptodate(page)) {
			error = lock_page_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_mapping_pages got it
					 */
					unlock_page(page);
					put_page(page);
					goto find_page;
				}
				unlock_page(page);
				//shrink_readahead_size_eio(filp, ra);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		put_page(page);
		goto out;

no_cached_page:
		//pr_info("acquire page lock 2");
		temp_status = acquire_page_lock(filp, mapping->host, index, inode_pages_address, mapping, READ);

		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		page = page_cache_alloc(mapping);
		if (!page) {
			//pr_info("DIDN'T HANDLE OUT OF MEMORY");
			error = -ENOMEM;
			goto out;
		}
		error = add_to_page_cache_lru(page, mapping, index,
				mapping_gfp_constraint(mapping, GFP_KERNEL));
		if (error) {
			put_page(page);
			if (error == -EEXIST) {
				error = 0;
				if(temp_status.page_lock){

					up_write(&(temp_status.state->rwsem));
				}else{
					up_read(&(temp_status.state->rwsem));
				}
				goto find_page;
			}
			goto out;
		}
		goto readpage;
	}

would_block:
	error = -EAGAIN;
out:
	ra->prev_pos = prev_index;
	ra->prev_pos <<= PAGE_SHIFT;
	ra->prev_pos |= prev_offset;

	*ppos = ((loff_t)index << PAGE_SHIFT) + offset;
	file_accessed(filp);
	return written ? written : error;
}


ssize_t
simplefs_generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
        size_t count = iov_iter_count(iter);
        ssize_t retval = 0;

        if (!count)
                goto out; /* skip atime */

        if (iocb->ki_flags & IOCB_DIRECT) {
                struct file *file = iocb->ki_filp;
                struct address_space *mapping = file->f_mapping;
                struct inode *inode = mapping->host;
                loff_t size;

                size = i_size_read(inode);
                if (iocb->ki_flags & IOCB_NOWAIT) {
                        if (filemap_range_has_page(mapping, iocb->ki_pos,
                                                   iocb->ki_pos + count - 1))
                                return -EAGAIN;
                } else {
                        retval = filemap_write_and_wait_range(mapping,
                                                iocb->ki_pos,
                                                iocb->ki_pos + count - 1);
                        if (retval < 0)
                                goto out;
                }

                file_accessed(file);

                retval = mapping->a_ops->direct_IO(iocb, iter);
                if (retval >= 0) {
                        iocb->ki_pos += retval;
                        count -= retval;
                }
                iov_iter_revert(iter, count - iov_iter_count(iter));

                /*
                 * Btrfs can have a short DIO read if we encounter
                 * compressed extents, so if there was an error, or if
                 * we've already read everything we wanted to, or if
                 * there was a short read because we hit EOF, go ahead
                 * and return.  Otherwise fallthrough to buffered io for
                 * the rest of the read.  Buffered reads will not work for
                 * DAX files, so don't bother trying.
                 */
                if (retval < 0 || !count || iocb->ki_pos >= size ||
                    IS_DAX(inode))
                        goto out;
        }

        retval = simplefs_generic_file_buffered_read(iocb, iter, retval);
out:
        return retval;
}


ssize_t
simplefs_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	size_t count = iov_iter_count(iter);
	ssize_t retval = 0;

	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	int pageindex;




	//up here to avoid deadlock
	//TODO rewrite the kernel_read function 
	//so that it doesn't go back into the
	//simplefs read iter function
	



	/*      ~*~       */ //TODO REMOVE THIS
	//inode_lock(inode);
	/*      ~*~       */

	//stolen from mm/filemap.c
	loff_t *ppos = &iocb->ki_pos;
	unsigned int index = *ppos >> PAGE_SHIFT;
	unsigned int last_index = (*ppos + iter->count + PAGE_SIZE-1) >> PAGE_SHIFT; 
	unsigned int offset = *ppos & ~PAGE_MASK;	
	unsigned int count_test = iter->count;



	//invalidating the page
	//callinvalidatepage(inode->i_ino, index, 1);

	/*
	for(pageindex = index; pageindex <= last_index; pageindex++){
                struct page *page = find_get_page(mapping, index);
                if(page != 0){
                        //ClearPageUptodate(page);
                }
        }
	*/

	retval = simplefs_generic_file_read_iter(iocb, iter);


	//**** reading into vector type 0, length 8192 ki_flags 0 ki_hint 0 nr_segs 0 ki_pos 1



	int i;
	char * base = ((iter->iov)->iov_base);


	
	/*      ~*~       */
	//inode_unlock(inode);
	/*      ~*~       */
	return retval;

}




u64 page_shmem_address_check(void *addr, unsigned long size)
{


	//TODO this should be surrounded by locks
    down_read(&hash_page_rwsem);
    struct  shmem_coherence_state * coherence_state = shmem_in_hashmap(addr);
    up_read(&hash_page_rwsem);
    if(coherence_state != NULL){
	    return 1;
    }else{
    }
	
    return 0;
}



static bool shmem_invalidate_page_write(struct address_space * mapping, struct page * pagep, int page_index, void *inv_argv){

        struct page * testp = pagep;
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
        inode_pages_address = shmem_address[mapping->host->i_ino] + (PAGE_SIZE * (page_index));
	
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
	if(testp == NULL){	
	}else{
        	simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(cpu_id), PAGE_SIZE, &test);
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


static bool shmem_invalidate(struct shmem_coherence_state * coherence_state, void *inv_argv){

	void *pagep;

	//acquire write lock on page

	struct address_space *mapping = coherence_state->mapping;

	//lock hashtable	
	//spin_lock(&shmem_states_lock);

	//lock page tree

	//spin_lock_irq(&mapping->tree_lock);

	//delete page from page cache
	//trying to mess with stuff from the page tree
	//this is stolen from find_get_entry in filemap.c
	//spin locks stolen from fs/nilfs2/page.c 
	pagep = find_get_page(mapping, coherence_state->pagenum);
		
		//radix_tree_lookup(&mapping->page_tree, coherence_state->pagenum);
	if(pagep){
		//we don't need to lock the page 
		//lock_page(pagep);

		if(!PageUptodate(pagep)){
			pr_info("PAGE NOT UP TO DATE?");
		}
		struct page * testp = pagep;
		
		//perform page invalidation stuff here
		shmem_invalidate_page_write(coherence_state->mapping, testp, coherence_state->pagenum, inv_argv);
		//delete_from_page_cache(testp);
		//pr_info("before page invalidated %d", PageRemoteValid(testp));

		//mark page as invalid from remote system
		ClearPageRemoteValid(testp);
		//pr_info("page invalidated %d", PageRemoteValid(testp));
		ClearPageUptodate(testp);
		
		//ClearPageDirty(testp);
		//SetPageError(testp);
		coherence_state->state = 0;
		//pr_info("inode size was %d", coherence_state->mapping->host->i_size);

		//delete_from_page_cache(testp);
		//unlock_page(pagep);
	}else{
		struct page * testp = NULL;
		//this can also be reached if something has been truncated
		shmem_invalidate_page_write(coherence_state->mapping, testp, coherence_state->pagenum, inv_argv);
		pr_info("LOST PAGE");
		if(coherence_state->mapping->host->i_size != 0){
			pr_info("file length wasn't zero");
			if(coherence_state->mapping->host->i_size < coherence_state->pagenum * 4096){
				pr_info("file has shrunk smaller than this page location");
			}else{
				pr_info("should we have been able to find the page here?");
			}
		}
		
		//print out the size of the inode
		//pr_info("inode size was %d", coherence_state->mapping->host->i_size);
		coherence_state->state = 0;

	}
	//delete page from the hashmap
	//hash_del(&(coherence_state->link));

	//spin_unlock_irq(&mapping->tree_lock);
        //spin_unlock(&shmem_states_lock);
	return true;

}


u64 page_testing_invalidate_page_callback(void *addr, void *inv_argv)
{

	//pr_info("started invalidation");
    down_read(&hash_page_rwsem);
    struct shmem_coherence_state * coherence_state = shmem_in_hashmap(addr);

    if(coherence_state != NULL){

	    down_write(&(coherence_state->rwsem)); //lock the page
	    up_read(&hash_page_rwsem); //unlock the hashtable now
	    shmem_invalidate(coherence_state, inv_argv);
	    up_write(&(coherence_state->rwsem)); //lock the page
    }else{
	    up_read(&hash_page_rwsem);

    }
    //pr_info("ended invalidation");
    return 1024;
}


ssize_t simplefs_generic_perform_write(struct file *file,
				struct iov_iter *i, loff_t pos)
{
	struct address_space *mapping = file->f_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	long status = 0;
	ssize_t written = 0;
	unsigned int flags = 0;

	do {
		struct page *page;
		unsigned long offset;	/* Offset into pagecache page */
		unsigned long bytes;	/* Bytes to write to page */
		size_t copied;		/* Bytes copied from user */
		void *fsdata;

		offset = (pos & (PAGE_SIZE - 1));
		bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_count(i));

again:
		/*
		 * Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 *
		 * Not only is this an optimisation, but it is also required
		 * to check that the address is actually valid, when atomic
		 * usercopies are used, below.
		 */
		if (unlikely(iov_iter_fault_in_readable(i, bytes))) {
			status = -EFAULT;
			break;
		}

		if (fatal_signal_pending(current)) {
			status = -EINTR;
			break;
		}

		//do locking stuff here
		unsigned int currentpage = pos / PAGE_SIZE;
		struct inode * inode = mapping->host;
		uintptr_t inode_pages_address;
		inode_pages_address = shmem_address[inode->i_ino] +
			(PAGE_SIZE * (currentpage));

retry:
		currentpage = currentpage;
		struct page_lock_status temp = acquire_page_lock(file, inode, currentpage, inode_pages_address, mapping, WRITE);
		//if page lock was acquired in write mode, then we have to update the remote state

		//need to copy in the most up to date version of the page




		status = a_ops->write_begin(file, mapping, pos, bytes, flags,
						&page, &fsdata);

		if (unlikely(status < 0)){

			break;
		}

		if (mapping_writably_mapped(mapping)){
			flush_dcache_page(page);

		}

	
		/*	
		//request access to the page here
		if(temp.old_state < READ){

			//request in read mode, and copy the data over
			int cpu_id = get_cpu();

			spin_lock(&cnthread_inval_send_ack_lock[cpu_id]);

			//spin_lock(&dummy_page_lock);
			// TODO(stutsman): Why are we bothering with per-cpu buffers if we have
			// a single lock around all of them here. Likely we want a per-cpu
			// spinlock.
			size_t data_size;
			void *buf = get_dummy_page_dma_addr(cpu_id);
			int r = mind_fetch_page(inode_pages_address, buf, &data_size);
			BUG_ON(r);
			simplefs_kernel_page_write(page, get_dummy_page_buf_addr(cpu_id), PAGE_SIZE, 0);

			//adds page to hashmap if not already in hashmap
			//update_coherence(mapping->host, page->index, mapping, READ);


			spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);
			//spin_unlock(&dummy_page_lock);
			//unlock_page(page);


		}*/
		int result = 0;
		if (temp.old_state < WRITE){
			if(temp.old_state < READ){
				//request access to page and then read the page 
				//if we don't have in read mode then we are missing data
				result = invalidate_page_write(page, file, inode, currentpage, true);
			}else{
				result = invalidate_page_write(page, file, inode, currentpage, false);
			}
		}
		if(result == -1){
			//should probably only do this when we have it
			//in write mode
			temp.state->state = temp.old_state;
			if(temp.page_lock){
				up_write(&(temp.state->rwsem));
			}else{
				up_read(&(temp.state->rwsem));
			}
			ClearPageRemoteValid(page);
			unlock_page(page);

			goto retry;

		}

		//TODO add retry on failure
		//I think we should just unlock the rwsem 
		//and not require invalidations to
		//acquire the page lock
		//they could just handle it as a read
		SetPageRemoteValid(page);

		//TODO on failure mark the page as not remote valid


		copied = iov_iter_copy_from_user_atomic(page, i, offset, bytes);

		flush_dcache_page(page);

		status = a_ops->write_end(file, mapping, pos, bytes, copied,
						page, fsdata);
		//unlocking the page here
		if(temp.page_lock){
			up_write(&(temp.state->rwsem));
		}else{
			up_read(&(temp.state->rwsem));
		}


		if (unlikely(status < 0))
			break;
		copied = status;

		cond_resched();

		iov_iter_advance(i, copied);
		if (unlikely(copied == 0)) {
			/*
			 * If we were unable to copy any data at all, we must
			 * fall back to a single segment length write.
			 *
			 * If we didn't fallback here, we could livelock
			 * because not all segments in the iov can be copied at
			 * once without a pagefault.
			 */
			bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_single_seg_count(i));
			goto again;
		}
		pos += copied;
		written += copied;

		balance_dirty_pages_ratelimited(mapping);
	} while (iov_iter_count(i));

	return written ? written : status;
}

ssize_t __simplefs_generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	struct inode 	*inode = mapping->host;
	ssize_t		written = 0;
	ssize_t		err;
	ssize_t		status;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);
	err = file_remove_privs(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

	if (iocb->ki_flags & IOCB_DIRECT) {
		loff_t pos, endbyte;

		written = generic_file_direct_write(iocb, from);
		/*
		 * If the write stopped short of completing, fall back to
		 * buffered writes.  Some filesystems do this for writes to
		 * holes, for example.  For DAX files, a buffered write will
		 * not succeed (even if it did, DAX does not handle dirty
		 * page-cache pages correctly).
		 */
		if (written < 0 || !iov_iter_count(from) || IS_DAX(inode))
			goto out;

		status = simplefs_generic_perform_write(file, from, pos = iocb->ki_pos);
		/*
		 * If generic_perform_write() returned a synchronous error
		 * then we want to return the number of bytes which were
		 * direct-written, or the error code if that was zero.  Note
		 * that this differs from normal direct-io semantics, which
		 * will return -EFOO even if some bytes were written.
		 */
		if (unlikely(status < 0)) {
			err = status;
			goto out;
		}
		/*
		 * We need to ensure that the page cache pages are written to
		 * disk and invalidated to preserve the expected O_DIRECT
		 * semantics.
		 */
		endbyte = pos + status - 1;
		err = filemap_write_and_wait_range(mapping, pos, endbyte);
		if (err == 0) {
			iocb->ki_pos = endbyte + 1;
			written += status;
			invalidate_mapping_pages(mapping,
						 pos >> PAGE_SHIFT,
						 endbyte >> PAGE_SHIFT);
		} else {
			/*
			 * We don't know how much we wrote, so just return
			 * the number of bytes which were direct-written
			 */
		}
	} else {
		written = simplefs_generic_perform_write(file, from, iocb->ki_pos);
		if (likely(written > 0))
			iocb->ki_pos += written;
	}
out:
	current->backing_dev_info = NULL;
	return written ? written : err;
}

ssize_t simplefs_generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;
//	inode_lock(inode);
//	ret = generic_write_checks(iocb, from);

	down_write(&inode->i_rwsem);
	bool write = false;
	int cur_size = i_size_read(inode);
	//this was borrowed from elsewhere in the kernel
	int new_size = iocb->ki_pos + iov_length(from->iov, from->nr_segs);
	//taken from generic_write_checks

	//if we shrunk the size it should have already occurred
	//we shouldn't be shrinking the size in here right?	
	if ((new_size > cur_size)|| (iocb->ki_flags & IOCB_APPEND)){
		//pr_info("size will change");
		//spin_unlock(spin_inode_lock[inode->i_ino]); //remote sync 
		write = true;
	}	

	while(1){
	//first try to acquire remote inode lock in read mode 	
	lock_loop(inode->i_ino, write);

	if(!write){
		//double check to make sure the size didn't change
		if ((new_size > cur_size)|| (iocb->ki_flags & IOCB_APPEND)){
			//pr_info("size will change");
			up_write(inode_rwlock[inode->i_ino]);	
			write = true;
			continue;
		}
	}
	break;
	}
	//generic_write_checks will realign stuff if 
	//we are trying to append to the end
	ret = generic_write_checks(iocb, from);

	if (ret > 0)
		ret = __simplefs_generic_file_write_iter(iocb, from);

	up_write(inode_rwlock[inode->i_ino]);	
		
		
	up_write(&inode->i_rwsem);
//this WAS BUGGED

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}


void simplefs_invalidatepage (struct page * p, unsigned int x, unsigned int y){
	//pr_info("invalidating page %d", p->index);

}

const struct address_space_operations simplefs_aops = {
    .readpage = simplefs_readpage,
    .writepage = simplefs_writepage,
    .write_begin = simplefs_write_begin,
    .write_end = simplefs_write_end,
    .invalidatepage = simplefs_invalidatepage,
};

const struct file_operations simplefs_file_ops = {
    .llseek = generic_file_llseek,
    .owner = THIS_MODULE,
    .read_iter = simplefs_file_read_iter,
    .write_iter = simplefs_generic_file_write_iter,
    .fsync = generic_file_fsync,
};

