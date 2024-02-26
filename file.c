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
// Each dummy buffer is per-core, but this prevents context switches and
// thread migrations from causing races to the buffers.
DEFINE_SPINLOCK(dummy_page_lock);

#define READ 1
#define WRITE 2

static spinlock_t cnthread_inval_send_ack_lock[DISAGG_NUM_CPU_CORE_IN_COMPUTING_BLADE];


struct shmem_coherence_state {
    	unsigned long shmem_addr;
	unsigned long i_ino;
	struct inode * inode;
	int pagenum;
	int state;
	struct address_space *mapping;
	struct hlist_node link;
};



DEFINE_HASHTABLE(shmem_states, 8); // 8 = 256 buckets
// Protects shmem_states and everything it references.
DEFINE_SPINLOCK(shmem_states_lock);

DEFINE_HASHTABLE(inode_states, 8); // 8 = 256 buckets
// Protects shmem_states and everything it references.
DEFINE_SPINLOCK(inode_states_lock);



static void hash_shmem(unsigned long shmem_addr, int inodenum, int pagenum, struct address_space *mapping, int state) {
	//pr_info("adding shmem information to hashtable");
	struct shmem_coherence_state *shmem_state;
	//refer more to Documentation/kernel-hacking/hacking.rst
	shmem_state = kmalloc(sizeof(struct shmem_coherence_state), GFP_KERNEL);
	shmem_state->i_ino = inodenum;
	shmem_state->pagenum = pagenum;
	shmem_state->mapping = mapping;
	shmem_state->state = state;
	shmem_state->shmem_addr = shmem_addr;

	spin_lock(&shmem_states_lock);
	hash_add(shmem_states, &(shmem_state->link), shmem_addr);
	spin_unlock(&shmem_states_lock);
}

static void inode_hash_shmem(unsigned long inode_addr, int inodenum, struct inode * inode, int state) {
	//pr_info("adding shmem information to hashtable");
	struct shmem_coherence_state *shmem_state;
	//refer more to Documentation/kernel-hacking/hacking.rst
	shmem_state = kmalloc(sizeof(struct shmem_coherence_state), GFP_KERNEL);
	shmem_state->i_ino = inodenum;
	shmem_state->inode = inode;
	shmem_state->state = state;
	shmem_state->shmem_addr = inode_addr;

	spin_lock(&inode_states_lock);
	hash_add(inode_states, &(shmem_state->link), inode_addr);
	spin_unlock(&inode_states_lock);
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
	spin_lock(&shmem_states_lock);

	hash_for_each(shmem_states, i, tempshmem, link) {
		if(tempshmem->shmem_addr == shmem_addr){ 
			//unlocking the spin lock
			spin_unlock(&shmem_states_lock);
			return tempshmem; //current;
		}
	}	

	//unlocking the spin lock
	spin_unlock(&shmem_states_lock);

	return NULL; //NULL;

}

static struct shmem_coherence_state * inode_shmem_in_hashmap(unsigned long inode_addr) {
	struct shmem_coherence_state *tempshmem;
	int i = inode_addr;

	//TODO make sure that page is still valid, and hasn't been removed from cache

	//locking the spin lock
	spin_lock(&inode_states_lock);

	hash_for_each(inode_states, i, tempshmem, link) {
		if(tempshmem->shmem_addr == inode_addr){ 
			//unlocking the spin lock
			spin_unlock(&inode_states_lock);
			return tempshmem; //current;
		}
	}	

	//unlocking the spin lock
	spin_unlock(&inode_states_lock);

	return NULL; //NULL;

}





extern unsigned long shmem_address[10];
extern unsigned long inode_address[10];

static void mind_pr_cache_dir_state(const char* msg,
	unsigned long start_time, uintptr_t shmem_address,
	unsigned long ack_counter, unsigned long target_counter)
{
	u16 state, sharer, dir_size, dir_lock, inv_cnt;
	send_cache_dir_full_always_check(
		DISAGG_KERN_TGID, shmem_address, &state, &sharer,
		&dir_size, &dir_lock, &inv_cnt, CN_SWITCH_REG_SYNC_NONE);
	//pr_info("%s - cpu :%d, tgid: %u, addr: 0x%lx, ack_cnt: %ld, tar_cnt: %ld, timeout (%u ms) / state: 0x%x, sharer: 0x%x\n",
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

	//pr_info("mind_fetch_page(shmem_address = 0x%lx, "
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
	//pr_info("sending pfault to mn done");
	wait_node->ack_buf = ret_buf.ack_buf;

	pr_pgfault("CN [%d]: start waiting 0x%lx\n", get_cpu(), shmem_address);
	if(r <= 0)
		cancel_waiting_for_nack(wait_node);
	r = wait_ack_from_ctrl(wait_node, NULL, NULL, NULL);

	//mind_pr_cache_dir_state(
	//	"AFTER PFAULT ACK/NACK",
	//	start_time, shmem_address,
	//	atomic_read(&wait_node->ack_counter),
	//	atomic_read(&wait_node->target_counter));
	
	data_size = ret_buf.data_size;
	return 0;
}

static int mind_fetch_page_write(
        uintptr_t shmem_address, void *page_dma_address, size_t *data_size)
{
        struct fault_reply_struct ret_buf;
        struct cache_waiting_node *wait_node = NULL;
        int r;
        unsigned long start_time = jiffies;

	spin_lock(&dummy_page_lock);

        ret_buf.data_size = PAGE_SIZE;
        ret_buf.data = page_dma_address;

        //pr_info("mind_fetch_page(shmem_address = 0x%lx, "
        //        "page_dma_address = %p)", shmem_address, page_dma_address);

        wait_node = add_waiting_node(DISAGG_KERN_TGID, shmem_address, NULL);
        BUG_ON(!wait_node);
	
	spin_unlock(&dummy_page_lock);

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
        //pr_info("sending pfault to mn done");
        wait_node->ack_buf = ret_buf.ack_buf;

        pr_pgfault("CN [%d]: start waiting 0x%lx\n", get_cpu(), shmem_address);
        if(r <= 0)
                cancel_waiting_for_nack(wait_node);
        r = wait_ack_from_ctrl(wait_node, NULL, NULL, NULL);

        //mind_pr_cache_dir_state(
        //        "AFTER PFAULT ACK/NACK",
        //        start_time, shmem_address,
        //        atomic_read(&wait_node->ack_counter),
        //        atomic_read(&wait_node->target_counter));

        data_size = ret_buf.data_size;
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

	//pr_info("update coherence called");
    //TODO add hashtable locks

    //TODO at the moment shmem_in_hashmap acquires the locks, we might just 
    //want to move that lock acquiring to be outside of that function so that
    //we can have it here so that we can read something from the hashmap and modify
    //it without another thread messing it up
    struct shmem_coherence_state * coherence_state = shmem_in_hashmap(inode_pages_address);
    if(coherence_state == NULL){
        //page not in hashmap
        hash_shmem(inode_pages_address, mapping->host->i_ino, page, mapping, reqstate);
	//pr_info("page not in hashmap adding with state %c", reqstate);

    }else{
	//pr_info("page in hashmap, updating state %c", reqstate);

	    if(coherence_state->state == WRITE){
		    return;
	    }else{
		    if(reqstate == WRITE){
			    coherence_state->state = WRITE;
		    }
	    }
    }
} 

static void update_inode_coherence(struct inode * inode, int reqstate) {
	uintptr_t inode_pages_address = inode_address[inode->i_ino];

    //TODO add hashtable locks

    //TODO at the moment shmem_in_hashmap acquires the locks, we might just 
    //want to move that lock acquiring to be outside of that function so that
    //we can have it here so that we can read something from the hashmap and modify
    //it without another thread messing it up
    struct shmem_coherence_state * coherence_state = inode_shmem_in_hashmap(inode_pages_address);
    if(coherence_state == NULL){
        //page not in hashmap
        inode_hash_shmem(inode_pages_address, inode->i_ino, inode, reqstate);
	pr_info("inode not in hashmap adding with state %c", reqstate);

    }else{
	pr_info("inode in hashmap, updating state %c", reqstate);

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

	const struct address_space *mapping = file->f_mapping;

	//pr_info("readpage ino %ld page %ld", mapping->host->i_ino, page->index);
        //TODO insert into shmem_states

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
	simplefs_kernel_page_write(page, get_dummy_page_buf_addr(get_cpu()), PAGE_SIZE, 0);
	
	//adds page to hashmap if not already in hashmap
	update_coherence(mapping->host, page->index, mapping, READ);


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


static bool invalidate_page_write(struct file *file, struct inode * inode, struct page * pagep){

	//pr_info("invalidate_page_write 1");
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
	//pr_info("invalidate_page_write 2");

        const struct address_space *mapping = file->f_mapping;

        inode_pages_address = shmem_address[mapping->host->i_ino] + (PAGE_SIZE * (pagep->index));

	int cpu_id = get_cpu();
	spin_lock(&cnthread_inval_send_ack_lock[cpu_id]);

        //spin_lock(&dummy_page_lock);
       	//pr_info("invalidate_page_write 3");

        size_t data_size;
        void *buf = get_dummy_page_dma_addr(get_cpu());
        r = mind_fetch_page_write(inode_pages_address, buf, &data_size);
        BUG_ON(r);

        temppte = ensure_pte(mm, (uintptr_t)get_dummy_page_buf_addr(get_cpu()), &ptl_ptr);

        ptrdummy = get_dummy_page_buf_addr(get_cpu());
	//pr_info("invalidate_page_write 4");

        //writes data to that page
        //copy data into dummy buffer, and send to switch
        simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(get_cpu()), PAGE_SIZE, &test);
        
	//int i;
        //for(i = 0; i < 20; i++){
        //        pr_info("testing invalidate write %c", ((char*)get_dummy_page_buf_addr(get_cpu()))[i]);
        //}

	//pr_info("invalidate_page_write 5");

        //spin_lock(ptl_ptr);

        //cn_copy_page_data_to_mn(DISAGG_KERN_TGID, mm, inode_pages_address,
        //temppte, CN_OTHER_PAGE, 0, buf);
        //pr_info("invalidate_page_write 6");

        //cnthread_send_finish_ack(DISAGG_KERN_TGID, inode_pages_address, &send_ctx, 0);

        // spin_unlock(ptl_ptr);
        //spin_unlock(&dummy_page_lock);
	spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);

        //spin_unlock_irq(&mapping->tree_lock);

        return true;
}

static bool request_inode_write(unsigned long ino){

        uintptr_t inode_pages_address;
        int r;
        struct mm_struct *mm;
        mm = get_init_mm();
        spinlock_t *ptl_ptr = NULL;
        pte_t *temppte;
        void *ptrdummy;
        static struct cnthread_inv_msg_ctx send_ctx;
        loff_t test = 20; 
        inode_pages_address = inode_address[ino];

	int cpu_id = get_cpu();
	spin_lock(&cnthread_inval_send_ack_lock[cpu_id]);

        size_t data_size;
        void *buf = get_dummy_page_dma_addr(get_cpu());
        r = mind_fetch_page_write(inode_pages_address, buf, &data_size);
        BUG_ON(r);

        temppte = ensure_pte(mm, (uintptr_t)get_dummy_page_buf_addr(get_cpu()), &ptl_ptr);

        ptrdummy = get_dummy_page_buf_addr(get_cpu());
	/*
	unsigned long * i_size_buf = (unsigned long*)get_dummy_page_buf_addr(get_cpu()); 
        i_size_buf[0] = i_size;

	//simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(get_cpu()), PAGE_SIZE, &test);
        
        struct cnthread_rdma_msg_ctx *rdma_ctx = NULL;
        struct cnthread_inv_msg_ctx *inv_ctx = &((struct cnthread_inv_argv *)inv_argv)->inv_ctx;

        rdma_ctx = &inv_ctx->rdma_ctx;
        inv_ctx->original_qp = (rdma_ctx->ret & CACHELINE_ROCE_RKEY_QP_MASK) >> CACHELINE_ROCE_RKEY_QP_SHIFT;
        create_invalidation_rdma_ack(inv_ctx->inval_buf, rdma_ctx->fva, rdma_ctx->ret, rdma_ctx->qp_val);
        *((u32 *)(&(inv_ctx->inval_buf[CACHELINE_ROCE_VOFFSET_TO_IP]))) = rdma_ctx->ip_val;

        //pr_info("inv_ctx->original_qp %d", inv_ctx->original_qp);

        u32 req_qp = (get_id_from_requester(inv_ctx->rdma_ctx.requester) * DISAGG_QP_PER_COMPUTE) + inv_ctx->original_qp;
        //pr_info("req_qp %d", req_qp);

        //pr_info("before cn_copy_page");
        cn_copy_page_data_to_mn(DISAGG_KERN_TGID, mm, inode_pages_address,
        temppte, CN_TARGET_PAGE, req_qp, buf);
        //pr_info("after cn_copy_page");

        //pr_info("before inval ack");
        //pr_info("inv_ctx->inval_buf %d", inv_ctx->inval_buf);
        _cnthread_send_inval_ack(DISAGG_KERN_TGID, inode_pages_address, inv_ctx->inval_buf);
        //pr_info("after inval ack");

        //pr_info("before FinACK");
        cnthread_send_finish_ack(DISAGG_KERN_TGID, inode_pages_address, inv_ctx, 1);
        //pr_info("after FinACK");
	*/
        spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);
	
        return true;
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
    //pr_info("write begin page number %d end page number %d, for inode %ld write pos %d  write length %d", currentpage, lastpage, (file->f_inode)->i_ino, pos, len);


    struct inode *inode = file->f_inode;


    //need to do the currentpage thing and not pass in the 
    //actual page since it causes null dereference stuff
    //
    
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
    uintptr_t inode_pages_address;
    unsigned int currentpage = pos / PAGE_SIZE;

    loff_t old_i_size = inode->i_size;
    
    /* Complete the write() */
    int ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);


    if (ret < len) {
        pr_err("wrote less than requested.");
	//TODO perform coherence on multiple pages
	
	//check size 	
	if(old_i_size != inode->i_size){
		//TODO perform inode size coherence here
		request_inode_write(inode->i_ino);
		update_inode_coherence(inode, WRITE);
	}
		
	if(!check_coherence(inode, currentpage, mapping, WRITE)){
		invalidate_page_write(file, inode, page);
		update_coherence(inode, currentpage, mapping, WRITE);
	}


        //hash_shmem(inode_pages_address, mapping->host->i_ino, page->index, mapping, 1);
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
    
    //check size 	
    if(old_i_size != inode->i_size){
	    //TODO perform inode size coherence here
	    request_inode_write(inode->i_ino);
	    }
    if(!check_coherence(inode, currentpage, mapping, WRITE)){
	    invalidate_page_write(file, inode, page);
	    update_coherence(inode, currentpage, mapping, WRITE);
    }


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
        //pr_info("inside simplefs_generic_file_buffered_read\n");
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
        int error = 0;

        if (unlikely(*ppos >= inode->i_sb->s_maxbytes))
                return 0;
        iov_iter_truncate(iter, inode->i_sb->s_maxbytes);

        index = *ppos >> PAGE_SHIFT;
        prev_index = ra->prev_pos >> PAGE_SHIFT;
        prev_offset = ra->prev_pos & (PAGE_SIZE-1);
        last_index = (*ppos + iter->count + PAGE_SIZE-1) >> PAGE_SHIFT;
        offset = *ppos & ~PAGE_MASK; //offset into the page

        for (;;) {
                struct page *page;
                //pr_info("looping page index %d offset %d\n", index, offset);
                pgoff_t end_index;
                loff_t isize;
                unsigned long nr, ret;

                cond_resched();
find_page:
                //pr_info("find page\n");

                page = find_get_page(mapping, index);
                //ClearPageUptodate(page);


                if (!page) {
                        //pr_info("no page found from findgetpage\n");
                        if (iocb->ki_flags & IOCB_NOWAIT)
                                goto would_block;
                        page_cache_sync_readahead(mapping,
                                        ra, filp,
                                        index, last_index - index);
                        page = find_get_page(mapping, index);
                        if (unlikely(page == NULL))
                                goto no_cached_page;
                }
                //pr_info("page found is %d\n", page);
                if (PageReadahead(page)) {
                        page_cache_async_readahead(mapping,
                                        ra, filp, page,
                                        index, last_index - index);
                        //pr_info("sync readahead\n");

                }
                if (!PageUptodate(page)) {
                        //pr_info("page not up to date\n");
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
                        if (PageUptodate(page))
                                goto page_ok;

                        if (inode->i_blkbits == PAGE_SHIFT ||
                                        !mapping->a_ops->is_partially_uptodate)
                                goto page_not_up_to_date;
                        /* pipes can't handle partially uptodate pages */
                        if (unlikely(iter->type & ITER_PIPE))
                                goto page_not_up_to_date;
                        if (!trylock_page(page))
                                goto page_not_up_to_date;
                        /* Did it get truncated before we got the lock? */
                        if (!page->mapping)
                                goto page_not_up_to_date_locked;
                        if (!mapping->a_ops->is_partially_uptodate(page,
                                                        offset, iter->count))
                                goto page_not_up_to_date_locked;
                        unlock_page(page);
                }
                //pr_info("page was marked up to date\n");
page_ok:
                //pr_info("page_ok \n");
                /*
                 * i_size must be checked after we know the page is Uptodate.
                 *
                 * Checking i_size after the check allows us to calculate
                 * the correct value for "nr", which means the zero-filled
                 * part of the page is not copied back to userspace (unless
                 * another truncate extends the file - this is desired though).
                 */

                isize = i_size_read(inode);
                end_index = (isize - 1) >> PAGE_SHIFT;
                if (unlikely(!isize || index > end_index)) {
                        //pr_info("size difference\n");
                        put_page(page);
                        goto out;
                }

                /* nr is the maximum number of bytes to copy from this page */
                nr = PAGE_SIZE;
                if (index == end_index) {  //current page and last page

                        nr = ((isize - 1) & ~PAGE_MASK) + 1; //inode size (8kb? - 1)
                        if (nr <= offset) { //if nr <= offset into page
                                //pr_info("offset not right nr was %d offset %d isize %d\n", nr, offset, isize);
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
                //pr_info("data being copied to page here \n");
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
                //pr_info("page not up to date\n");
                /* Get exclusive access to the page ... */
                error = lock_page_killable(page);
                if (unlikely(error))
                        goto readpage_error;

page_not_up_to_date_locked:
                //pr_info("page not up to date locked\n");
                /* Did it get truncated before we got the lock? */
                if (!page->mapping) {
                        unlock_page(page);
                        put_page(page);
                        continue;
                }

                /* Did somebody else fill it already? */
                if (PageUptodate(page)) {
                        unlock_page(page);
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
                //pr_info("after readpage called \n");
                //pr_info("going to page_ok\n");
                goto page_ok;

readpage_error:
                //pr_info("read page error \n");
                /* UHHUH! A synchronous read error occurred. Report it */
                put_page(page);
                goto out;

no_cached_page:
                //pr_info("no cached page \n");
                /*
                 * Ok, it wasn't cached, so we need to create a new
                 * page..
                 */
                page = page_cache_alloc(mapping);
                if (!page) {
                        error = -ENOMEM;
                        goto out;
                }
                error = add_to_page_cache_lru(page, mapping, index,
                                mapping_gfp_constraint(mapping, GFP_KERNEL));
                if (error) {
                        put_page(page);
                        if (error == -EEXIST) {
                                error = 0;
                                goto find_page;
                        }
                        goto out;
                }
                goto readpage;
        }

would_block:
        //pr_info("would_block\n");
        error = -EAGAIN;
out:
        ra->prev_pos = prev_index;
        ra->prev_pos <<= PAGE_SHIFT;
        ra->prev_pos |= prev_offset;

        *ppos = ((loff_t)index << PAGE_SHIFT) + offset;
        file_accessed(filp);
        //pr_info("leaving generic_file_buffered_read\n");
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


	//pr_info("read ki_pos %d", iocb->ki_pos);


	//pr_info("read ki_pos %d", iocb->ki_pos);
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
	//pr_info("**********index is %d last index is %d offset is %d count is %d", index, last_index, offset, count_test);


	//pr_info("*****beginning read inode %d page %d", inode->i_ino, index);

	//invalidating the page
	//callinvalidatepage(inode->i_ino, index, 1);

	/*
	for(pageindex = index; pageindex <= last_index; pageindex++){
                pr_info("page index attempting to invalidate is %d\n", pageindex);
                struct page *page = find_get_page(mapping, index);
                pr_info("getting page pointer in file read iter %d\n", page);
                if(page != 0){
                        //ClearPageUptodate(page);
                        pr_info("marking page %d out of date\n", pageindex);
                }
        }
	*/

	retval = simplefs_generic_file_read_iter(iocb, iter);

   	//pr_info("**** reading into vector type %d, length %d ki_flags %d ki_hint %d nr_segs %d ki_pos %d", iter->type, (iter->iov)->iov_len, iocb->ki_flags, iocb->ki_flags, iocb->ki_hint, iter->nr_segs, iocb->ki_pos);

	//**** reading into vector type 0, length 8192 ki_flags 0 ki_hint 0 nr_segs 0 ki_pos 1



	int i;
	char * base = ((iter->iov)->iov_base);


	
	/*      ~*~       */
	//inode_unlock(inode);
	/*      ~*~       */
	//pr_info("****ending read");
	return retval;

}




u64 shmem_address_check(void *addr, unsigned long size)
{

    //pr_info("tesing shmem address callback");
    //pr_info("tesing shmem address callback");
    //pr_info("tesing shmem address callback");
    //pr_info("tesing shmem address callback");
    //pr_info("tesing shmem address callback");
    struct  shmem_coherence_state * coherence_state = shmem_in_hashmap(addr);
    if(coherence_state != NULL){
	    //pr_info("shmem was in hash table");
	    //pr_info("shmem address %ld", coherence_state->shmem_addr);
	    //pr_info("shmem i_ino %d", coherence_state->i_ino);
	    //pr_info("shmem pagenum %d", coherence_state->pagenum);
	    //pr_info("shmem coherence state %d", coherence_state->state);
	    return 1;
    }else{
	    //pr_info("shmem was not in the hashtable");
    }

	//check to see if it is in the inode hashmap
    coherence_state = inode_shmem_in_hashmap(addr);
    if(coherence_state != NULL){
	    pr_info("shmem was in inode hash table");
	    //pr_info("shmem address %ld", coherence_state->shmem_addr);
	    //pr_info("shmem i_ino %d", coherence_state->i_ino);
	    //pr_info("shmem pagenum %d", coherence_state->pagenum);
	    //pr_info("shmem coherence state %d", coherence_state->state);
	    return 1;
    }else{
	    //pr_info("shmem was not in the hashtable");
    }

    return 0;
}



static bool shmem_invalidate_inode_write(struct inode * inode, void *inv_argv){

        struct mm_struct *mm;
        mm = get_init_mm();
        spinlock_t *ptl_ptr = NULL;
        pte_t *temppte;
        void *ptrdummy;
        static struct cnthread_inv_msg_ctx send_ctx;
        loff_t test = 20; 
	int i;
	uintptr_t inode_pages_address = shmem_address[inode->i_ino]; 

	int cpu_id = get_cpu();

        //spin_lock(&dummy_page_lock);
        spin_lock(&cnthread_inval_send_ack_lock[cpu_id]);

        size_t data_size;
        void *buf = get_dummy_page_dma_addr(get_cpu());
        //r = mind_fetch_page_write(inode_pages_address, buf, &data_size);
        //BUG_ON(r);

        temppte = ensure_pte(mm, (uintptr_t)get_dummy_page_buf_addr(get_cpu()), &ptl_ptr);

        ptrdummy = get_dummy_page_buf_addr(get_cpu());

        //writes data to that page
        //copy data into dummy buffer, and send to switch
	((uint64_t*)get_dummy_page_buf_addr(get_cpu()))[0] = inode->i_size;

	pr_info("testing invalidate inode write %ld", ((uint64_t*)get_dummy_page_buf_addr(get_cpu()))[0]);


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
	
	spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);
	return true;
}

static bool shmem_invalidate_page_write(struct address_space * mapping, struct page * pagep, void *inv_argv){

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
        inode_pages_address = shmem_address[mapping->host->i_ino] + (PAGE_SIZE * (pagep->index));
	
	int cpu_id = get_cpu();

        //spin_lock(&dummy_page_lock);
        spin_lock(&cnthread_inval_send_ack_lock[cpu_id]);

        size_t data_size;
        void *buf = get_dummy_page_dma_addr(get_cpu());
        //r = mind_fetch_page_write(inode_pages_address, buf, &data_size);
        //BUG_ON(r);

        temppte = ensure_pte(mm, (uintptr_t)get_dummy_page_buf_addr(get_cpu()), &ptl_ptr);

        ptrdummy = get_dummy_page_buf_addr(get_cpu());

        //writes data to that page
        //copy data into dummy buffer, and send to switch
        simplefs_kernel_page_read(testp, (void*)get_dummy_page_buf_addr(get_cpu()), PAGE_SIZE, &test);

        //for(i = 0; i < 20; i++){
        //        pr_info("testing invalidate write %c", ((char*)get_dummy_page_buf_addr(get_cpu()))[i]);
        //}


        //spin_lock(ptl_ptr);
	//pr_info("inside ptl_ptr lock");

	struct cnthread_rdma_msg_ctx *rdma_ctx = NULL;
        struct cnthread_inv_msg_ctx *inv_ctx = &((struct cnthread_inv_argv *)inv_argv)->inv_ctx;
	
	rdma_ctx = &inv_ctx->rdma_ctx;
	inv_ctx->original_qp = (rdma_ctx->ret & CACHELINE_ROCE_RKEY_QP_MASK) >> CACHELINE_ROCE_RKEY_QP_SHIFT;
        create_invalidation_rdma_ack(inv_ctx->inval_buf, rdma_ctx->fva, rdma_ctx->ret, rdma_ctx->qp_val);
        *((u32 *)(&(inv_ctx->inval_buf[CACHELINE_ROCE_VOFFSET_TO_IP]))) = rdma_ctx->ip_val;

	//pr_info("inv_ctx->original_qp %d", inv_ctx->original_qp);
	
	u32 req_qp = (get_id_from_requester(inv_ctx->rdma_ctx.requester) * DISAGG_QP_PER_COMPUTE) + inv_ctx->original_qp;
        //pr_info("req_qp %d", req_qp);
	
	//pr_info("before cn_copy_page");
	cn_copy_page_data_to_mn(DISAGG_KERN_TGID, mm, inode_pages_address,
        temppte, CN_TARGET_PAGE, req_qp, buf);
        //pr_info("after cn_copy_page");
	
	//pr_info("before inval ack");
	//pr_info("inv_ctx->inval_buf %d", inv_ctx->inval_buf);
        _cnthread_send_inval_ack(DISAGG_KERN_TGID, inode_pages_address, inv_ctx->inval_buf);
        //pr_info("after inval ack");
        
	//pr_info("before FinACK");
        cnthread_send_finish_ack(DISAGG_KERN_TGID, inode_pages_address, inv_ctx, 1);
        //pr_info("after FinACK");
	
	//spin_unlock(ptl_ptr);
	//spin_unlock(&dummy_page_lock);
	spin_unlock(&cnthread_inval_send_ack_lock[cpu_id]);

	//spin_unlock_irq(&mapping->tree_lock);
	return true;
}


static bool inode_shmem_invalidate(struct shmem_coherence_state * coherence_state, void *inv_argv){

	pr_info("inode shmem invalidate");
	void *pagep;
	struct inode *inode = coherence_state->inode;

	//lock hashtable	

	//lock inode 
	down_write((&(inode->i_rwsem)));		
	shmem_invalidate_inode_write(inode, inv_argv);
	//TODO ALSO INCLUDE READ CASE
	//we are now invalid
	//writer can begin writing

	//request read access 
	spin_lock(&dummy_page_lock);
	size_t data_size;
	int r;
	void *buf = get_dummy_page_dma_addr(get_cpu());
        uintptr_t inode_pages_address = shmem_address[inode->i_ino]; 
	r = mind_fetch_page(inode_pages_address, buf, &data_size);
        BUG_ON(r);

	//update the value in the inode
	pr_info("before updated size %ld", inode->i_size);
	inode->i_size = ((loff_t*)(buf))[0];
	pr_info("updated size to %ld", inode->i_size);
	spin_unlock(&dummy_page_lock);

	//on access gained, unlock inode		
	up_write((&(inode->i_rwsem)));



	//spin_lock(&inode_states_lock);
	//UPDATE STATUS IN HASHTABLE HERE 
	//spin_unlock(&inode_states_lock);

	return true;

}




static bool shmem_invalidate(struct shmem_coherence_state * coherence_state, void *inv_argv){

	pr_info("shmem invalidate");
	void *pagep;
	struct address_space *mapping = coherence_state->mapping;

	//lock hashtable	
	spin_lock(&shmem_states_lock);

	//lock page tree
	spin_lock_irq(&mapping->tree_lock);

	//delete page from page cache
	//trying to mess with stuff from the page tree
	//this is stolen from find_get_entry in filemap.c
	//spin locks stolen from fs/nilfs2/page.c 
	pagep = radix_tree_lookup(&mapping->page_tree, coherence_state->pagenum);

	if(pagep){

		struct page * testp = pagep;
		
		//perform page invalidation stuff here
		//pr_info("shmem_invalidate_page start");
		shmem_invalidate_page_write(coherence_state->mapping, testp, inv_argv);

		//pr_info("shmem_invalidate_page end");

		ClearPageUptodate(testp);
	}else{
		//pr_info("page no longer in page cache");
	}

	//delete page from the hashmap
	hash_del(&(coherence_state->link));

	spin_unlock_irq(&mapping->tree_lock);
        spin_unlock(&shmem_states_lock);

	return true;

}


u64 testing_invalidate_page_callback(void *addr, void *inv_argv)
{
	//pr_info("invalidate page callback called");
       struct shmem_coherence_state * coherence_state = shmem_in_hashmap(addr);
    if(coherence_state != NULL){
	  shmem_invalidate(coherence_state, inv_argv);
	//pr_info("page was found");

    }else{
	    //pr_info("page no longer in hash table");
    }

    coherence_state = inode_shmem_in_hashmap(addr);
    if(coherence_state != NULL){
	    inode_shmem_invalidate(coherence_state, inv_argv);
	    pr_info("inodewas found");

    }else{
	    pr_info("inode no longer in hash table");
    }

    return 1024;
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


