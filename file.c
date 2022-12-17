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

#include "simplefs.h"


int counter = 0;

struct inode_item {
	unsigned long i_ino;
	int pagenum;
	int state;
	struct inode * inode;	
	struct address_space *mapping;
	struct hlist_node myhash_list;
};
/* spin locks for hashtable */
//https://stackoverflow.com/questions/6792930/how-do-i-share-a-global-variable-between-c-files
extern struct spinlock *test_spin_lock;


//struct inode_item;
//https://lwn.net/Articles/510202/

/* hashmap for inode msi states */
//8 bits = 256 buckets
DEFINE_HASHTABLE(inode_msi_table, 8); 


//adds page to inode hashmap
static void hash_inode_page(int inodenum, int pagenum, struct address_space *mapping, int state) {
	pr_info("adding inode %d page %d to hash", inodenum, pagenum);
	//malloc an inode item and add it to the hashmap	
	//
	//refer more to Documentation/kernel-hacking/hacking.rst
	struct inode_item * newinode = kmalloc(sizeof(struct inode_item), GFP_KERNEL);
	newinode->i_ino = inodenum;
	newinode->pagenum = pagenum;
	newinode->mapping = mapping;
	newinode->state = state;
	//how does it get the inode_item struct if we just pass the node in?
	spin_lock(test_spin_lock);
	hash_add(inode_msi_table, &(newinode->myhash_list), inodenum);
	spin_unlock(test_spin_lock);
}


//https://kernelnewbies.org/FAQ/Hashtables
//returns inode_item if the page is in the hashmap
static struct inode_item * pageinhashmap(unsigned long i_ino, int pagenum) {
	struct inode_item *tempinode;
	int i = i_ino;

	//TODO make sure that page is still valid, and hasn't been removed from cache

	//locking the spin lock
	spin_lock(test_spin_lock);

	hash_for_each(inode_msi_table, i, tempinode, myhash_list) {
		if(tempinode->i_ino == i_ino && tempinode->pagenum == pagenum){
			//unlocking the spin lock
			spin_unlock(test_spin_lock);
			return tempinode; //current;
		}
	}	

	//unlocking the spin lock
	spin_unlock(test_spin_lock);

	return NULL; //NULL;

}



//Caller has to have inode lock
//before calling this
static bool invalidatepage(unsigned long i_ino, int pagenum){

	struct inode_item* inodecheck = pageinhashmap(i_ino, pagenum);
	if (inodecheck != NULL){
		void *pagep;
		struct address_space *mapping = inodecheck->mapping;
		spin_lock_irq(&mapping->tree_lock);

		//delete page from page cache
		//trying to mess with stuff from the page tree
		//this is stolen from find_get_entry in filemap.c
		//spin locks stolen from fs/nilfs2/page.c 
		pagep = radix_tree_lookup_slot(&mapping->page_tree, pagenum);
		if(pagep){
			radix_tree_delete(&mapping->page_tree, pagenum);
			mapping->nrpages--; 
		}

		//delete page from the hashmap
		hash_del(&(inodecheck->myhash_list));
		spin_unlock_irq(&mapping->tree_lock);
		pr_info("invalidated pagd page");

		return true;
	}else{
		pr_info("no page to invalidate");
		return false;
	}

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

static void performcoherence(struct inode * inode, int page, struct address_space * mapping, int reqstate) {
    struct inode_item * temp = pageinhashmap(inode->i_ino, page);
    if(temp == NULL){
	pr_info("page number %d for inode %d being added to hashmap", page, inode->i_ino);
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
 * Called by the page cache to read a page from the physical disk and map it in
 * memory.
 */
static int simplefs_readpage(struct file *file, struct page *page)
{
    pr_info("******reading page number %d", page->index);
    struct address_space *mapping = file->f_mapping; 
    struct inode *inode = mapping->host;
    int temp = page->index;
    performcoherence(inode, temp, mapping, 1);

    return mpage_readpage(page, simplefs_file_get_block);
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
    pr_info("write begin page number %d, for inode %d", currentpage, (file->f_inode)->i_ino);
    struct inode *inode = file->f_inode;

    //need to do the currentpage thing and not pass in the 
    //actual page since it causes null dereference stuff
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
    return ret;
}








ssize_t
simplefs_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	size_t count = iov_iter_count(iter);
	ssize_t retval = 0;

	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	/*      ~*~       */
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
	invalidatepage(inode->i_ino, index);

	retval = generic_file_read_iter(iocb, iter);

	/*      ~*~       */
	inode_unlock(inode);
	/*      ~*~       */
	pr_info("****ending read");

	return retval;

}

ssize_t simplefs_file_write_iter(struct kiocb *iocb, struct iov_iter *from) {


	//NOTE this stuff is currently handled in
	//simplefs.h and fs.c in the __init function
	//struct spinlock *test_spin_lock;
	//spin_lock_init(test_spin_lock);


	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	/*      ~*~       */
	inode_lock(inode);
	/*      ~*~       */


	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = __generic_file_write_iter(iocb, from);


	/*      ~*~       */
	inode_unlock(inode);
	/*      ~*~       */


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
    .write_iter = simplefs_file_write_iter,
    .fsync = generic_file_fsync,
};


