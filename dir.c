#define pr_fmt(fmt) "simplefs: " fmt

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <../../include/disagg/cnthread_disagg.h>
#include <../../include/disagg/exec_disagg.h>
#include <../../include/disagg/fault_disagg.h>
#include <../../mm/internal.h>
#include <../../roce_modules/roce_for_disagg/roce_disagg.h>
#include <asm/traps.h>
#include <../include/disagg/kshmem_disagg.h>


#include "simplefs.h"

struct fake_file_dir fake_block[10];

int iterate_root = 1;
extern int mind_fetch_page_write(
	uintptr_t shmem_address, void *page_dma_address, size_t *data_size);
extern spinlock_t cnthread_inval_send_ack_lock[DISAGG_NUM_CPU_CORE_IN_COMPUTING_BLADE];
extern int clone_remote_dir;

void request_remote_dir(void){
	int cpu = get_cpu();
	int i;
	int r;
	spin_lock(&cnthread_inval_send_ack_lock[cpu]);

	// TODO(stutsman): Why are we bothering with per-cpu buffers if we have
	// a single lock around all of them here. Likely we want a per-cpu
	// spinlock.
	size_t data_size;
	//void *buf = get_dummy_page_dma_addr(get_cpu());
	void *buf = get_dummy_page_dma_addr(cpu);

	pr_info("requesting remote file info");
	pr_info("requesting remote file info");
	pr_info("requesting remote file info");
	pr_info("requesting remote file info");
	pr_info("requesting remote file info");
	pr_info("requesting remote file info");

	r = mind_fetch_page_write(file_address, buf, &data_size);
	if(r == -1){
		spin_unlock(&cnthread_inval_send_ack_lock[cpu]);
		return;
	}

	for(i = 0; i < 10; i++){	
		fake_block[i] = ((struct fake_file_dir *)get_dummy_page_buf_addr(cpu))[i];
		if(fake_block[i].inode_num != 0){
			pr_info("file string is %s", fake_block[i].name);
		}
	}


	spin_unlock(&cnthread_inval_send_ack_lock[cpu]);

}

/*
 * Iterate over the files contained in dir and commit them in ctx.
 * This function is called by the VFS while ctx->pos changes.
 * Return 0 on success.
 */
static int simplefs_iterate(struct file *dir, struct dir_context *ctx)
{
    struct inode *inode = file_inode(dir);
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    struct super_block *sb = inode->i_sb;
    struct buffer_head *bh = NULL, *bh2 = NULL;
    struct simplefs_file_ei_block *eblock = NULL;
    struct simplefs_dir_block *dblock = NULL;
    struct simplefs_file *f = NULL;
    int ei = 0, bi = 0, fi = 0;
    int ret = 0;
     int i;
     int r;

     //don't want to keep reporting the same files if iterate is called again
     if(iterate_root){

	    //I think we want to request remote access here
	    
	     if(clone_remote_dir){
		     request_remote_dir();
		     clone_remote_dir = 0;
	     }
	    pr_info("iterating over fake files");
	    for(i = 0; i < 10; i++){

		    if(fake_block[i].inode_num > 0){
			    dir_emit(ctx, fake_block[i].name, SIMPLEFS_FILENAME_LEN,
					    fake_block[i].inode_num, DT_UNKNOWN);
			    ctx->pos++;

			    pr_info("adding file %s", fake_block[i].name);
		    }
	    }
	    pr_info("done iterating over fake files");
	    brelse(bh);
		iterate_root = 0;
    }

    return 0;





    /* Check that dir is a directory */
    if (!S_ISDIR(inode->i_mode))
        return -ENOTDIR;

    /*
     * Check that ctx->pos is not bigger than what we can handle (including
     * . and ..)
     */
    if (ctx->pos > SIMPLEFS_MAX_SUBFILES + 2)
        return 0;

    /* Commit . and .. to ctx */
    if (!dir_emit_dots(dir, ctx))
        return 0;

    /* Read the directory index block on disk */
    bh = sb_bread(sb, ci->ei_block);
    if (!bh)
        return -EIO;
    eblock = (struct simplefs_file_ei_block *) bh->b_data;

    ei = (ctx->pos - 2) / SIMPLEFS_FILES_PER_EXT;
    bi = (ctx->pos - 2) % SIMPLEFS_FILES_PER_EXT
         / SIMPLEFS_FILES_PER_BLOCK;
    fi = (ctx->pos - 2) % SIMPLEFS_FILES_PER_BLOCK;

    /* Iterate over the index block and commit subfiles */
    for (; ei < SIMPLEFS_MAX_EXTENTS; ei++) {
        if (eblock->extents[ei].ee_start == 0) {
            break;
        }
        /* Iterate over blocks in one extent */
        for (; bi < eblock->extents[ei].ee_len; bi++) {
            bh2 = sb_bread(sb, eblock->extents[ei].ee_start + bi);
            if (!bh2) {
                ret = -EIO;
                goto release_bh;
            }
            dblock = (struct simplefs_dir_block *) bh2->b_data;
            if (dblock->files[0].inode == 0) {
                break;
            }
            /* Iterate every file in one block */
            for (; fi < SIMPLEFS_FILES_PER_BLOCK; fi++) {
                f = &dblock->files[fi];
                if (f->inode && !dir_emit(ctx, f->filename, SIMPLEFS_FILENAME_LEN,
                               f->inode, DT_UNKNOWN))
                    break;
                ctx->pos++;
            }
            brelse(bh2);
            bh2 = NULL;
        }
    }

release_bh:
    brelse(bh);

    return ret;
}


int validation_test = 0;

int test_revalidate(struct dentry *d , unsigned int test){
		if(d->d_name.name[0] != 't'){
			return 1;
		}
		if(validation_test % 2 == 0){
			test_dentry_revalidate = 0;
			pr_info("forcing revalidate root");

			return 0;
		}else{

			return 1;
		}
}
const struct file_operations simplefs_dir_ops = {
    .owner = THIS_MODULE,
    .iterate_shared = simplefs_iterate,
};

const struct dentry_operations simplefs_den_ops = {
	.d_revalidate = test_revalidate,
};

