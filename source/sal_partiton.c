#include <string.h>
#include <wafel/ios/svc.h>
#include <wafel/utils.h>
#include "sal.h"
#include "mbr.h"
#include "sal_partition.h"


#define LOCAL_HEAP_ID 0xCAFE
#define SECTOR_SIZE 512

u32 partition_offset = 0xFFFFFFF;
u32 partition_size = 0xFFFFFFFF;


static read_func *real_read;
static write_func *real_write;
static sync_func *real_sync;

static char umsBlkDevID[0x10] ALIGNED(4);

#define LD_DWORD(ptr)       (u32)(((u32)*((u8*)(ptr)+3)<<24)|((u32)*((u8*)(ptr)+2)<<16)|((u16)*((u8*)(ptr)+1)<<8)|*(u8*)(ptr))

#define ADD_OFFSET(high, low) do { \
    unsigned long long combined = ((unsigned long long)(high) << 32) | (low); \
    combined += partition_offset; \
    (high) = (unsigned int)(combined >> 32); \
    (low) = (unsigned int)(combined & 0xFFFFFFFF); \
} while (0)

int read_wrapper(void *device_handle, u32 lba_hi, u32 lba_lo, u32 blkCount, u32 blockSize, void *buf, void *cb, void* cb_ctx){
    ADD_OFFSET(lba_hi, lba_lo);
    return real_read(device_handle, lba_hi, lba_lo, blkCount, blockSize, buf, cb, cb_ctx);
}

int write_wrapper(void *device_handle, u32 lba_hi, u32 lba_lo, u32 blkCount, u32 blockSize, void *buf, void *cb, void* cb_ctx){
    ADD_OFFSET(lba_hi, lba_lo);
    int ret = real_write(device_handle, lba_hi, lba_lo, blkCount, blockSize, buf, cb, cb_ctx);
    //debug_printf("WFSWRITE: %u, %u\n", lba_lo, blkCount);
    return ret;
}

int sync_wrapper(int server_handle, u32 lba_hi, u32 lba_lo, u32 num_blocks, void * cb, void * cb_ctx){
    ADD_OFFSET(lba_hi, lba_lo);
    //debug_printf("%s: sync called lba: %d, num_blocks: %d\n", PLUGIN_NAME, lba_lo, num_blocks);
    return real_sync(server_handle, lba_hi, lba_lo, num_blocks, cb, cb_ctx);
}


struct cb_ctx {
    int semaphore;
    int res;
} typedef cb_ctx;

static void read_callback(int res, cb_ctx *ctx){
    ctx->res = res;
    iosSignalSemaphore(ctx->semaphore);
}


static int sync_read(FSSALAttachDeviceArg* attach_arg, u64 lba, u32 blkCount, void *buf){
    cb_ctx ctx = {iosCreateSemaphore(1,0)};
    if(ctx.semaphore < 0){
        debug_printf("%s: Error creating Semaphore: 0x%X\n", PLUGIN_NAME, ctx.semaphore);
        return ctx.semaphore;
    }
    int res = attach_arg->op_read(attach_arg->server_handle, lba>>32, lba, blkCount, SECTOR_SIZE, buf, read_callback, &ctx);
    if(!res){
        iosWaitSemaphore(ctx.semaphore, 0);
        res = ctx.res;
    }
    iosDestroySemaphore(ctx.semaphore);
    return res;
}


void patch_partition_attach_arg(FSSALAttachDeviceArg *attach_arg){
    real_read = attach_arg->op_read;
    real_write = attach_arg->op_write;
    real_sync = attach_arg->opsync;
    attach_arg->op_read = read_wrapper;
    attach_arg->op_write = write_wrapper;
    attach_arg->op_read2 = crash_and_burn;
    attach_arg->op_write2 = crash_and_burn;
    attach_arg->opsync = sync_wrapper;
    attach_arg->params.device_type = DEVTYPE_USB;
    attach_arg->params.max_lba_size = partition_size -1;
    attach_arg->params.block_count = partition_size;
}


static bool is_mbr(mbr_sector* mbr){
    debug_printf("%s: MBR signature: 0x%04X\n", PLUGIN_NAME, mbr->boot_signature);
    return mbr->boot_signature==0x55AA;
}

static partition_entry* find_usb_partition(mbr_sector* mbr){
    partition_entry *selected = NULL;
    u32 selected_start = 0;
    for (size_t i = 1; i < MBR_MAX_PARTITIONS; i++){
        u32 istart = LD_DWORD(mbr->partition[i].lba_start);
        if(mbr->partition[i].type == NTFS && (selected_start < istart)){
            selected = mbr->partition+i;
            selected_start = istart;
        }
    }
    return selected;
}

int read_usb_partition_from_mbr(FSSALAttachDeviceArg *attach_arg, u32* out_offset, u32* out_size){
    mbr_sector *mbr = iosAllocAligned(LOCAL_HEAP_ID, max(attach_arg->params.block_size, SECTOR_SIZE), 0x40);
    if(!mbr){
        debug_printf("%s: Failed to allocate IO buf\n", PLUGIN_NAME);
        return -1;
    }
    int ret = -2;
    int res = sync_read(attach_arg, 0, 1, mbr);
    if(res)
        goto out_free;

    if(!is_mbr(mbr)){
        debug_printf("%s: MBR NOT found!!!\n", PLUGIN_NAME);
        ret = 0;
        goto out_free;
    }

    partition_entry *part = find_usb_partition(mbr);
    if(!part){
        debug_printf("%s: USB partition not found!!!\n", PLUGIN_NAME);
        ret = 1;
        goto out_free;
    }
    ret = 2;
    *out_offset = LD_DWORD(part->lba_start);
    *out_size = LD_DWORD(part->lba_length);
    memcpy(umsBlkDevID, mbr, sizeof(umsBlkDevID));
    debug_printf("%s: USB partition found %p: offset: %u, size: %u\n", PLUGIN_NAME, part, *out_offset, *out_size);

out_free:
    iosFree(LOCAL_HEAP_ID, mbr); // also frees part
    return ret;
}