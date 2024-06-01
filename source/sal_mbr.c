#include <string.h>
#include <wafel/utils.h>
#include <wafel/ios/svc.h>
#include "mbr.h"
#include "sal.h"
#include "sal_partition.h"

#define LOCAL_HEAP_ID 0xCAFE
#define SECTOR_SIZE 512

#define LD_DWORD(ptr)       (u32)(((u32)*((u8*)(ptr)+3)<<24)|((u32)*((u8*)(ptr)+2)<<16)|((u16)*((u8*)(ptr)+1)<<8)|*(u8*)(ptr))

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

int read_usb_partition_from_mbr(FSSALAttachDeviceArg *attach_arg, u32* out_offset, u32* out_size, u32* out_umsBlkDevID){
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
    if(out_umsBlkDevID)
        memcpy(out_umsBlkDevID, mbr, 0x10);
    debug_printf("%s: USB partition found %p: offset: %u, size: %u\n", PLUGIN_NAME, part, *out_offset, *out_size);

out_free:
    iosFree(LOCAL_HEAP_ID, mbr); // also frees part
    return ret;
}