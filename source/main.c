#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <wafel/dynamic.h>
#include <wafel/ios_dynamic.h>
#include <wafel/utils.h>
#include <wafel/patch.h>
#include <wafel/ios/svc.h>
#include <wafel/trampoline.h>
#include "mbr.h"

#define SECTOR_SIZE 512
#define HEAP_ID 0xCAFF
#define DEVTYPE_USB 17

#define LD_DWORD(ptr)       (u16)(((u32)*((u8*)(ptr)+3)<<24)|((u32)*((u8*)(ptr)+2)<<16)|((u16)*((u8*)(ptr)+1)<<8)|*(u8*)(ptr))

static int (*FSSAL_attach_device)(int*) = (void*)0x10733aa4;

static int sdusb_attach_device_handle[0xb5];

static u32 sdusb_offset = 0xFFF;
static int (*real_read)(int*, u32, u32, u32, u32, void*, void*, void*) = (void*)0x107bddd0;
static int (*real_write)(int*, u32, u32, u32, u32, void*, void*, void*) = (void*)0x107bdd60;

static int read_wrapper(void *device_handle, u32 lba_hi, u32 lba, u32 blkCount, u32 blockSize, void *buf, void *cb, void* cb_ctx){
    return real_read(device_handle, lba_hi, lba + sdusb_offset, blkCount, blockSize, buf, cb, cb_ctx);
}

static int write_wrapper(void *device_handle, u32 lba_hi, u32 lba, u32 blkCount, u32 blockSize, void *buf, void *cb, void* cb_ctx){
    return real_write(device_handle, lba_hi, lba + sdusb_offset, blkCount, blockSize, buf, cb, cb_ctx);
}

static partition_entry* find_usb_partition(mbr_sector* mbr){
    for (size_t i = 1; i < MBR_MAX_PARTITIONS; i++){
        if(mbr->partition[i].type == MBR_PARTITION_TYPE_MLC_NOSCFM){
            return mbr->partition+i;
        }
    }
    return NULL;
}

struct cb_ctx {
    int semaphore;
    int res;
} typedef cb_ctx;

static void read_callback(int res, cb_ctx *ctx){
    debug_printf("In read_callback(%d,%p)\n", res, ctx);
    ctx->res = res;
    iosSignalSemaphore(ctx->semaphore);
}

void hook_register_sd(trampoline_state *state){
    memcpy(sdusb_attach_device_handle, (int*) state->r[6] -3, sizeof(sdusb_attach_device_handle));
    int *device_handle = (int*)state->r[0] -3;
    real_read = (void*)device_handle[0x76];
    real_write = (void*)device_handle[0x78];
    u8 *buf = iosAllocAligned(0xCAFF, SECTOR_SIZE, 0x40);
    if(!buf){
        debug_printf("SDUSB: Failed to allocate IO buf\n");
        return;
    }

    cb_ctx ctx = {iosCreateSemaphore(1,0)};
    if(ctx.semaphore < 0){
        debug_printf("SDUSB: Error creating Semaphore: 0x%X\n", ctx.semaphore);
    }

    debug_printf("Calling sdio_read at %p\n", real_read);
    int res = real_read(device_handle, 0, 0, 1, SECTOR_SIZE, buf, read_callback, &ctx);
    debug_printf("sdio_read returned: %u\n", res);

    debug_printf("SDUSB: Waiting for semaphore\n");
    iosWaitSemaphore(ctx.semaphore, 0);

    iosDestroySemaphore(ctx.semaphore);

    debug_printf("read_buff at %p:", buf);
    for(int i=0; i<SECTOR_SIZE; i++){
        if(i%32 == 0)
            debug_printf("\n");
        debug_printf("%02X ", buf[i]);
    }
    debug_printf("\n");

    partition_entry *part = find_usb_partition((mbr_sector*)buf);

    if(!part){
        debug_printf("SDUSB: USB partition not found!!!\n");
        return;
    }
    
    sdusb_offset = LD_DWORD(part->lba_start);
    u32 size = LD_DWORD(part->lba_length);

    iosFree(HEAP_ID, buf); // also frees part

    debug_printf("SDUSB: USB partition found: offset: %u, size: %u\n", sdusb_offset, size);

    sdusb_attach_device_handle[0x3] = (int) sdusb_attach_device_handle;
    sdusb_attach_device_handle[0x76] = (int)read_wrapper;
    sdusb_attach_device_handle[0x76] = (int)write_wrapper;
    sdusb_attach_device_handle[0x5] = DEVTYPE_USB;
    sdusb_attach_device_handle[0xa] = size -1;
    sdusb_attach_device_handle[0xa] = size;

    res = FSSAL_attach_device(sdusb_attach_device_handle+3);

    debug_printf("SDUSB: Attached pseudo USB device. res: 0x%X\n", res);
}


// This fn runs before everything else in kernel mode.
// It should be used to do extremely early patches
// (ie to BSP and kernel, which launches before MCP)
// It jumps to the real IOS kernel entry on exit.
__attribute__((target("arm")))
void kern_main()
{
    // Make sure relocs worked fine and mappings are good
    debug_printf("we in here trampoline demo plugin kern %p\n", kern_main);

    debug_printf("init_linking symbol at: %08x\n", wafel_find_symbol("init_linking"));

    trampoline_hook_before(0x107bd9a4, hook_register_sd);

}

// This fn runs before MCP's main thread, and can be used
// to perform late patches and spawn threads under MCP.
// It must return.
void mcp_main()
{

}
