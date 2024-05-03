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

const char* MODULE_NAME = "SDUSB";

#define SECTOR_SIZE 512
#define LOCAL_HEAP_ID 0xCAFE
#define DEVTYPE_USB 17

#define SERVER_HANDLE_LEN 0xb5
#define SERVER_HANDLE_SZ (SERVER_HANDLE_LEN * sizeof(int))

#define LD_DWORD(ptr)       (u32)(((u32)*((u8*)(ptr)+3)<<24)|((u32)*((u8*)(ptr)+2)<<16)|((u16)*((u8*)(ptr)+1)<<8)|*(u8*)(ptr))

static int (*FSSAL_attach_device)(int*) = (void*)0x10733aa4;

#define FIRST_HANDLE ((int*)0x11c39e78)
#define HANDLE_END ((int*)0x11c3a420)

int extra_server_handle[SERVER_HANDLE_LEN]; // = HANDLE_END-SERVER_HANDLE_LEN;

static u32 sdusb_offset = 0xFFFFFFF;
static u32 sdusb_size = 0xFFFFFFFF;

typedef int read_write_fun(int*, u32, u32, u32, u32, void*, void*, void*);

read_write_fun *real_read = (read_write_fun*)0x107bddd0;
read_write_fun *real_write = (read_write_fun*)0x107bdd60;


static int read_wrapper(void *device_handle, u32 lba_hi, u32 lba, u32 blkCount, u32 blockSize, void *buf, void *cb, void* cb_ctx){
    return real_read(device_handle, lba_hi, lba + sdusb_offset, blkCount, blockSize, buf, cb, cb_ctx);
}

static int write_wrapper(void *device_handle, u32 lba_hi, u32 lba, u32 blkCount, u32 blockSize, void *buf, void *cb, void* cb_ctx){
    return real_write(device_handle, lba_hi, lba + sdusb_offset, blkCount, blockSize, buf, cb, cb_ctx);
}

static partition_entry* find_usb_partition(mbr_sector* mbr){
    if(mbr->boot_signature[0]==0x55 && mbr->boot_signature[0]==0xAA)
        return NULL;
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
    ctx->res = res;
    iosSignalSemaphore(ctx->semaphore);
}


static int sync_read(int* server_handle, u32 lba, u32 blkCount, void *buf){
    cb_ctx ctx = {iosCreateSemaphore(1,0)};
    if(ctx.semaphore < 0){
        debug_printf("%s: Error creating Semaphore: 0x%X\n", MODULE_NAME, ctx.semaphore);
        return ctx.semaphore;
    }
    int res = ((read_write_fun*)server_handle[0x76])(server_handle, 0, lba, blkCount, SECTOR_SIZE, buf, read_callback, &ctx);
    if(!res){
        iosWaitSemaphore(ctx.semaphore, 0);
        res = ctx.res;
    }
    iosDestroySemaphore(ctx.semaphore);
    return res;
}

void patch_usb_handle(int* sdusb_server_handle){
    real_read = (void*)sdusb_server_handle[0x76];
    real_write = (void*)sdusb_server_handle[0x78];
    sdusb_server_handle[0x76] = (int)read_wrapper;
    sdusb_server_handle[0x78] = (int)write_wrapper;
    sdusb_server_handle[0x5] = DEVTYPE_USB;
    sdusb_server_handle[0xa] = sdusb_size -1;
    sdusb_server_handle[0x1] = sdusb_server_handle[0xe] = sdusb_size;
}

void clone_patch_attach_usb_hanlde(int* server_handle){
    memcpy(extra_server_handle, server_handle, SERVER_HANDLE_SZ);
    patch_usb_handle(server_handle);
    // somehow it doesn't work if we fix the handle pointer
    //extra_server_handle[0x3] = (int) extra_server_handle;
    int res = FSSAL_attach_device(extra_server_handle+3);
    extra_server_handle[0x82] = res;
    debug_printf("SDUSB: Attached extra handle. res: 0x%X\n", res);
}

int read_usb_partition_from_mbr(int* server_handle, u32* out_offset, u32* out_size){
    mbr_sector *mbr = iosAllocAligned(LOCAL_HEAP_ID, SECTOR_SIZE, 0x40);
    if(!mbr){
        debug_printf("%s: Failed to allocate IO buf\n", MODULE_NAME);
        return -1;
    }
    int ret = -2;
    int res = sync_read(server_handle, 0, 1, mbr);
    if(res)
        goto out_free;

    partition_entry *part = find_usb_partition(mbr);
    if(!part){
        debug_printf("%s: USB partition not found!!!\n", MODULE_NAME);
        ret = 0;
        goto out_free;
    }
    ret = 1;
    *out_offset = LD_DWORD(part->lba_start);
    *out_size = LD_DWORD(part->lba_length);
    debug_printf("%s: USB partition found %p: offset: %u, size: %u\n", MODULE_NAME, part, *out_offset, *out_size);

out_free:
    iosFree(LOCAL_HEAP_ID, mbr); // also frees part
    return ret;
}

void hook_register_sd(trampoline_state *state){
    int *server_handle = (int*)state->r[0] -3;
    debug_printf("%s: org server_handle: %p\n", MODULE_NAME, server_handle);

    int res = read_usb_partition_from_mbr(server_handle, &sdusb_offset, &sdusb_size);
    if(res<=0)
        return;

    // the virtual USB device has to use the original slot, so the sd goes to the extra slot
    clone_patch_attach_usb_hanlde(server_handle);
}


void crypto_hook(trampoline_state* state){
    // hope that 0x11 stays constant for mlc
    if(state->r[5] == sdusb_size && state->r[0] != 0x11){
        //debug_printf("SDUSB: cryptohook detected USB partition true lr: %p\n", state->lr);
        // tells crypto to not do crypto (depends on stroopwafel patch)
        state->r[0] = 0xDEADBEEF;
    }
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
    trampoline_hook_before(0x10740f48, crypto_hook); // hook decrypt call
    trampoline_hook_before(0x10740fe8, crypto_hook); // hook encrypt call
}

// This fn runs before MCP's main thread, and can be used
// to perform late patches and spawn threads under MCP.
// It must return.
void mcp_main()
{

}
