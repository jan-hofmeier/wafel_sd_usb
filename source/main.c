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



#define SECTOR_SIZE 512
#define HEAP_ID 0xCAFF

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

static void read_callback(void *parm1, u8 *buf){
    debug_printf("In read_callback(%p,%p)\n", parm1, buf);
    debug_printf("read_buff at %p:", buf);
    for(int i=0; i<SECTOR_SIZE; i++){
        if(i%32 == 0)
            debug_printf("\n");
        debug_printf("%02X ", buf[i]);
    }
    debug_printf("\n");

    sdusb_attach_device_handle[0x76] = (int)read_wrapper;
    sdusb_attach_device_handle[0x76] = (int)write_wrapper;

    iosFree(HEAP_ID, buf);


}

void hook_register_sd(trampoline_state *state){
    memcpy(sdusb_attach_device_handle, (int*) state->r[6] -3, sizeof(sdusb_attach_device_handle));
    int *device_handle = (int*)state->r[0] -3;
    real_read = (void*)device_handle[0x76];
    real_write = (void*)device_handle[0x78];
    void *buf = iosAllocAligned(0xCAFF, SECTOR_SIZE, 0x40);
    if(!buf){
        debug_printf("SDUSB: Failed to allocate IO buf\n");
        return;
    }
    debug_printf("Calling sdio_read at %p\n", real_read);
    int res = real_read(device_handle, 0, 0, 1, SECTOR_SIZE, buf, read_callback, buf);
    debug_printf("sdio_read returned: %u¸n", res);
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
