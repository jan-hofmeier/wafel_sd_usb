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


struct sal_device_handle {

} typedef sal_device_handle;

u8 read_buff[512] ALIGNED(64);


void read_callback(void *parm1, void *parm2){
    debug_printf("In read_callback(%p,%p)\n", parm1, parm2);
    debug_printf("read_buff at %p:", read_buff);
    for(int i=0; i<sizeof(read_buff); i++){
        if(i%32 == 0)
            debug_printf("\n");
        debug_printf("%02X ", read_buff[i]);
    }
    debug_printf("\n");
}

void hook_register_sd(trampoline_state *state){
    int *device_handle = (int*)state->r[0] -3;
    int (*read_dev)(int*, u32, u32, u32, u32, void*, void*, void*) = (void*)device_handle[0x76];
    debug_printf("Calling sdio_read at %p\n", read_dev);
    int res = read_dev(device_handle, 0, 0, 1, 512, read_buff, read_callback, read_buff);
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
