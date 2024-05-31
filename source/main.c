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
#include "wafel/ios/prsh.h"
#include "wafel/hai.h"
#include "rednand_config.h"
#include "sal.h"
#include "sal_partition.h"


// tells crypto to not do crypto (depends on stroopwafel patch)
#define NO_CRYPTO_HANDLE 0xDEADBEEF

FSSALAttachDeviceArg extra_attach_arg;

static bool active = false;

#ifdef USE_MLC_KEY
u32 mlc_size_sectors = 0;
#endif

static volatile bool learn_mlc_crypto_handle = false;
static volatile bool learn_usb_crypto_handle = false;


void clone_patch_attach_usb_hanlde(FSSALAttachDeviceArg *attach_arg){
    memcpy(&extra_attach_arg, attach_arg, sizeof(extra_attach_arg));
    patch_partition_attach_arg(&extra_attach_arg);
    // somehow it doesn't work if we fix the handle pointer
    //extra_server_handle[0x3] = (int) extra_server_handle;
    learn_usb_crypto_handle = true;
    int res = FSSAL_attach_device(&extra_attach_arg);
    debug_printf("%s: Attached extra handle. res: 0x%X\n", PLUGIN_NAME, res);
}

void hai_write_file_patch(trampoline_t_state *s){
    uint32_t *buffer = (uint32_t*)s->r[1];
    debug_printf("HAI WRITE COMPANION\n");
    if(active && hai_getdev() == DEVTYPE_USB){
        hai_companion_add_offset(buffer, partition_offset);
    }
}

void hai_ios_patches(trampoline_t_state *s){
    if(active && hai_getdev() == DEVTYPE_USB)
        hai_redirect_mlc2sd();
}

int hai_path_sprintf_hook(char* parm1, char* parm2, char *fmt, char *dev, int (*sprintf)(char*, char*, char*, char*, char*), int lr, char *companion_file ){
    if(active)
        dev = "mlc";
    return sprintf(parm1, parm2, fmt, dev, companion_file);
}

void apply_hai_patches(void){
    trampoline_t_hook_before(0x050078AE, hai_write_file_patch);
    hai_apply_getdev_patch();
    //apply patches to HAI IOS just before it gets launched
    trampoline_t_hook_before(0x0500881e, hai_ios_patches);
    //force device in hai parm to MLC
    trampoline_t_blreplace(0x051001d6, hai_path_sprintf_hook);
    //ASM_T_PATCH_K(0x05100198, "nop");
}

void hook_register_sd(trampoline_state *state){
    FSSALAttachDeviceArg *attach_arg = (FSSALAttachDeviceArg*)state->r[0];

    int res = read_usb_partition_from_mbr(attach_arg, &partition_offset, &partition_size);
    if(res<=0)
        return;

    active = true;

    // the virtual USB device has to use the original slot, so the sd goes to the extra slot
    clone_patch_attach_usb_hanlde(attach_arg);
}

#ifdef USE_MLC_KEY
int mlc_attach_hook(int* attach_arg, int r1, int r2, int r3, int (*attach_fun)(int*)){
    mlc_size_sectors = attach_arg[0xe - 3];
    learn_mlc_crypto_handle = true;
    return attach_fun(attach_arg);
}
#endif

static void crypto_hook(trampoline_state *state){
#ifdef USE_MLC_KEY
    static u32 mlc_crypto_handle = 0;
    if(learn_mlc_crypto_handle && state->r[5] == mlc_size_sectors){
        learn_mlc_crypto_handle = false;
        mlc_crypto_handle = state->r[0];
        debug_printf("%s: learned mlc crypto handle: 0x%X\n", PLUGIN_NAME, mlc_crypto_handle);
    }
#endif

    static u32 usb_crypto_handle = 0;
    if(state->r[5] == partition_size){
        if(learn_usb_crypto_handle){
            learn_usb_crypto_handle = false;
            usb_crypto_handle = state->r[0];
            debug_printf("%s: learned mlc crypto handle: 0x%X\n", PLUGIN_NAME,  usb_crypto_handle);
        }
        if(usb_crypto_handle == state->r[0]){
#ifdef USE_MLC_KEY
            state->r[0] = mlc_crypto_handle;
#else     
            state->r[0] = NO_CRYPTO_HANDLE;
#endif
        }
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
    debug_printf("we in here %s plugin kern %p\n", PLUGIN_NAME, kern_main);

    debug_printf("init_linking symbol at: %08x\n", wafel_find_symbol("init_linking"));

    rednand_config *rednand_conf;
    size_t rednand_conf_size;
    if(!prsh_get_entry("rednand", (void**)&rednand_conf, &rednand_conf_size)){
        if(rednand_conf_size<sizeof(rednand_config_v1) || rednand_conf->mlc.lba_length){
            debug_printf("%s: detected MLC redirection, %s will be disabled\n", PLUGIN_NAME, PLUGIN_NAME);
            return;
        }
    }

    trampoline_hook_before(0x107bd9a4, hook_register_sd);
    trampoline_hook_before(0x10740f48, crypto_hook); // hook decrypt call
    trampoline_hook_before(0x10740fe8, crypto_hook); // hook encrypt call

#ifdef USE_MLC_KEY
    trampoline_blreplace(0x107bdae0, mlc_attach_hook);
#endif

    // somehow it causes crashes when applied from the attach hook
    apply_hai_patches();

    debug_printf("%s: patches applied\n", PLUGIN_NAME);

    //trampoline_hook_before(0x10740f2c, test_hook);
}

// This fn runs before MCP's main thread, and can be used
// to perform late patches and spawn threads under MCP.
// It must return.
void mcp_main()
{

}
