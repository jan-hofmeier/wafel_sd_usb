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
#include "mbr.h"
#include "rednand_config.h"
#include "sal.h"

const char* MODULE_NAME = "SDUSB";

#define SECTOR_SIZE 512
#define LOCAL_HEAP_ID 0xCAFE
#define DEVTYPE_USB 17

// tells crypto to not do crypto (depends on stroopwafel patch)
#define NO_CRYPTO_HANDLE 0xDEADBEEF

#define LD_DWORD(ptr)       (u32)(((u32)*((u8*)(ptr)+3)<<24)|((u32)*((u8*)(ptr)+2)<<16)|((u16)*((u8*)(ptr)+1)<<8)|*(u8*)(ptr))


#define FIRST_HANDLE ((int*)0x11c39e78)
#define HANDLE_END ((int*)0x11c3a420)

FSSALAttachDeviceArg extra_attach_arg;

static u32 sdusb_offset = 0xFFFFFFF;
static u32 sdusb_size = 0xFFFFFFFF;

#ifdef USE_MLC_KEY
u32 mlc_size_sectors = 0;
#endif

static volatile bool learn_mlc_crypto_handle = false;
static volatile bool learn_usb_crypto_handle = false;

static read_func *real_read;
static write_func *real_write;
static sync_func *real_sync;

bool active = false;


#define ADD_OFFSET(high, low) do { \
    unsigned long long combined = ((unsigned long long)(high) << 32) | (low); \
    combined += sdusb_offset; \
    (high) = (unsigned int)(combined >> 32); \
    (low) = (unsigned int)(combined & 0xFFFFFFFF); \
} while (0)

int read_wrapper(void *device_handle, u32 lba_hi, u32 lba_lo, u32 blkCount, u32 blockSize, void *buf, void *cb, void* cb_ctx){
    ADD_OFFSET(lba_hi, lba_lo);
    return real_read(device_handle, lba_hi, lba_lo, blkCount, blockSize, buf, cb, cb_ctx);
}

int write_wrapper(void *device_handle, u32 lba_hi, u32 lba_lo, u32 blkCount, u32 blockSize, void *buf, void *cb, void* cb_ctx){
    ADD_OFFSET(lba_hi, lba_lo);
    return real_write(device_handle, lba_hi, lba_lo, blkCount, blockSize, buf, cb, cb_ctx);
}

int sync_wrapper(int server_handle, u32 lba_hi, u32 lba_lo, u32 num_blocks, void * cb, void * cb_ctx){
    ADD_OFFSET(lba_hi, lba_lo);
    //debug_printf("%s: sync called lba: %d, num_blocks: %d\n", MODULE_NAME, lba_lo, num_blocks);
    return real_sync(server_handle, lba_hi, lba_lo, num_blocks, cb, cb_ctx);
}

static partition_entry* find_usb_partition(mbr_sector* mbr){
    if(mbr->boot_signature!=0x55AA)
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


static int sync_read(FSSALAttachDeviceArg* attach_arg, u64 lba, u32 blkCount, void *buf){
    cb_ctx ctx = {iosCreateSemaphore(1,0)};
    if(ctx.semaphore < 0){
        debug_printf("%s: Error creating Semaphore: 0x%X\n", MODULE_NAME, ctx.semaphore);
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

void patch_usb_attach_arg(FSSALAttachDeviceArg *attach_arg){
    real_read = attach_arg->op_read;
    real_write = attach_arg->op_write;
    real_sync = attach_arg->opsync;
    attach_arg->op_read = read_wrapper;
    attach_arg->op_write = write_wrapper;
    attach_arg->op_read2 = crash_and_burn;
    attach_arg->op_write2 = crash_and_burn;
    attach_arg->opsync = sync_wrapper;
    attach_arg->params.device_type = DEVTYPE_USB;
    attach_arg->params.max_lba_size = sdusb_size -1;
    attach_arg->params.block_count = sdusb_size;
}

void clone_patch_attach_usb_hanlde(FSSALAttachDeviceArg *attach_arg){
    memcpy(&extra_attach_arg, attach_arg, sizeof(extra_attach_arg));
    patch_usb_attach_arg(&extra_attach_arg);
    // somehow it doesn't work if we fix the handle pointer
    //extra_server_handle[0x3] = (int) extra_server_handle;
    learn_usb_crypto_handle = true;
    int res = FSSAL_attach_device(&extra_attach_arg);
    debug_printf("SDUSB: Attached extra handle. res: 0x%X\n", res);
}

int read_usb_partition_from_mbr(FSSALAttachDeviceArg *attach_arg, u32* out_offset, u32* out_size){
    mbr_sector *mbr = iosAllocAligned(LOCAL_HEAP_ID, attach_arg->params.block_size, 0x40);
    if(!mbr){
        debug_printf("%s: Failed to allocate IO buf\n", MODULE_NAME);
        return -1;
    }
    int ret = -2;
    int res = sync_read(attach_arg, 0, 1, mbr);
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

void hai_write_file_patch(trampoline_t_state *s){
    uint32_t *buffer = (uint32_t*)s->r[1];
    debug_printf("HAI WRITE COMPANION\n");
    if(active && hai_getdev() == DEVTYPE_USB){
        hai_companion_add_offset(buffer, sdusb_offset);
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

    int res = read_usb_partition_from_mbr(attach_arg, &sdusb_offset, &sdusb_size);
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
        debug_printf("%s: learned mlc crypto handle: 0x%X\n", MODULE_NAME, mlc_crypto_handle);
    }
#endif

    static u32 usb_crypto_handle = 0;
    if(state->r[5] == sdusb_size){
        if(learn_usb_crypto_handle){
            learn_usb_crypto_handle = false;
            usb_crypto_handle = state->r[0];
            debug_printf("%s: learned mlc crypto handle: 0x%X\n", MODULE_NAME,  usb_crypto_handle);
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

void test_hook(trampoline_state* state){
    int *data = (int*)state->r[2];
    for(int i=0; i<16; i++){
        debug_printf("%X: %08X\n", i, data[i]);
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
    debug_printf("we in here %s plugin kern %p\n", MODULE_NAME, kern_main);

    debug_printf("init_linking symbol at: %08x\n", wafel_find_symbol("init_linking"));

    rednand_config *rednand_conf;
    size_t rednand_conf_size;
    if(!prsh_get_entry("rednand", (void**)&rednand_conf, &rednand_conf_size)){
        if(rednand_conf_size<sizeof(rednand_config_v1) || rednand_conf->mlc.lba_length){
            debug_printf("%s: detected MLC redirection, %s will be disabled\n", MODULE_NAME, MODULE_NAME);
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

    debug_printf("%s: patches applied\n", MODULE_NAME);

    //trampoline_hook_before(0x10740f2c, test_hook);
}

// This fn runs before MCP's main thread, and can be used
// to perform late patches and spawn threads under MCP.
// It must return.
void mcp_main()
{

}
