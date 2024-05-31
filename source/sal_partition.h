#pragma once

#include <wafel/types.h>

#define DEVTYPE_USB 17
#define DEVTYPE_SD 6

extern u32 partition_offset;
extern u32 partition_size;

void patch_partition_attach_arg(FSSALAttachDeviceArg *attach_arg);
int read_usb_partition_from_mbr(FSSALAttachDeviceArg *attach_arg, u32* out_offset, u32* out_size);