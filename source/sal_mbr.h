#pragma once

#include "sal.h"

int read_usb_partition_from_mbr(FSSALAttachDeviceArg *attach_arg, u32* out_offset, u32* out_size, u8* out_umsBlkDevID);