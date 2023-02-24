#include "../keys/keys.h"

#include "../keys/es_crypto.h"
#include "../keys/fs_crypto.h"
#include "../keys/nfc_crypto.h"
#include "../keys/ssl_crypto.h"

#include "../config.h"
#include <display/di.h>
#include "../frontend/gui.h"
#include <gfx_utils.h>
#include "../gfx/tui.h"
#include "../hos/hos.h"
#include <libs/fatfs/ff.h>
#include <libs/nx_savedata/header.h>
#include <libs/nx_savedata/save.h>
#include <mem/heap.h>
#include <mem/minerva.h>
#include <mem/sdram.h>
#include <sec/se.h>
#include <sec/se_t210.h>
#include <soc/fuse.h>
#include <soc/t210.h>
#include "../storage/emummc.h"
#include "../storage/nx_emmc.h"
#include "../storage/nx_emmc_bis.h"
#include <storage/nx_sd.h>
#include <storage/sdmmc.h>
#include <utils/btn.h>
#include <utils/list.h>
#include <utils/sprintf.h>
#include <utils/util.h>

#include "../keys/key_sources.inl"

#include <string.h>

extern hekate_config h_cfg;

void validate_keyslots()
{
	minerva_change_freq(FREQ_1600);

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_grey(0x1B);
    gfx_con_setpos(0, 0);

	gfx_printf("[%kLo%kck%kpi%kck%k_R%kCM%k v%d.%d.%d%k]\n",
        colors[0], colors[1], colors[2], colors[3], colors[4], colors[5], 0xFFFF00FF, LP_VER_MJ, LP_VER_MN, LP_VER_BF, 0xFFCCCCCC);

	u8 *data = malloc(4 * SE_KEY_128_SIZE);
    u32 color_idx = 0;

	for (u32 ks = 0; ks < 16; ks++) {
        // Check if key is as expected
        if (ks < ARRAY_SIZE(mariko_key_vectors)) {
            se_aes_crypt_block_ecb(ks, DECRYPT, &data[0], mariko_key_vectors[ks]);
            if (key_exists(data)) {
				gfx_printf("\n%kkeyslot %d: %kFailed", colors[(color_idx++) % 6], ks, colors[0]);
                continue;
            }
			else {
				gfx_printf("\n%kkeyslot %d: %kOK", colors[(color_idx++) % 6], ks, colors[3]);
				continue;
			}
        }
    }

	gfx_printf("\n\n%kPress a button to return to the menu.", colors[(color_idx++) % 6]);
	minerva_change_freq(FREQ_800);
    btn_wait();
    gfx_clear_grey(0x1B);
}

void write()
{
    
}