/*
ISC License
Copyright (c) 2018, SciresM
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "writer.h"

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

    for (u32 ks = 0; ks < 16; ks++)
    {
        // Check if key is as expected
        if (ks < ARRAY_SIZE(mariko_key_vectors))
        {
            se_aes_crypt_block_ecb(ks, DECRYPT, &data[0], mariko_key_vectors[ks]);
            if (key_exists(data))
            {
                gfx_printf("\n%kkeyslot %d: %kFailed", colors[(color_idx++) % 6], ks, colors[0]);
                continue;
            }
            else
            {
                gfx_printf("\n%kkeyslot %d: %kOK", colors[(color_idx++) % 6], ks, colors[3]);
                continue;
            }
        }
    }
    gfx_printf("\n%kkeyslot 14: %kConsole unique", colors[(color_idx++) % 6], colors[2]);
    gfx_printf("\n%kkeyslot 15: %kConsole unique", colors[(color_idx++) % 6], colors[2]);

    gfx_printf("\n\n%kPress a button to return to the menu.", colors[(color_idx++) % 6]);
    minerva_change_freq(FREQ_800);
    btn_wait();
    gfx_clear_grey(0x1B);
}

/**
 * Reads a line from file f and parses out the key and value from it.
 * The format of a line must match /^ *[A-Za-z0-9_] *[,=] *.+$/.
 * If a line ends in \r, the final \r is stripped.
 * The input file is assumed to have been opened with the 'b' flag.
 * The input file is assumed to contain only ASCII.
 *
 * A line cannot exceed 512 bytes in length.
 * Lines that are excessively long will be silently truncated.
 *
 * On success, *key and *value will be set to point to the key and value in
 * the input line, respectively.
 * *key and *value may also be NULL in case of empty lines.
 * On failure, *key and *value will be set to NULL.
 * End of file is considered failure.
 *
 * Because *key and *value will point to a static buffer, their contents must be
 * copied before calling this function again.
 * For the same reason, this function is not thread-safe.
 *
 * The key will be converted to lowercase.
 * An empty key is considered a parse error, but an empty value is returned as
 * success.
 *
 * This function assumes that the file can be trusted not to contain any NUL in
 * the contents.
 *
 * Whitespace (' ', ASCII 0x20, as well as '\t', ASCII 0x09) at the beginning of
 * the line, at the end of the line as well as around = (or ,) will be ignored.
 *
 * @param f the file to read
 * @param key pointer to change to point to the key
 * @param value pointer to change to point to the value
 * @return 0 on success,
 *         1 on end of file,
 *         -1 on parse error (line too long, line malformed)
 *         -2 on I/O error
 */
static int get_kv(char *line, char **key, char **value)
{
#define SKIP_SPACE(p)                        \
    do                                       \
    {                                        \
        for (; *p == ' ' || *p == '\t'; ++p) \
            ;                                \
    } while (0);
    char *k, *v, *p, *end;

    *key = *value = NULL;

    if (line == NULL)
    {
        return 1;
    }

    if (*line == '\n' || *line == '\r' || *line == '\0')
        return 0;

    /* Not finding \r or \n is not a problem.
     * The line might just be exactly 512 characters long, we have no way to
     * tell.
     * Additionally, it's possible that the last line of a file is not actually
     * a line (i.e., does not end in '\n'); we do want to handle those.
     */
    if ((p = strchr(line, '\r')) != NULL || (p = strchr(line, '\n')) != NULL)
    {
        end = p;
        *p = '\0';
    }
    else
    {
        end = line + strlen(line) + 1;
    }

    p = line;
    SKIP_SPACE(p);
    k = p;

    /* Validate key and convert to lower case. */
    for (; *p != ' ' && *p != ',' && *p != '\t' && *p != '='; ++p)
    {
        if (*p == '\0')
            return -1;

        if (*p >= 'A' && *p <= 'Z')
        {
            *p = 'a' + (*p - 'A');
            continue;
        }

        if (*p != '_' &&
            (*p < '0' || *p > '9') &&
            (*p < 'a' || *p > 'z'))
        {
            return -1;
        }
    }

    /* Bail if the final ++p put us at the end of string */
    if (*p == '\0')
        return -1;

    /* We should be at the end of key now and either whitespace or [,=]
     * follows.
     */
    if (*p == '=' || *p == ',')
    {
        *p++ = '\0';
    }
    else
    {
        *p++ = '\0';
        SKIP_SPACE(p);
        if (*p != '=' && *p != ',')
            return -1;
        *p++ = '\0';
    }

    /* Empty key is an error. */
    if (*k == '\0')
        return -1;

    SKIP_SPACE(p);
    v = p;

    /* Skip trailing whitespace */
    for (p = end - 1; *p == '\t' || *p == ' '; --p)
        ;

    *(p + 1) = '\0';

    *key = k;
    *value = v;

    return 0;
#undef SKIP_SPACE
}

static int ishex(char c)
{
    if ('a' <= c && c <= 'f')
        return 1;
    if ('A' <= c && c <= 'F')
        return 1;
    if ('0' <= c && c <= '9')
        return 1;
    return 0;
}

static char hextoi(char c)
{
    if ('a' <= c && c <= 'f')
        return c - 'a' + 0xA;
    if ('A' <= c && c <= 'F')
        return c - 'A' + 0xA;
    if ('0' <= c && c <= '9')
        return c - '0';
    return 0;
}

bool parse_hex_key(unsigned char *key, const char *hex, unsigned int len)
{
    if (strlen(hex) != 2 * len)
    {
        return false;
    }

    for (unsigned int i = 0; i < 2 * len; i++)
    {
        if (!ishex(hex[i]))
        {
            return false;
        }
    }

    memset(key, 0, len);

    for (unsigned int i = 0; i < 2 * len; i++)
    {
        char val = hextoi(hex[i]);
        if ((i & 1) == 0)
        {
            val <<= 4;
        }
        key[i >> 1] |= val;
    }

    return true;
}

void extkeys_initialize_settings(keyslot_keyset_t *keyset, char *filebuffer)
{
    memset(keyset, 0, sizeof(keyslot_keyset_t));

    char *key, *value;
    int ret;

    char *line = strtok(filebuffer, "\n");

    while (line != NULL)
    {
        int line_length = strlen(line);
        char *line_copy = malloc(line_length + 1);
        memcpy(line_copy, line, line_length + 1);

        ret = get_kv(line_copy, &key, &value);

        if (ret == 0)
        {
            if (key == NULL || value == NULL)
            {
                continue;
            }

            if (strcmp(key, "mariko_kek") == 0)
            {
                parse_hex_key(keyset->mariko_kek, value, sizeof(keyset->mariko_kek));
            }
            else if (strcmp(key, "mariko_bek") == 0)
            {
                parse_hex_key(keyset->mariko_bek, value, sizeof(keyset->mariko_bek));
            }
            else if (strcmp(key, "secure_boot_key") == 0)
            {
                parse_hex_key(keyset->secure_boot_key, value, sizeof(keyset->secure_boot_key));
            }
        }

        free(line_copy);

        line = strtok(NULL, "\n");
    }
}

bool read_keys(keyslot_keyset_t *ks, const char *keyfile_path)
{
    FILINFO fno;
    if (f_stat(keyfile_path, &fno) || fno.fsize > 0x003FBC00)
        return false;

    u32 keyfile_size = 0;
    char *keyfile_buffer = sd_file_read(keyfile_path, &keyfile_size);

    extkeys_initialize_settings(ks, keyfile_buffer);

    free(keyfile_buffer);

    return true;
}

void write_keyslots()
{
    minerva_change_freq(FREQ_1600);

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_grey(0x1B);
    gfx_con_setpos(0, 0);

    u32 color_idx = 0;

    keyslot_keyset_t *keyset = malloc(sizeof(keyslot_keyset_t));

    read_keys(keyset, "sd:/switch/keyslot.keys");

    se_aes_key_set(12, keyset->mariko_kek, SE_KEY_128_SIZE);
    gfx_printf("\n%kwrote keyslot 12", colors[(color_idx++) % 6]);
    se_aes_key_set(13, keyset->mariko_bek, SE_KEY_128_SIZE);
    gfx_printf("\n%kwrote keyslot 13", colors[(color_idx++) % 6]);
    // se_aes_key_set(14, keyset->secure_boot_key, SE_KEY_128_SIZE);
    // gfx_printf("\n%kwrote keyslot 14", colors[(color_idx++) % 6]);

    free(keyset);

    gfx_printf("\n\n%kDONE", colors[(color_idx++) % 6]);
    gfx_printf("\n\n%kPress a button to return to the menu.", colors[(color_idx++) % 6]);
    
    minerva_change_freq(FREQ_800);
    btn_wait();
    gfx_clear_grey(0x1B);
}