void validate_keyslots();
void write_keyslots();

typedef struct keyslot_keyset {
    u8 mariko_kek[SE_KEY_128_SIZE];
    u8 mariko_bek[SE_KEY_128_SIZE];
    u8 secure_boot_key[SE_KEY_128_SIZE];
} keyslot_keyset_t;

bool parse_hex_key(unsigned char *key, const char *hex, unsigned int len);
void extkeys_initialize_settings(keyslot_keyset_t *keyset, char *filebuffer);
int key_exists(const void *data);

bool read_keys(keyslot_keyset_t *ks, const char *keyfile_path);