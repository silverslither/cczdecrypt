#include "libdeflate.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (s_uEncryptedPvrKeyParts[(p & 3) ^ e] ^ z)))
#define DELTA 0x9e3779b9
#define FREAD_CHUNK 0x100000
#define HEADER_SIZE 16
#define ENCRYPTED_OFFSET 12

struct __attribute__((scalar_storage_order("big-endian"))) CCZHeader {
    u8 sig[4];
    u16 compression_type;
    u16 version;
    u32 checksum;
    u32 len;
};

u32 s_uEncryptedPvrKeyParts[4];
u32 s_uEncryptionKey[1024];

const u16 enclen = 1024;

void initKey(void) {
    u32 y, p, e;
    u32 rounds = 6;
    u32 sum = 0;
    u32 z = s_uEncryptionKey[enclen - 1];

    do {
        sum += DELTA;
        e = (sum >> 2) & 3;

        for (p = 0; p < enclen - 1; p++) {
            y = s_uEncryptionKey[p + 1];
            z = s_uEncryptionKey[p] += MX;
        }

        y = s_uEncryptionKey[0];
        z = s_uEncryptionKey[enclen - 1] += MX;

    } while (--rounds);
}

void decryptCCZ(u32 *data, u32 len) {
    static const u32 securelen = 512;
    static const u32 distance = 64;

    u32 i = 0;
    u16 b = 0;

    for (; i < len && i < securelen; i++) {
        data[i] ^= s_uEncryptionKey[b++];
        if (b >= enclen)
            b = 0;
    }

    for (; i < len; i += distance) {
        data[i] ^= s_uEncryptionKey[b++];
        if (b >= enclen)
            b = 0;
    }
}

u32 checksumCCZ(u32 *data, u32 len) {
    static const u32 cslen = 128;
    u32 cs = 0;

    len = (len < cslen) ? len : cslen;

    for (u32 i = 0; i < len; i++)
        cs = cs ^ data[i];

    return cs;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("Usage: cczdecrypt [infile] [key] [options]\n"
               "Decrypt Cocos2d encrypted CCZ `file` with given `key`.\n"
               "`infile` can be absolute or relative to cwd.\n"
               "`key` must be 32 hexadecimal digits.\n"
               "Example: cczdecrypt data.pvr.ccz 83c1e28613d11f53ead45ea59da9fca3\n\n"
               "Additional options:\n"
               "  -o[outfile],                  Write output to `outfile` instead of default\n"
               "  -i, --ignore-checksum         Bypass CCZ checksum check\n");
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "Usage: cczdecrypt [file] [key] [options]\nType cczdecrypt --help for more information.\n");
        return 1;
    }

    u32 i;
    u8 checksum = 1;
    char *outfile = NULL;

    for (i = 3; i < (u32)argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--ignore-checksum") == 0) {
            checksum = 0;
        } else if (argv[i][0] == '-' && argv[i][1] == 'o') {
            outfile = argv[i] + 2;
        } else {
            fprintf(stderr, "Unrecognized argument %s.", argv[i]);
            return 1;
        }
    }

    if (strlen(argv[2]) != 32 || sscanf(argv[2], "%8x%8x%8x%8x", s_uEncryptedPvrKeyParts, s_uEncryptedPvrKeyParts + 1, s_uEncryptedPvrKeyParts + 2, s_uEncryptedPvrKeyParts + 3) != 4) {
        fprintf(stderr, "Invalid key. Must be 32 hexadecimal digits.\n");
        return 1;
    }

    initKey();

    u8 *buf = malloc(FREAD_CHUNK);
    if (buf == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    u32 l = strlen(argv[1]);

#ifdef _WIN32
    while (argv[1][l - 1] == '.' || argv[1][l - 1] == ' ')
        l--;
    argv[1][l] = 0;
#endif

    u32 len = 0, read;
    FILE *infp = fopen(argv[1], "rb");

    if (infp == NULL) {
        fprintf(stderr, "File read error.\n");
        return 1;
    }

    while (1) {
        read = fread(buf + len, 1, FREAD_CHUNK, infp);
        if (read < FREAD_CHUNK) {
            len += read;
            break;
        }

        len += FREAD_CHUNK;
        buf = realloc(buf, len + FREAD_CHUNK);
        if (buf == NULL) {
            fprintf(stderr, "Memory allocation failed.\n");
            return 1;
        }
    }

    if (ferror(infp)) {
        fprintf(stderr, "File read error.\n");
        return 1;
    }

    fclose(infp);

    if (len <= HEADER_SIZE) {
        fprintf(stderr, "Invalid CCZ file.\n");
        return 1;
    }

    struct CCZHeader *header = (struct CCZHeader *)buf;

    if (header->sig[0] != 'C' || header->sig[1] != 'C' || header->sig[2] != 'Z') {
        fprintf(stderr, "Invalid CCZ file.\n");
        return 1;
    }

    decryptCCZ((u32 *)(buf + ENCRYPTED_OFFSET), (len - ENCRYPTED_OFFSET) >> 2);

    if (checksum && checksumCCZ((u32 *)(buf + ENCRYPTED_OFFSET), (len - ENCRYPTED_OFFSET) >> 2) != header->checksum) {
        fprintf(stderr, "Checksum mismatch, check that your key is correct.\n");
        return 1;
    }

    u8 *out = malloc(header->len);
    if (out == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    struct libdeflate_decompressor *decompressor = libdeflate_alloc_decompressor();
    int zerr = libdeflate_zlib_decompress(decompressor, buf + HEADER_SIZE, len - HEADER_SIZE, out, header->len, NULL);
    switch (zerr) {
    case LIBDEFLATE_BAD_DATA:
        fprintf(stderr, "libdeflate error LIBDEFLATE_BAD_DATA.\n");
        return 1;
    case LIBDEFLATE_SHORT_OUTPUT:
        fprintf(stderr, "libdeflate error LIBDEFLATE_SHORT_OUTPUT.\n");
        return 1;
    case LIBDEFLATE_INSUFFICIENT_SPACE:
        fprintf(stderr, "libdeflate error LIBDEFLATE_INSUFFICIENT_SPACE.\n");
        return 1;
    }

    if (outfile != NULL) {
        argv[1] = outfile;
    } else {
        i = l;

        while (i > 0 && argv[1][i - 1] != '/' && argv[1][i - 1] != '\\')
            i--;

        if ((argv[1][l - 1] == 'z' || argv[1][l - 1] == 'Z') && (argv[1][l - 2] == 'c' || argv[1][l - 2] == 'C') && (argv[1][l - 3] == 'c' || argv[1][l - 3] == 'C') && argv[1][l - 4] == '.') {
            l = l - 4;

#ifdef _WIN32
            while (l > i && (argv[1][l - 1] == '.' || argv[1][l - 1] == ' '))
                l--;
#endif

            if (l > i) {
                argv[1][l] = 0;
            } else {
                char *outf = malloc(i + 11);

                if (outf == NULL) {
                    fprintf(stderr, "Memory allocation failed.\n");
                    return 1;
                }

                memcpy(outf, argv[1], i);
                memcpy(outf + i, "decrypted_", 11);

                argv[1] = outf;
            }
        } else {
            char *outf = malloc(l + 11);

            if (outf == NULL) {
                fprintf(stderr, "Memory allocation failed.\n");
                return 1;
            }

            while (i > 0 && argv[1][i] != '/' && argv[1][i] != '\\')
                i--;

            i++;
            if (i == 1 && (argv[1][i] == '/' || argv[1][i] == '\\'))
                i = 0;

            memcpy(outf, argv[1], i);
            memcpy(outf + i, "decrypted_", 10);
            memcpy(outf + i + 10, argv[1] + i, l - i + 1);
            argv[1] = outf;
        }
    }

    FILE *outfp = fopen(argv[1], "wb");

    if (outfp == NULL || fwrite(out, 1, header->len, outfp) < header->len || ferror(outfp)) {
        fprintf(stderr, "File write error.\n");
        return 1;
    }

    fclose(outfp);
    printf("Wrote decrypted file to %s.\n", argv[1]);

    return 0;
}