#ifndef RICHIE_RICH_H
#define RICHIE_RICH_H
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#ifdef _WINDOWS
#include <windows.h>
#else
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif

#define OPT_STRIP                   0b00000001
#define OPT_VERIFY                  0b00000010

#define VERIFY_CHECKSUM(x)          ((x)&OPT_VERIFY)
#define STRIP_HEADER(x)             ((x)&OPT_STRIP)

#define PE_MAGIC                    0x00004550
#define DOS_MAGIC                   0x5a4d
#define RICH_FOOTER                 0x68636952
#define RICH_PTHEADER               0x536e6144

#define PE_HDR_OFFT_OFFT            0x3c

#define RICH_DEFAULT_HEADER_OFFT    0x80
#define RICH_FIRST_ENTRY_OFFT       16

// Size of the COFF header plus Windows-specific fields
#define PE_WITH_WINSPEC_SIZE        0x78
// Length of a section table entry
#define PE_SECTBLENT_SIZE           40

#ifdef DEBUG_BUILD
#define DLOG(fmt, ...)                          \
    printf(fmt, ##__VA_ARGS__)
#else
#define DLOG(fmt, ...)
#endif

#define ELOG(fmt, ...)                          \
    fprintf(stderr, fmt, ##__VA_ARGS__)

#define ILOG(fmt, ...)                          \
    printf(fmt, ##__VA_ARGS__)

#define PE_NEW_HEADERS_SIZE(true_hdrs, align)   \
    ((((true_hdrs)/(align))+1)*(align))

struct pe_file {
    uint8_t *data;
    size_t len;
    uint32_t pe_offt;
    uint32_t rich_beg_offt;
    uint32_t rich_end_offt;
    uint32_t rich_csum;
};

#define PTR_RICH_HDR(p)     ((p)->data + (p)->rich_beg_offt)
#define PTR_PE_BEGIN(p)     ((p)->data + (p)->pe_offt)

#define U32_PE_Magic(p)             (*(uint32_t *)(PTR_PE_BEGIN(p)))
#define U16_PE_NumberOfSections(p)  (*(uint16_t *)(PTR_PE_BEGIN(p) + 0x6))
#define U16_PE_SizeOptionalHdr(p)   (*(uint16_t *)(PTR_PE_BEGIN(p) + 0x14))
#define U32_PE_FileAlignment(p)     (*(uint32_t *)(PTR_PE_BEGIN(p) + 0x3c))
#define U32_PE_SizeOfHeaders(p)     (*(uint32_t *)(PTR_PE_BEGIN(p) + 0x54))

#define U16_DOS_Magic(p)            (*(uint16_t *)((p)->data))
#define U32_DOS_PE_Offt(p)          (*(uint32_t *)((p)->data+PE_HDR_OFFT_OFFT))

struct rich_entry {
    uint16_t minor_version;
    uint16_t prod_id;
    uint32_t use_count;
} __attribute__((packed));


int get_file_data(const char *path, struct pe_file *pe);
int write_file(const char *path, uint8_t *data, size_t len);

int pe_verify(struct pe_file *pe);

int rich_find_header(struct pe_file *pe);
int rich_decode_header(struct pe_file *pe);
void rich_dump_header(struct pe_file *pe);
void rich_strip_header(struct pe_file *pe);
uint32_t rich_verify_checksum(struct pe_file *pe);

#endif
