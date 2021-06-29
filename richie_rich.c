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

#include "prodid.h"

#define PE_MAGIC                    0x4550
#define DOS_MAGIC                   0x5a4d
#define RICH_FOOTER                 0x68636952
#define RICH_PTHEADER               0x536e6144

#define PE_HDR_OFFT_OFFT            0x3c
#define DEFAULT_RICH_HEADER_OFFT    0x80


#ifdef DEBUG_BUILD
#define DLOG(fmt, ...)                  \
    printf(fmt, ##__VA_ARGS__)
#else
#define DLOG(fmt, ...)
#endif

#define ELOG(fmt, ...)                  \
    fprintf(stderr, fmt, ##__VA_ARGS__)

struct pe_file {
    uint8_t *data;
    size_t len;
    uint32_t pe_offt;
    uint32_t rich_beg_offt;
    uint32_t rich_end_offt;
    uint32_t rich_key;
};

struct rich_entry {
    uint16_t minor_version;
    uint16_t prod_id;
    uint32_t use_count;
};

static void usage(const char *n) __attribute__((noreturn));

static void usage(const char *n)
{

    ELOG("Usage: %s <path_to_pe> [rich_header_offset]\n", n);
    exit(1);
}

#ifdef _WINDOWS
int get_file_data(const char *path, struct pe_file *pe)
{
    HANDLE fd, proc_heap;
    DWORD file_size, bytes_read;

    fd = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL, NULL);
    if (fd == INVALID_HANDLE_VALUE) {
        ELOG("[err] CreateFileA: (ERR: %d)\n", GetLastError());
        return -1;
    }

    file_size = GetFileSize(fd, NULL);

    if (file_size == INVALID_FILE_SIZE) {
        ELOG("[err] GetFileSize: (ERR: %d)\n", GetLastError());
        return -1;
    }

    if (!(proc_heap = GetProcessHeap())) {
        ELOG("[err] GetProcessHeap: (ERR: %d)\n", GetLastError());
        return -1;
    }

    if (!(pe->data = (uint8_t *)HeapAlloc(proc_heap, 0, file_size))) {
        ELOG("[err] HeapAlloc: An exception has occured\n");
        return -1;
    }

    if (!ReadFile(fd, pe->data, file_size, &bytes_read, NULL)) {
        ELOG("[err] ReadFile: (ERR: %d)\n", GetLastError());
        CloseHandle(fd);
        return -1;
    }

    CloseHandle(fd);
    return 0;
}
#else
int get_file_data(const char *path, struct pe_file *pe)
{
    int fd;
    struct stat pe_stat;

    memset(&pe_stat, 0, sizeof(struct stat));

    if (stat(path, &pe_stat) == -1) {
        ELOG("[err] stat: %s\n", strerror(errno));
        return -1;
    }

    if ((fd = open(path, O_RDWR)) == -1) {
        ELOG("[err] open: %s\n", strerror(errno));
        return -1;
    }

    pe->len = pe_stat.st_size;

    pe->data = mmap(NULL, pe->len, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                    fd, 0);

    close(fd);

    if (pe->data == MAP_FAILED) {
        ELOG("[err] mmap: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
#endif

int verify_pe(struct pe_file *pe)
{
    if (*((uint16_t *)(pe->data)) != DOS_MAGIC) {
        ELOG("[err] DOS header not found\n");
        return 0;
    }

    pe->pe_offt = *((uint32_t *)(pe->data+PE_HDR_OFFT_OFFT));
    DLOG("[debug] PE header @ 0x%x\n", pe->pe_offt);

    if (*((uint16_t *)(pe->data+pe->pe_offt)) != PE_MAGIC) {
        ELOG("[err] PE header not found\n");
        return 0;
    }
    return 1;
}

int find_rich_header(struct pe_file *pe)
{
    uint32_t i;

    for (i = pe->rich_beg_offt; i < pe->pe_offt; i++) {
        if (pe->data[i] != 'R')
            continue;

        if ((*(uint32_t*)(pe->data+i)) != RICH_FOOTER)
            continue;

        pe->rich_end_offt = i;
        i += 4;
        pe->rich_key = *((uint32_t *)(pe->data+i));
        DLOG("[debug] Rich footer found\n"
             "[debug] Checksum/Key: 0x%x\n",
             pe->rich_key);
        return 1;
    }

    puts("[err] Rich footer not found");
    return 0;
}

void print_rich_header_entry(struct rich_entry *re)
{
    int i;
    printf("%d\t%d\t\t%s (0x%04x)\n",
           re->use_count, re->minor_version,
           re->prod_id >= PROD_IDS_NO ? "" : prod_ids[re->prod_id],
           re->prod_id);
}


void decode_dump_rich_header(struct pe_file *pe)
{
    struct rich_entry *entry;
    uint32_t tmp;
    uint32_t i;

    for (i = pe->rich_beg_offt; i < pe->rich_end_offt; i+=8) {

        tmp = *(uint32_t *)(pe->data+i);
        tmp ^= pe->rich_key;
        *(uint32_t *)(pe->data+i) = tmp;

        if (i == pe->rich_beg_offt) {
            if (tmp != RICH_PTHEADER) {
                ELOG("[err] Rich header not found\n");
                return;
            }
            DLOG("[debug] Rich header found\n");
            i += 8;
            printf("------------------------------------------------------\n");
            printf("Count\tMinor Version\tProdID\n");
            printf("------------------------------------------------------\n");
            continue;
        }

        tmp = *(uint32_t *)(pe->data+i+4);
        tmp ^= pe->rich_key;
        *(uint32_t *)(pe->data+i+4) = tmp;

        print_rich_header_entry((struct rich_entry *)(pe->data+i));
    }
}

int main(int argc, char **argv)
{
    struct pe_file pe;

    if (argc == 3) {
        unsigned long tmp = strtoul(argv[2], NULL, 10);
        if (tmp > UINT_MAX) {
            ELOG("[err] Invalid Rich Header offset: %s\n", argv[2]);
            return 1;
        }
        pe.rich_beg_offt = (uint32_t)tmp;
        DLOG("[debug] Custom Rich header offset: 0x%x\n", pe.rich_beg_offt);
    } else if (argc == 2) {
        pe.rich_beg_offt = DEFAULT_RICH_HEADER_OFFT;
    } else {
        usage(argv[0]);
    }

    if (get_file_data(argv[1], &pe) == -1)
        return 1;

    if (!verify_pe(&pe))
        goto end;

    if (!find_rich_header(&pe))
        goto end;

    decode_dump_rich_header(&pe);

end:
#ifdef _WINDOWS
    HeapFree(pe.data, 0, NULL);
#else
    munmap(pe.data, pe.len);
#endif
    return 0;
}

