#include <richie_rich.h>

static void usage(const char *n) __attribute__((noreturn));

static void usage(const char *n)
{

    ELOG("Usage: %s <-i path_to_pe> [-w out_file] [-o rich_header_offset] "
         "[-v] [-s] \n\n", n);
    ELOG("  -i\tPath to the subject PE (required)\n");
    ELOG("  -s\tStrip the rich header from the executable (requires -w)\n");
    ELOG("  -w\tPath to the new PE file\n");
    ELOG("  -o\tSet a custom rich header offset (default is %lu)\n",
         RICH_DEFAULT_HEADER_OFFT);
    ELOG("  -v\tVerify the Rich header checksum\n\n");
    exit(1);
}

uint8_t options = 0;

int main(int argc, char **argv)
{
    int opt;
    const char *in_file = NULL,
               *out_file = NULL;
    struct pe_file pe;

    pe.rich_beg_offt = 0;

    while ((opt = getopt(argc, argv, "vso:w:i:")) != -1) {
        switch (opt) {
        case 'o':
            unsigned long tmp = strtoul(optarg, NULL, 10);
            if (tmp > UINT_MAX) {
                ELOG("[err] Invalid Rich Header offset: %s\n", optarg);
                return 1;
            }
            pe.rich_beg_offt = (uint32_t)tmp;
            DLOG("[debug] Custom Rich header offset: 0x%x\n",
                 pe.rich_beg_offt);
            break;
        case 'i':
            in_file = optarg;
            break;
        case 'w':
            out_file = optarg;
            break;
        case 'v':
            options |= OPT_VERIFY;
            break;
        case 's':
            options |= OPT_STRIP;
            break;
        default:
            usage(argv[0]);
            break;
        }
    }

    if (!in_file)
        usage(argv[0]);

    if (STRIP_HEADER(options) && !out_file)
        usage(argv[0]);

    if (!pe.rich_beg_offt)
        pe.rich_beg_offt = RICH_DEFAULT_HEADER_OFFT;

    if (get_file_data(in_file, &pe) == -1)
        return 1;

    if (pe_verify(&pe) == -1)
        goto end;

    if (rich_find_header(&pe) == -1)
        goto end;

    if (rich_decode_header(&pe) == -1)
        goto end;

    rich_dump_header(&pe);

    if (VERIFY_CHECKSUM(options)) {
        uint32_t real_checksum = rich_verify_checksum(&pe);
        if (real_checksum) {
            ILOG("[info] The Rich header checksum is invalid\n"
                 "[info] Checksum in the header:\t0x%08x\n"
                 "[info] Real checksum:\t\t0x%08x\n",
                 pe.rich_csum, real_checksum);
        } else {
            ILOG("[info] The Rich header checksum is valid\n");
        }
    }

    if (STRIP_HEADER(options)) {
        ILOG("[info] Stripping the Rich header (output in \"%s\")\n", out_file);
        rich_strip_header(&pe);
        write_file(out_file, pe.data, pe.len);
    }

end:
#ifdef _WINDOWS
    HeapFree(pe.data, 0, NULL);
#else
    munmap(pe.data, pe.len);
#endif
    return 0;
}
