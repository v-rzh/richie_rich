#include <richie_rich.h>
#include <prodid.h>

static void rich_print_header_entry(struct rich_entry *re)
{
    printf("%d\t%d\t\t%s (0x%04x)\n",
           re->use_count, re->minor_version,
           re->prod_id >= PROD_IDS_NO ? "" : prod_ids[re->prod_id],
           re->prod_id);
}

#define LROT(wrd, n)   ((((wrd) << (n)) & 0xffffffff) | ((wrd) >> (32-(n))))

static uint32_t rich_calculate_checksum(struct pe_file *pe)
{
    struct rich_entry *entry;
    uint32_t ret = 0x80, i, tmp;

    for (i=0; i < pe->rich_beg_offt; i++) {
        if (i == PE_HDR_OFFT_OFFT) {
            i += 3;
            continue;
        }
        tmp = (uint32_t) *(pe->data+i);
        if (!tmp) continue;
        ret += LROT(tmp, i);
    }

    i += RICH_FIRST_ENTRY_OFFT;

    for (; i != pe->rich_end_offt; i += 8) {
        entry = (struct rich_entry *)(pe->data + i);
        tmp = (((entry->prod_id) << 16)|(entry->minor_version));
        ret += LROT(tmp, (entry->use_count)&0x1f);
    }

    return ret;
}

uint32_t rich_verify_checksum(struct pe_file *pe)
{
    uint32_t ret = rich_calculate_checksum(pe);
    if (ret != pe->rich_csum)
        return ret;

    return 0;
}

int rich_find_header(struct pe_file *pe)
{
    uint32_t i;

    for (i = pe->rich_beg_offt; i < pe->pe_offt; i++) {
        if (pe->data[i] != 'R')
            continue;

        if ((*(uint32_t*)(pe->data+i)) != RICH_FOOTER)
            continue;

        pe->rich_end_offt = i;
        i += 4;
        pe->rich_csum = *((uint32_t *)(pe->data+i));
        DLOG("[debug] Rich footer found\n"
             "[debug] Checksum/Key: 0x%x\n",
             pe->rich_csum);
        return 0;
    }

    ELOG("[err] Rich footer not found\n");
    return -1;
}

int rich_decode_header(struct pe_file *pe)
{
    uint32_t i, tmp;
    for (i = pe->rich_beg_offt; i < pe->rich_end_offt; i+=8) {
        tmp = *(uint32_t *)(pe->data+i);
        tmp ^= pe->rich_csum;
        *(uint32_t *)(pe->data+i) = tmp;

        if (i == pe->rich_beg_offt) {
            if (tmp != RICH_PTHEADER) {
                ELOG("[err] Rich header not found\n");
                return -1;
            }
            DLOG("[debug] Rich header found\n");
            i += 8;
            continue;
        }
        tmp = *(uint32_t *)(pe->data+i+4);
        tmp ^= pe->rich_csum;
        *(uint32_t *)(pe->data+i+4) = tmp;
    }
    return 0;
}

void rich_dump_header(struct pe_file *pe)
{
    uint32_t i = pe->rich_beg_offt + RICH_FIRST_ENTRY_OFFT;

    puts("------------------------------------------------------\n"
         "Count\tMinor Version\tProdID\n"
         "------------------------------------------------------");

    for (; i < pe->rich_end_offt; i+=8)
        rich_print_header_entry((struct rich_entry *)(pe->data+i));

    putchar('\n');
}

void rich_strip_header(struct pe_file *pe)
{
    size_t rich_hdr_len = pe->pe_offt - pe->rich_beg_offt;
    uint32_t pe_hdrs_sz = U32_PE_SizeOfHeaders(pe)-rich_hdr_len-pe->rich_beg_offt,
             new_true_headers = pe->pe_offt + PE_WITH_WINSPEC_SIZE +
                                U16_PE_SizeOptionalHdr(pe) - rich_hdr_len +
                                (U16_PE_NumberOfSections(pe)*PE_SECTBLENT_SIZE);

    U32_PE_SizeOfHeaders(pe) = PE_NEW_HEADERS_SIZE(new_true_headers,
                                                   U32_PE_FileAlignment(pe));

    memmove(PTR_RICH_HDR(pe), PTR_PE_BEGIN(pe), pe_hdrs_sz);
    pe->pe_offt = pe->rich_beg_offt;
    memset(pe->data+new_true_headers, 0, U32_PE_SizeOfHeaders(pe)-new_true_headers);

    U32_DOS_PE_Offt(pe) = pe->pe_offt;
}
