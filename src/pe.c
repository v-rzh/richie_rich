#include <richie_rich.h>

int pe_verify(struct pe_file *pe)
{
    if (U16_DOS_Magic(pe) != DOS_MAGIC) {
        ELOG("[err] DOS header not found\n");
        return -1;
    }

    pe->pe_offt = U32_DOS_PE_Offt(pe);
    DLOG("[debug] PE header @ 0x%x\n", pe->pe_offt);

    if (U32_PE_Magic(pe) != PE_MAGIC) {
        ELOG("[err] PE header not found\n");
        return -1;
    }
    return 0;
}
