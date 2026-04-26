/* PC-state VM with explicit unsigned int (i32) arithmetic recurrence.
 * Lift target: vm_dword_loop_target.
 * Goal: cover i32 arithmetic inside a VM dispatcher (already the
 * default int width on Win64 / x86-64; this exercises explicit u32
 * mod-2^32 wrap behavior).
 * state = state * 1103515245u + 12345u, iterated symbolic times.
 * Distinct from vm_byte_loop (i8) and vm_word_loop (i16); uses ANSI
 * rand() constants but on each iter rather than the LCG-chain sample
 * which iterates over a fixed 8 trips.
 */
#include <stdio.h>

enum DvVmPc {
    DV2_LOAD       = 0,
    DV2_INIT       = 1,
    DV2_CHECK      = 2,
    DV2_BODY_MUL   = 3,
    DV2_BODY_ADD   = 4,
    DV2_BODY_DEC   = 5,
    DV2_HALT       = 6,
};

__declspec(noinline)
unsigned vm_dword_loop_target(unsigned x) {
    unsigned state = 0;
    int n = 0;
    int pc = DV2_LOAD;

    while (1) {
        if (pc == DV2_LOAD) {
            state = x;
            n = (int)((x >> 28) & 0xF);
            pc = DV2_INIT;
        } else if (pc == DV2_INIT) {
            pc = DV2_CHECK;
        } else if (pc == DV2_CHECK) {
            pc = (n > 0) ? DV2_BODY_MUL : DV2_HALT;
        } else if (pc == DV2_BODY_MUL) {
            state = state * 1103515245u;
            pc = DV2_BODY_ADD;
        } else if (pc == DV2_BODY_ADD) {
            state = state + 12345u;
            pc = DV2_BODY_DEC;
        } else if (pc == DV2_BODY_DEC) {
            n = n - 1;
            pc = DV2_CHECK;
        } else if (pc == DV2_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFu;
        }
    }
}

int main(void) {
    printf("vm_dword_loop(0xCAFEBABE)=%u vm_dword_loop(0xFFFFFFFF)=%u\n",
           (unsigned)vm_dword_loop_target(0xCAFEBABEu),
           (unsigned)vm_dword_loop_target(0xFFFFFFFFu));
    return 0;
}
