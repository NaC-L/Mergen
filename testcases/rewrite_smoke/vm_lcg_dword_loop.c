/* PC-state VM running an LCG-style mixed multiply-and-mask recurrence
 * with u32 mask:
 * Lift target: vm_lcg_dword_loop_target.
 *   key   = x;            // full u32
 *   n     = x & 0xF;      // low 4 bits overlap with low nibble of key
 *   state = 1;
 *   while (n) state = (state * 5 + key + 3) & 0xFFFFFFFF; n--;
 *   return state;
 * Dword-mask variant of vm_lcg_loop (& 0xFF) and vm_lcg_word_loop
 * (& 0xFFFF).  Returns unsigned to make mod-2^32 wrap explicit.
 */
#include <stdio.h>

__declspec(noinline)
unsigned vm_lcg_dword_loop_target(unsigned x) {
    unsigned key   = 0;
    int      n     = 0;
    unsigned state = 0;
    unsigned tmp   = 0;
    int      pc    = 0;

    while (1) {
        if (pc == 0) {
            pc = 1;
        } else if (pc == 1) {
            key = x;
            pc = 2;
        } else if (pc == 2) {
            n = (int)(x & 0xFu);
            pc = 3;
        } else if (pc == 3) {
            state = 1;
            pc = 4;
        } else if (pc == 4) {
            pc = (n > 0) ? 5 : 9;
        } else if (pc == 5) {
            tmp = state * 5u;
            pc = 6;
        } else if (pc == 6) {
            tmp = tmp + key + 3u;
            pc = 7;
        } else if (pc == 7) {
            state = tmp;
            pc = 8;
        } else if (pc == 8) {
            n = n - 1;
            pc = 4;
        } else if (pc == 9) {
            return state;
        } else {
            return 0xFFFFFFFFu;
        }
    }
}

int main(void) {
    printf("vm_lcg_dword_loop(0xCAFEBABE)=%u\n",
           (unsigned)vm_lcg_dword_loop_target(0xCAFEBABEu));
    return 0;
}
