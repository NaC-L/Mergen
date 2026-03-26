/* Jump table test: MSVC /O2 should emit a real jump table for 7+ dense cases.
 * Lift target: calc_jumptable
 * Expected IR: switch (or equivalent multi-target branch) on symbolic input.
 *
 * NOTE: Must be compiled with /O2 (not /Od) to generate jmp [table + reg*8].
 * /Od generates compare chains which the lifter already handles. */

#include <stdio.h>

__declspec(noinline)
int calc_jumptable(int op) {
    switch (op) {
    case 0: return 1;
    case 1: return 2;
    case 2: return 4;
    case 3: return 8;
    case 4: return 16;
    case 5: return 32;
    case 6: return 64;
    case 7: return 128;
    case 8: return 256;
    case 9: return 512;
    default: return -1;
    }
}

int main(void) {
    printf("jt(0)=%d jt(5)=%d jt(9)=%d jt(99)=%d\n",
           calc_jumptable(0), calc_jumptable(5),
           calc_jumptable(9), calc_jumptable(99));
    return 0;
}
