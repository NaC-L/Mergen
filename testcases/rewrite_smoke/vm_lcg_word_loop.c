/* PC-state VM running an LCG-style mixed multiply-and-mask recurrence
 * with u16 mask:
 * Lift target: vm_lcg_word_loop_target.
 *   key   = x & 0xFFFF;
 *   n     = x & 0xF;     // low 4 bits overlap with low nibble of key
 *   state = 1;
 *   while (n) state = (state * 5 + key + 3) & 0xFFFF; n--;
 *   return state;
 * Word-mask variant of vm_lcg_loop (uses & 0xFF).  Both key and
 * iteration count are derived from x; n overlaps with key's low nibble
 * mirroring the byte-stride sample.
 */
#include <stdio.h>

enum LcwVmPc {
    LGW_INIT       = 0,
    LGW_LOAD_KEY   = 1,
    LGW_LOAD_N     = 2,
    LGW_INIT_STATE = 3,
    LGW_CHECK      = 4,
    LGW_BODY_MUL   = 5,
    LGW_BODY_ADD   = 6,
    LGW_BODY_MASK  = 7,
    LGW_BODY_DEC   = 8,
    LGW_HALT       = 9,
};

__declspec(noinline)
int vm_lcg_word_loop_target(int x) {
    int key   = 0;
    int n     = 0;
    int state = 0;
    int tmp   = 0;
    int pc    = LGW_INIT;

    while (1) {
        if (pc == LGW_INIT) {
            pc = LGW_LOAD_KEY;
        } else if (pc == LGW_LOAD_KEY) {
            key = x & 0xFFFF;
            pc = LGW_LOAD_N;
        } else if (pc == LGW_LOAD_N) {
            n = x & 0xF;
            pc = LGW_INIT_STATE;
        } else if (pc == LGW_INIT_STATE) {
            state = 1;
            pc = LGW_CHECK;
        } else if (pc == LGW_CHECK) {
            pc = (n > 0) ? LGW_BODY_MUL : LGW_HALT;
        } else if (pc == LGW_BODY_MUL) {
            tmp = state * 5;
            pc = LGW_BODY_ADD;
        } else if (pc == LGW_BODY_ADD) {
            tmp = tmp + key + 3;
            pc = LGW_BODY_MASK;
        } else if (pc == LGW_BODY_MASK) {
            state = tmp & 0xFFFF;
            pc = LGW_BODY_DEC;
        } else if (pc == LGW_BODY_DEC) {
            n = n - 1;
            pc = LGW_CHECK;
        } else if (pc == LGW_HALT) {
            return state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_lcg_word_loop(0xCAFE)=%d vm_lcg_word_loop(255)=%d\n",
           vm_lcg_word_loop_target(0xCAFE), vm_lcg_word_loop_target(255));
    return 0;
}
