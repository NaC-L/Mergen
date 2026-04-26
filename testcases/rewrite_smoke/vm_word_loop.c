/* PC-state VM with explicit unsigned short (i16) arithmetic recurrence.
 * Lift target: vm_word_loop_target.
 * Goal: cover narrower-type (i16) arithmetic inside a VM dispatcher.
 * state = state * 13 + 5 (mod 65536), iterated symbolic times.
 * Distinct from vm_byte_loop (i8 narrower arithmetic) and the int64
 * family.
 */
#include <stdio.h>

enum WvVmPc {
    WV2_LOAD       = 0,
    WV2_INIT       = 1,
    WV2_CHECK      = 2,
    WV2_BODY_MUL   = 3,
    WV2_BODY_ADD   = 4,
    WV2_BODY_DEC   = 5,
    WV2_HALT       = 6,
};

__declspec(noinline)
int vm_word_loop_target(int x) {
    unsigned short state = 0;
    int n = 0;
    int pc = WV2_LOAD;

    while (1) {
        if (pc == WV2_LOAD) {
            state = (unsigned short)x;
            n = (x >> 16) & 0xF;
            pc = WV2_INIT;
        } else if (pc == WV2_INIT) {
            pc = WV2_CHECK;
        } else if (pc == WV2_CHECK) {
            pc = (n > 0) ? WV2_BODY_MUL : WV2_HALT;
        } else if (pc == WV2_BODY_MUL) {
            state = (unsigned short)(state * 13);
            pc = WV2_BODY_ADD;
        } else if (pc == WV2_BODY_ADD) {
            state = (unsigned short)(state + 5);
            pc = WV2_BODY_DEC;
        } else if (pc == WV2_BODY_DEC) {
            n = n - 1;
            pc = WV2_CHECK;
        } else if (pc == WV2_HALT) {
            return (int)state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_word_loop(0xCAFEBABE)=%d vm_word_loop(0xFFFFFFFF)=%d\n",
           vm_word_loop_target(0xCAFEBABE),
           vm_word_loop_target((int)0xFFFFFFFFu));
    return 0;
}
