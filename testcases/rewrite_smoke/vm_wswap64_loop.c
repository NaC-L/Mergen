/* PC-state VM running an i64 word-swap (4-way u16 reverse) built from
 * explicit shifts and masks in a variable-trip loop.  Even-trip values
 * produce identity; odd-trip values produce a single word-swap of x.
 *   for i in 0..n: state = wordswap_via_shifts_and_masks(state)
 * Variable trip n = (x & 7) + 1.
 * Lift target: vm_wswap64_loop_target.
 *
 * Distinct from:
 *   - vm_bswap64_loop (8-way byte-reverse, may fold to llvm.bswap.i64)
 *   - vm_wordrev_window64_loop (variable-window reverse with input-derived
 *     trip count, partial reverse for n<4)
 *
 * Tests the explicit 4-way mask+shift+or fan-in for u16 lanes on the
 * full i64 state.  Likely no LLVM intrinsic recognition: word-reverse
 * is not bswap.
 */
#include <stdio.h>
#include <stdint.h>

enum WsVmPc {
    WS_LOAD       = 0,
    WS_INIT       = 1,
    WS_LOOP_CHECK = 2,
    WS_LOOP_BODY  = 3,
    WS_LOOP_INC   = 4,
    WS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_wswap64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = WS_LOAD;

    while (1) {
        if (pc == WS_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = WS_INIT;
        } else if (pc == WS_INIT) {
            idx = 0;
            pc = WS_LOOP_CHECK;
        } else if (pc == WS_LOOP_CHECK) {
            pc = (idx < n) ? WS_LOOP_BODY : WS_HALT;
        } else if (pc == WS_LOOP_BODY) {
            state = ((state & 0x000000000000FFFFull) << 48) |
                    ((state & 0x00000000FFFF0000ull) << 16) |
                    ((state & 0x0000FFFF00000000ull) >> 16) |
                    ((state & 0xFFFF000000000000ull) >> 48);
            pc = WS_LOOP_INC;
        } else if (pc == WS_LOOP_INC) {
            idx = idx + 1;
            pc = WS_LOOP_CHECK;
        } else if (pc == WS_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_wswap64(0x123456789ABCDEF0)=0x%llx\n",
           (unsigned long long)vm_wswap64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
