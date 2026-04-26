/* PC-state VM running an i64 dword-swap (2-way u32 reverse) built from
 * explicit shifts in a variable-trip loop.  Even-trip values produce
 * identity; odd-trip values produce a single dword-swap of x.
 *   for i in 0..n: state = (state << 32) | (state >> 32)
 * Variable trip n = (x & 7) + 1.
 * Lift target: vm_dswap64_loop_target.
 *
 * Distinct from:
 *   - vm_wswap64_loop (4-way word-reverse on full i64)
 *   - vm_bswap64_loop (8-way byte-reverse, may fold to llvm.bswap.i64)
 *   - vm_dwordrev_window64_loop (variable-window dword pack with input-
 *     derived trip count)
 *
 * Tests the canonical 2-way dword swap (rotate-by-32 equivalent).
 * Likely folds to llvm.fshl.i64 or a single ror64 by 32; the lifter
 * may collapse the loop after fixed-trip recognition.
 */
#include <stdio.h>
#include <stdint.h>

enum DsVmPc {
    DSW_LOAD       = 0,
    DSW_INIT       = 1,
    DSW_LOOP_CHECK = 2,
    DSW_LOOP_BODY  = 3,
    DSW_LOOP_INC   = 4,
    DSW_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_dswap64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = DSW_LOAD;

    while (1) {
        if (pc == DSW_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = DSW_INIT;
        } else if (pc == DSW_INIT) {
            idx = 0;
            pc = DSW_LOOP_CHECK;
        } else if (pc == DSW_LOOP_CHECK) {
            pc = (idx < n) ? DSW_LOOP_BODY : DSW_HALT;
        } else if (pc == DSW_LOOP_BODY) {
            state = (state << 32) | (state >> 32);
            pc = DSW_LOOP_INC;
        } else if (pc == DSW_LOOP_INC) {
            idx = idx + 1;
            pc = DSW_LOOP_CHECK;
        } else if (pc == DSW_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dswap64(0x123456789ABCDEF0)=0x%llx\n",
           (unsigned long long)vm_dswap64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
