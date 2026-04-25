/* PC-state VM running an i64 byte-swap built from explicit shifts and
 * masks (no intrinsic) in a variable-trip loop.  Even-trip values produce
 * identity; odd-trip values produce a single byte-swap of the input.
 *   for i in 0..n: state = byteswap_via_shifts_and_masks(state)
 * Variable trip n = (x & 7) + 1.
 * Lift target: vm_bswap64_loop_target.
 *
 * Distinct from vm_imported_bswap_loop (i32 _byteswap_ulong intrinsic):
 * exercises the explicit 8-way mask+shift+or fan-in lowering on full i64
 * state.  The lifter likely recognizes this as llvm.bswap.i64 after
 * optimization.
 */
#include <stdio.h>
#include <stdint.h>

enum BsVmPc {
    BS_LOAD       = 0,
    BS_INIT       = 1,
    BS_LOOP_CHECK = 2,
    BS_LOOP_BODY  = 3,
    BS_LOOP_INC   = 4,
    BS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_bswap64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = BS_LOAD;

    while (1) {
        if (pc == BS_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = BS_INIT;
        } else if (pc == BS_INIT) {
            idx = 0;
            pc = BS_LOOP_CHECK;
        } else if (pc == BS_LOOP_CHECK) {
            pc = (idx < n) ? BS_LOOP_BODY : BS_HALT;
        } else if (pc == BS_LOOP_BODY) {
            state = ((state & 0x00000000000000FFull) << 56) |
                    ((state & 0x000000000000FF00ull) << 40) |
                    ((state & 0x0000000000FF0000ull) << 24) |
                    ((state & 0x00000000FF000000ull) << 8)  |
                    ((state & 0x000000FF00000000ull) >> 8)  |
                    ((state & 0x0000FF0000000000ull) >> 24) |
                    ((state & 0x00FF000000000000ull) >> 40) |
                    ((state & 0xFF00000000000000ull) >> 56);
            pc = BS_LOOP_INC;
        } else if (pc == BS_LOOP_INC) {
            idx = idx + 1;
            pc = BS_LOOP_CHECK;
        } else if (pc == BS_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bswap64(0x123456789ABCDEF0)=0x%llx vm_bswap64(0xCAFE)=0x%llx\n",
           (unsigned long long)vm_bswap64_loop_target(0x123456789ABCDEF0ull),
           (unsigned long long)vm_bswap64_loop_target(0xCAFEull));
    return 0;
}
