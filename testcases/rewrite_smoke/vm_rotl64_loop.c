/* PC-state VM running an iterated 64-bit left rotation.
 *   amount = (x & 0x1F) + 1     (range 1..32, safe for u64 shift)
 *   n      = ((x >> 5) & 7) + 1 (range 1..8)
 *   state  = x; for i in 0..n: state = rotl64(state, amount)
 * Returns the full uint64_t state.
 * Lift target: vm_rotl64_loop_target.
 *
 * Distinct from vm_imported_rotl_loop (i32 rotation via _rotl) and
 * vm_rotate_loop: this exercises 64-bit rotation in a variable-trip loop,
 * lowering through llvm.fshl.i64 (or shift+or pair) on i64 state.
 */
#include <stdio.h>
#include <stdint.h>

enum R64VmPc {
    R64_LOAD       = 0,
    R64_INIT       = 1,
    R64_LOOP_CHECK = 2,
    R64_LOOP_BODY  = 3,
    R64_LOOP_INC   = 4,
    R64_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_rotl64_loop_target(uint64_t x) {
    int      idx    = 0;
    int      n      = 0;
    int      amount = 0;
    uint64_t state  = 0;
    int      pc     = R64_LOAD;

    while (1) {
        if (pc == R64_LOAD) {
            amount = (int)(x & 0x1Full) + 1;
            n      = (int)((x >> 5) & 7ull) + 1;
            state  = x;
            pc = R64_INIT;
        } else if (pc == R64_INIT) {
            idx = 0;
            pc = R64_LOOP_CHECK;
        } else if (pc == R64_LOOP_CHECK) {
            pc = (idx < n) ? R64_LOOP_BODY : R64_HALT;
        } else if (pc == R64_LOOP_BODY) {
            state = (state << amount) | (state >> (64 - amount));
            pc = R64_LOOP_INC;
        } else if (pc == R64_LOOP_INC) {
            idx = idx + 1;
            pc = R64_LOOP_CHECK;
        } else if (pc == R64_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_rotl64(0xCAFE)=0x%llx vm_rotl64(0x123456789ABCDEF0)=0x%llx\n",
           (unsigned long long)vm_rotl64_loop_target(0xCAFEull),
           (unsigned long long)vm_rotl64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
