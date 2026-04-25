/* PC-state VM that cyclically shifts BYTES of x by an input-derived
 * amount (top byte bits 0..2 select the rotation).
 *   shift = (x >> 56) & 7;
 *   result = 0;
 *   for i in 0..8:
 *     byte = (x >> (i*8)) & 0xFF
 *     result |= byte << (((i + shift) & 7) * 8)
 *   return result;
 * Lift target: vm_bytecyc64_loop_target.
 *
 * Distinct from vm_bswap64_loop (full 8-byte reverse) and vm_rotl64_loop
 * (bit-level rotation): byte-granularity cyclic permutation with
 * input-derived shift amount.  Each byte goes to position (i+shift)&7.
 */
#include <stdio.h>
#include <stdint.h>

enum BcVmPc {
    BC_LOAD       = 0,
    BC_INIT       = 1,
    BC_LOOP_CHECK = 2,
    BC_LOOP_BODY  = 3,
    BC_LOOP_INC   = 4,
    BC_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_bytecyc64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t shift  = 0;
    uint64_t result = 0;
    int      pc     = BC_LOAD;

    while (1) {
        if (pc == BC_LOAD) {
            xx     = x;
            shift  = (x >> 56) & 7ull;
            result = 0ull;
            pc = BC_INIT;
        } else if (pc == BC_INIT) {
            idx = 0;
            pc = BC_LOOP_CHECK;
        } else if (pc == BC_LOOP_CHECK) {
            pc = (idx < 8) ? BC_LOOP_BODY : BC_HALT;
        } else if (pc == BC_LOOP_BODY) {
            uint64_t byte = (xx >> (idx * 8)) & 0xFFull;
            uint64_t pos  = ((uint64_t)idx + shift) & 7ull;
            result = result | (byte << (pos * 8));
            pc = BC_LOOP_INC;
        } else if (pc == BC_LOOP_INC) {
            idx = idx + 1;
            pc = BC_LOOP_CHECK;
        } else if (pc == BC_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytecyc64(0x0102030405060708)=0x%llx vm_bytecyc64(0xCAFEBABEDEADBEEF)=0x%llx\n",
           (unsigned long long)vm_bytecyc64_loop_target(0x0102030405060708ull),
           (unsigned long long)vm_bytecyc64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
