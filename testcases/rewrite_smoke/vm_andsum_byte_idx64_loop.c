/* PC-state VM that ANDs each byte with the loop index and sums:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFF) & (i + 1));   // byte AND counter, ADD-folded
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_andsum_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_uintadd_byte_idx64_loop  (byte * counter, ADD)
 *   - vm_xormul_byte_idx64_loop   (byte * counter, XOR)
 *   - vm_notand_chain64_loop      (NOT-AND of state, no counter)
 *
 * Tests `and i64 byte, counter` (AND of zext-byte with phi-tracked
 * counter (i+1)) folded via ADD.  Counter values 1..8 are <128 so
 * the AND keeps only low bits of each byte.  All-0xFF input
 * accumulates 1+2+3+...+8 = 36.
 */
#include <stdio.h>
#include <stdint.h>

enum AsVmPc {
    AS_INIT_ALL = 0,
    AS_CHECK    = 1,
    AS_BODY     = 2,
    AS_INC      = 3,
    AS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_andsum_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = AS_INIT_ALL;

    while (1) {
        if (pc == AS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = AS_CHECK;
        } else if (pc == AS_CHECK) {
            pc = (i < n) ? AS_BODY : AS_HALT;
        } else if (pc == AS_BODY) {
            r = r + ((s & 0xFFull) & (i + 1ull));
            s = s >> 8;
            pc = AS_INC;
        } else if (pc == AS_INC) {
            i = i + 1ull;
            pc = AS_CHECK;
        } else if (pc == AS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_andsum_byte_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_andsum_byte_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
