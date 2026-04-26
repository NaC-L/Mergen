/* PC-state VM that OR-folds u8 bytes over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r | (s & 0xFF);
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_byte_orfold64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_andfold64_loop  (AND fold, monotone DECREASING)
 *   - vm_word_orfold64_loop   (OR fold at 16-bit stride)
 *   - vm_orsum_byte_idx64_loop (byte | counter, OR-with-counter not OR fold)
 *
 * Tests `or i64` chain at byte stride.  OR fold is monotone INCREASING
 * (only sets bits) - counterpart to AND's monotone decreasing.  All-FF
 * input yields r=0xFF.
 */
#include <stdio.h>
#include <stdint.h>

enum BoVmPc {
    BO_INIT_ALL = 0,
    BO_CHECK    = 1,
    BO_BODY     = 2,
    BO_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_orfold64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = BO_INIT_ALL;

    while (1) {
        if (pc == BO_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            pc = BO_CHECK;
        } else if (pc == BO_CHECK) {
            pc = (n > 0ull) ? BO_BODY : BO_HALT;
        } else if (pc == BO_BODY) {
            r = r | (s & 0xFFull);
            s = s >> 8;
            n = n - 1ull;
            pc = BO_CHECK;
        } else if (pc == BO_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_orfold64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_byte_orfold64_loop_target(0xCAFEBABEull));
    return 0;
}
