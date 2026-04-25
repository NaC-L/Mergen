/* PC-state VM that XOR-folds u16 words over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r ^ (s & 0xFFFF);
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_word_xorfold64_loop_target.
 *
 * Distinct from:
 *   - vm_word_addchain64_loop  (ADD)
 *   - vm_word_orfold64_loop    (OR)
 *   - vm_word_andfold64_loop   (AND)
 *   - vm_word_subchain64_loop  (SUB)
 *   - vm_word_xormul64_loop    (XOR with self-multiply)
 *
 * Completes the basic fold-op set for u16 word stride: ADD, SUB, OR,
 * AND, XOR.  Pairs of equal words cancel under XOR.
 */
#include <stdio.h>
#include <stdint.h>

enum WfVmPc {
    WF_INIT_ALL = 0,
    WF_CHECK    = 1,
    WF_BODY     = 2,
    WF_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_xorfold64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = WF_INIT_ALL;

    while (1) {
        if (pc == WF_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            pc = WF_CHECK;
        } else if (pc == WF_CHECK) {
            pc = (n > 0ull) ? WF_BODY : WF_HALT;
        } else if (pc == WF_BODY) {
            r = r ^ (s & 0xFFFFull);
            s = s >> 16;
            n = n - 1ull;
            pc = WF_CHECK;
        } else if (pc == WF_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_xorfold64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_xorfold64_loop_target(0xCAFEBABEull));
    return 0;
}
