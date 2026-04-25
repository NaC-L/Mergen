/* PC-state VM running a four-state phi chain on full uint64_t.
 *   a = x;  b = ~x;  c = x ^ K1;  d = x ^ K2;
 *   for i in 0..n: { t = a + b + c + d; a = b; b = c; c = d; d = t; }
 *   return d;
 * Variable trip n = (x & 0xF) + 1.
 * Lift target: vm_4state64_loop_target.
 *
 * Distinct from vm_fibonacci64_loop (2 states) and vm_tribonacci64_loop
 * (3 states): exercises a 4-state direct-shift phi chain on full i64.
 * Each new t reads ALL four previous values; only single-direction
 * shift (a<-b<-c<-d<-t) so no compound cross-update issue.
 */
#include <stdio.h>
#include <stdint.h>

enum F4VmPc {
    F4_LOAD       = 0,
    F4_INIT       = 1,
    F4_LOOP_CHECK = 2,
    F4_LOOP_BODY  = 3,
    F4_LOOP_INC   = 4,
    F4_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_4state64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t a   = 0;
    uint64_t b   = 0;
    uint64_t c   = 0;
    uint64_t d   = 0;
    uint64_t t   = 0;
    int      pc  = F4_LOAD;

    while (1) {
        if (pc == F4_LOAD) {
            n = (int)(x & 0xFull) + 1;
            a = x;
            b = ~x;
            c = x ^ 0xCAFEBABEDEADBEEFull;
            d = x ^ 0x9E3779B97F4A7C15ull;
            pc = F4_INIT;
        } else if (pc == F4_INIT) {
            idx = 0;
            pc = F4_LOOP_CHECK;
        } else if (pc == F4_LOOP_CHECK) {
            pc = (idx < n) ? F4_LOOP_BODY : F4_HALT;
        } else if (pc == F4_LOOP_BODY) {
            t = a + b + c + d;
            a = b;
            b = c;
            c = d;
            d = t;
            pc = F4_LOOP_INC;
        } else if (pc == F4_LOOP_INC) {
            idx = idx + 1;
            pc = F4_LOOP_CHECK;
        } else if (pc == F4_HALT) {
            return d;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_4state64(0xCAFE)=%llu vm_4state64(0xFF)=%llu\n",
           (unsigned long long)vm_4state64_loop_target(0xCAFEull),
           (unsigned long long)vm_4state64_loop_target(0xFFull));
    return 0;
}
