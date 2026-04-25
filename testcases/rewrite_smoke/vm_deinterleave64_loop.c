/* PC-state VM that deinterleaves alternating bits of low 32 bits of x:
 * places even-indexed source bits into low 32 of result, odd-indexed
 * source bits into high 32 of result.
 *   evens = 0;  odds = 0;
 *   for i in 0..32:
 *     evens |= ((x >> (2*i))   & 1) << i;
 *     odds  |= ((x >> (2*i+1)) & 1) << i;
 *   return (odds << 32) | evens;
 * 32-trip fixed loop with FOUR shifts and two OR accumulators.
 * Lift target: vm_deinterleave64_loop_target.
 *
 * Distinct from vm_morton64_loop (interleave/spread one stream into
 * every-other position): this is the INVERSE - splits one input into
 * two streams.  Both accumulator slots update unconditionally with OR
 * (no mutually-exclusive branches), avoiding the dual-i64 promotion
 * failure documented in vm_dualcounter64_loop.
 */
#include <stdio.h>
#include <stdint.h>

enum DiVmPc {
    DI_LOAD       = 0,
    DI_INIT       = 1,
    DI_LOOP_CHECK = 2,
    DI_LOOP_BODY  = 3,
    DI_LOOP_INC   = 4,
    DI_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_deinterleave64_loop_target(uint64_t x) {
    int      idx   = 0;
    uint64_t xx    = 0;
    uint64_t evens = 0;
    uint64_t odds  = 0;
    int      pc    = DI_LOAD;

    while (1) {
        if (pc == DI_LOAD) {
            xx    = x;
            evens = 0ull;
            odds  = 0ull;
            pc = DI_INIT;
        } else if (pc == DI_INIT) {
            idx = 0;
            pc = DI_LOOP_CHECK;
        } else if (pc == DI_LOOP_CHECK) {
            pc = (idx < 32) ? DI_LOOP_BODY : DI_HALT;
        } else if (pc == DI_LOOP_BODY) {
            evens = evens | (((xx >> (2 * idx))     & 1ull) << idx);
            odds  = odds  | (((xx >> (2 * idx + 1)) & 1ull) << idx);
            pc = DI_LOOP_INC;
        } else if (pc == DI_LOOP_INC) {
            idx = idx + 1;
            pc = DI_LOOP_CHECK;
        } else if (pc == DI_HALT) {
            return (odds << 32) | evens;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_deinterleave64(0xAAAAAAAA)=%llu vm_deinterleave64(0x55555555)=%llu\n",
           (unsigned long long)vm_deinterleave64_loop_target(0xAAAAAAAAull),
           (unsigned long long)vm_deinterleave64_loop_target(0x55555555ull));
    return 0;
}
