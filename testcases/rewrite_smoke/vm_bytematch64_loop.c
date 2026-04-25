/* PC-state VM that counts how many of the lower 7 bytes of x equal the
 * top byte of x.
 *   target = (x >> 56) & 0xFF;
 *   count = 0;
 *   for i in 0..7:
 *     byte = (x >> (i*8)) & 0xFF
 *     if byte == target: count++
 *   return count;
 * 7-trip fixed loop with byte-walking shift + byte-equality compare.
 * Lift target: vm_bytematch64_loop_target.
 *
 * Distinct from vm_xorbytes64_loop (XOR-fold) and vm_djb264_loop
 * (multiplicative hash): byte-equality count via icmp eq i64 (after
 * masking) inside a fixed loop with input-derived target byte.
 */
#include <stdio.h>
#include <stdint.h>

enum BmVmPc {
    BM_LOAD       = 0,
    BM_INIT       = 1,
    BM_LOOP_CHECK = 2,
    BM_LOOP_BODY  = 3,
    BM_LOOP_INC   = 4,
    BM_HALT       = 5,
};

__declspec(noinline)
int vm_bytematch64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t target = 0;
    int      count  = 0;
    int      pc     = BM_LOAD;

    while (1) {
        if (pc == BM_LOAD) {
            xx     = x;
            target = (x >> 56) & 0xFFull;
            count  = 0;
            pc = BM_INIT;
        } else if (pc == BM_INIT) {
            idx = 0;
            pc = BM_LOOP_CHECK;
        } else if (pc == BM_LOOP_CHECK) {
            pc = (idx < 7) ? BM_LOOP_BODY : BM_HALT;
        } else if (pc == BM_LOOP_BODY) {
            uint64_t b = (xx >> (idx * 8)) & 0xFFull;
            if (b == target) {
                count = count + 1;
            }
            pc = BM_LOOP_INC;
        } else if (pc == BM_LOOP_INC) {
            idx = idx + 1;
            pc = BM_LOOP_CHECK;
        } else if (pc == BM_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_bytematch64(0x0101010101010101)=%d vm_bytematch64(0xCAFEBABE)=%d\n",
           vm_bytematch64_loop_target(0x0101010101010101ull),
           vm_bytematch64_loop_target(0xCAFEBABEull));
    return 0;
}
