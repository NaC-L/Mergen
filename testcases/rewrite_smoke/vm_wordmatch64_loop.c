/* PC-state VM that counts how many of the lower 3 u16 words of x equal
 * the top word of x.
 *   target = (x >> 48) & 0xFFFF;
 *   count = 0;
 *   for i in 0..3:
 *     w = (x >> (i*16)) & 0xFFFF
 *     if w == target: count++
 *   return count;
 * 3-trip fixed loop with word-walking shift + u16-equality compare.
 * Lift target: vm_wordmatch64_loop_target.
 *
 * Distinct from:
 *   - vm_bytematch64_loop (8-bit stride, 7-trip)
 *   - vm_xorwords64_loop  (4-trip XOR-fold over u16 words)
 *   - vm_word_eq_first_count64_loop (eq vs FIRST word with variable trip)
 *
 * Tests u16-equality count via `icmp eq i64` (after masking) inside a
 * fixed 3-trip loop with input-derived top-word target.
 */
#include <stdio.h>
#include <stdint.h>

enum WmVmPc {
    WM2_LOAD       = 0,
    WM2_INIT       = 1,
    WM2_LOOP_CHECK = 2,
    WM2_LOOP_BODY  = 3,
    WM2_LOOP_INC   = 4,
    WM2_HALT       = 5,
};

__declspec(noinline)
int vm_wordmatch64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t target = 0;
    int      count  = 0;
    int      pc     = WM2_LOAD;

    while (1) {
        if (pc == WM2_LOAD) {
            xx     = x;
            target = (x >> 48) & 0xFFFFull;
            count  = 0;
            pc = WM2_INIT;
        } else if (pc == WM2_INIT) {
            idx = 0;
            pc = WM2_LOOP_CHECK;
        } else if (pc == WM2_LOOP_CHECK) {
            pc = (idx < 3) ? WM2_LOOP_BODY : WM2_HALT;
        } else if (pc == WM2_LOOP_BODY) {
            uint64_t w = (xx >> (idx * 16)) & 0xFFFFull;
            if (w == target) {
                count = count + 1;
            }
            pc = WM2_LOOP_INC;
        } else if (pc == WM2_LOOP_INC) {
            idx = idx + 1;
            pc = WM2_LOOP_CHECK;
        } else if (pc == WM2_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_wordmatch64(0x0001000100010001)=%d\n",
           vm_wordmatch64_loop_target(0x0001000100010001ull));
    return 0;
}
