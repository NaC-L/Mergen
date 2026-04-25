/* PC-state VM that counts bytes whose value is <= 0x7F (low half):
 *
 *   n = (x & 7) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     cnt = cnt + ((b <= 0x7F) ? 1 : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_ule_thresh_count64_loop_target.
 *
 * Tests `icmp ule` predicate at byte stride.  Adds `ule` to the
 * cmp-counter coverage matrix (which previously had eq/ne/ult/ugt/uge/slt).
 */
#include <stdio.h>
#include <stdint.h>

enum BleVmPc {
    BLE_INIT_ALL = 0,
    BLE_CHECK    = 1,
    BLE_BODY     = 2,
    BLE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_ule_thresh_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = BLE_INIT_ALL;

    while (1) {
        if (pc == BLE_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = BLE_CHECK;
        } else if (pc == BLE_CHECK) {
            pc = (n > 0ull) ? BLE_BODY : BLE_HALT;
        } else if (pc == BLE_BODY) {
            uint64_t b = s & 0xFFull;
            cnt = cnt + ((b <= 0x7Full) ? 1ull : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BLE_CHECK;
        } else if (pc == BLE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_ule_thresh_count64(0x7F7F7F7F7F7F7F7F)=%llu\n",
           (unsigned long long)vm_byte_ule_thresh_count64_loop_target(0x7F7F7F7F7F7F7F7Full));
    return 0;
}
