/* Mixed symbolic + concrete: branch on input then multiply.
 * Lift target: calc_mixed — symbolic arg, one branch, post-merge math.
 * Expected IR: select on (x > 100), then mul by 3. */
#include <stdio.h>
#include <stdint.h>

__declspec(noinline)
int calc_mixed(int x) {
    uint32_t base = 42u;
    uint32_t ux = (uint32_t)x;
    if (x > 100)
        base += ux;
    else
        base -= ux;
    uint32_t scaled = base * 3u;
    return (int)(int32_t)scaled;
}

int main(void) {
    printf("mixed(150)=%d mixed(50)=%d\n",
           calc_mixed(150), calc_mixed(50));
    return 0;
}
