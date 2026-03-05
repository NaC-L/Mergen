/* Mixed symbolic + concrete: branch on input then multiply.
 * Lift target: calc_mixed — symbolic arg, one branch, post-merge math.
 * Expected IR: select on (x > 100), then mul by 3. */
#include <stdio.h>

__declspec(noinline)
int calc_mixed(int x) {
    int base = 42;
    if (x > 100)
        base += x;
    else
        base -= x;
    return base * 3;
}

int main(void) {
    printf("mixed(150)=%d mixed(50)=%d\n",
           calc_mixed(150), calc_mixed(50));
    return 0;
}
