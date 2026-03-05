/* Test: function with cout call.
 * Lift target: calc_cout — external call handling.
 * The computation is pure, but it calls cout before returning. */
#include <iostream>

__declspec(noinline)
int calc_cout(int x) {
    int result = x * 3 + 7;
    std::cout << result;
    return result;
}

int main() {
    int r = calc_cout(10);
    return r;
}
