#include <iostream>
#include <cmath>

using namespace std;

int main() {

    // compute a^x
    int a = 30;
    int x = 65535;
    int res = 1;

    int mulcnt = 0;

    for (int i = x - 1; i > 0; i >>= 1) {
        mulcnt++;
        if(i&1) {
            res =  (a * res) % x;
        }
        a = (a * a) % x;
    }    

    cout << "mulcnt: " << mulcnt << endl;
    cout << "res: " << res << endl;
    cout << log2(65525) << endl;
}