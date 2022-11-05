#include <iostream>
#include <string.h>


using namespace std;

void printBits16(int32_t t) {
    for (int i = 16 - 1; i >= 0; i--) {
        cout << ((t & (1 << i)) >> i);
    }
    cout << endl;
}

void printBits32(int32_t t) {
    for (int i = 32 - 1; i >= 0; i--) {
        cout << ((t & (1 << i)) >> i);
    }
    cout << endl;
}

void printBits64(int64_t t) {
    for (int i = 64 - 1; i >= 0; i--) {
        cout << ((t & (1 << i)) >> i);
    }
    cout << endl;
}

int main() {

    float num1 = 112312.25f;

    int16_t byte1[2] = {0};
    
    
    memcpy(byte1, &num1, 4);

    
    int32_t byte;
    memcpy(&byte, &num1, 4);

    printBits32(byte);
    printBits16(byte1[0]);
    printBits16(byte1[1]);

    return 0;

}