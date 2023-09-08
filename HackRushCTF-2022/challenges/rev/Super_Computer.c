#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

long long flag[] = {6727001931715929522, 6727003031210785000, 6727003031210790177, 6727003031227571798, 6727001927404204942, 6727003026915771844, 6727003026915842557, 6727003031227591731, 6727001931699191403, 6727001927404294817, 6727001931699266776, 6727003026932643854, 6727001931699277127, 6727001931699281789, 6727001931699221428, 6727001927421101290, 6727001931716008227, 6727003026915896664, 6727001927421116049, 6727001927404344263, 6726721551939200255, 6727003026915915829, 6727001927421070445, 6727001927421009570, 6727003026915930842, 6726721551939225105, 6727003026915874889, 6727001931699219582, 6727003026915950262, 6727001931699229677, 6727001927404267045, 6727001931716016475, 6727003026932681875};
long long p = 8310290075942797583;

void processing() {
    printf("beep beep .......\n");
}

long long large_value(long long init) {
    if(init <= 3) {
        return init;
    }
    processing();
    sleep(1);
    return ((large_value(init - 2) + 2) ^ ((large_value(init - 1) + 1) + (large_value(init - 3) + 3))) % p;
}

long long key() {
    return large_value(0xf00de);
}

void kill_program() {
    printf("Wait, this isn't a supercomputer.\n");
    _exit(0);
}

void check_timeout() {
    signal(SIGALRM, kill_program);
    alarm(4);
}

void print_flag(long long key) {
    int n = sizeof(flag)/sizeof(flag[0]);
    char dec_flag[n];
    for(int i = 0; i < n; i++) {
        long long b = flag[i] ^ key;
        long long ans = 0;
        for(int j = 0; j < 64; j += 8) {
            ans |= ((b & 1) << (j / 8));
            b = b >> 8;
        }
        key += 0x1337;
        dec_flag[i] = ans;
    }
    dec_flag[n] = '\x00';
    printf("[*] Flag: %s\n", dec_flag);
}


int main() {
    printf("Welcome to the flag distributor.\n");
    printf("But be careful, you may need a supercomputer to get the flag.\n");
    check_timeout();
    long long k = key();
    print_flag(k);
    return 0;
}
