#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* flag = "\x11Xxy4^|Q8\x16""2}\x1d{^?NQD\x1eLRsn?\x19[TSl\x1bls\x16?8t]TV{_";
int map[] = {3, 5, 1, 0, 2, 6, 4, 7};

int mixup(int val) {
    int new_val = 0;
    for(int i = 0; i < 8; i++) {
        new_val |= (val & 1) << map[i];
        val = val >> 1;
    }
    return new_val;
}

char* encrypt(char* input) {
    int n = strlen(input);
    char* output = malloc(n + 1);
    for(int i = 0; i < n; i++) {
        int val = input[i];
        int new_val = mixup(val);
        output[i] = new_val;
    }
    output[n] = 0;
    return output;
}


int main() {
    printf("Here is my superior encryption implemenation. I dare you to touch it.\n");
    printf("The thing you are looking for must be somewhere in the memory though.\n");
    printf("I forgot to mention, I am a n00b in crypto.\n");
    char input[100];
    printf("Enter a string you want to secure: ");
    scanf("%s", input);
    printf("Here is your secured input: %s\n", encrypt(input));
    return 0;
}
