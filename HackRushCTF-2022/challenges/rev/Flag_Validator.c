#include "stdio.h"
#include "stdlib.h"
#include "string.h"


int validate_flag(char* flag) {
    if(strlen(flag) != 23) {
        return 0;
    }
    if(strncmp(flag, "HackRushCTF{", 12) != 0) {
        return 0;
    }
    if(flag[17] + flag[18] != flag[16] + 88) {
        return 0;
    }
    if(flag[17] - flag[18] + flag[16] != 114) {
        return 0;
    }
    if(flag[18] + flag[17] != 304 - flag[16]) {
        return 0;
    }
    if(flag[12] + flag[14] != flag[20] + 155) {
        return 0;
    }
    if(flag[12] - flag[14] + flag[20] != 75) {
        return 0;
    }
    if(flag[14] + flag[12] != 293 - flag[20]) {
        return 0;
    }
    if(flag[13] + flag[21] != 167) {
        return 0;
    }
    if(flag[21] - flag[13] != 69) {
        return 0;
    }
    if(flag[15] / 46 != 2) {
        return 0;
    }
    if(flag[15] % 46 != 20) {
        return 0;
    }
    if(flag[15] * flag[19] != 9184) {
        return 0;
    }

    if(flag[strlen(flag) - 1] != '}') {
        return 0;
    }
    return 1;
}


int main() {
    char your_flag[100];
    printf("Please enter your flag: ");
    scanf("%s", your_flag);

    int verdict = validate_flag(your_flag);
    if(verdict) {
        printf("Correct!\n");
    } else {
        printf("Wrong!\n");
    }
}
