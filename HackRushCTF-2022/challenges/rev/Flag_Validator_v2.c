#include "stdio.h"
#include "stdlib.h"
#include "string.h"

int validate_flag(char* flag) {
    if(strlen(flag) != 118) {
        return 0;
    }
    if(strncmp(flag, "HackRushCTF{", 12) != 0) {
        return 0;
    }
    if(!((flag[68] + flag[48] == flag[24] + 30) && (flag[68] - flag[48] + flag[24] == 72) && (flag[48] + flag[68] == 238 - flag[24]) && (flag[66] / 13 == 8) && (flag[66] % 13 == 8) && (flag[66] * flag[102] == 5712) && (flag[107] + flag[81] == flag[51] + 78) && (flag[107] - flag[81] + flag[51] == 24) && (flag[81] + flag[107] == 182 - flag[51]) && (flag[58] + flag[34] == flag[35] + 76) && (flag[58] - flag[34] + flag[35] == 114) && (flag[34] + flag[58] == 212 - flag[35]) && (flag[77] + flag[110] == 199) && (flag[110] - flag[77] == -21) && (flag[88] + flag[71] == flag[103] + 144) && (flag[88] - flag[71] + flag[103] == 46) && (flag[71] + flag[88] == 248 - flag[103]) && (flag[31] * flag[44] == 11115) && (flag[31] == 117) && (flag[26] + flag[70] == flag[28] + 100) && (flag[26] - flag[70] + flag[28] == 124) && (flag[70] + flag[26] == 290 - flag[28]) && (flag[27] / 37 == 1) && (flag[27] % 37 == 32) && (flag[27] * flag[67] == 3381) && (flag[62] + flag[112] == 205) && (flag[112] - flag[62] == -37) && (flag[33] + flag[99] == flag[40] + 42) && (flag[33] - flag[99] + flag[40] == 158) && (flag[99] + flag[33] == 264 - flag[40]) && (flag[45] + flag[93] == flag[69] + 120) && (flag[45] - flag[93] + flag[69] == 112) && (flag[93] + flag[45] == 314 - flag[69]) && (flag[82] + flag[80] == 173) && (flag[80] - flag[82] == -61) && (flag[91] * flag[12] == 2401) && (flag[91] == 49) && (flag[87] + flag[96] == flag[95] + 158) && (flag[87] - flag[96] + flag[95] == 74) && (flag[96] + flag[87] == 264 - flag[95]) && (flag[16] / 50 == 1) && (flag[16] % 50 == 28) && (flag[16] * flag[109] == 4446) && (flag[83] + flag[53] == flag[13] + 138) && (flag[83] - flag[53] + flag[13] == 94) && (flag[53] + flag[83] == 328 - flag[13]) && (flag[56] * flag[19] == 12312) && (flag[56] == 108) && (flag[41] + flag[74] == flag[39] + 17) && (flag[41] - flag[74] + flag[39] == 81) && (flag[74] + flag[41] == 183 - flag[39]) && (flag[20] / 34 == 1) && (flag[20] % 34 == 17) && (flag[20] * flag[90] == 4029) && (flag[47] + flag[49] == flag[55] + 36) && (flag[47] - flag[49] + flag[55] == 62) && (flag[49] + flag[47] == 252 - flag[55]) && (flag[100] + flag[113] == 108) && (flag[113] - flag[100] == 4) && (flag[46] + flag[84] == 199) && (flag[84] - flag[46] == -9) && (flag[73] + flag[101] == flag[54] + 53) && (flag[73] - flag[101] + flag[54] == 45) && (flag[101] + flag[73] == 157 - flag[54]) && (flag[116] / 26 == 2) && (flag[116] % 26 == 0) && (flag[116] * flag[98] == 2912) && (flag[106] + flag[32] == flag[22] + 95) && (flag[106] - flag[32] + flag[22] == 83) && (flag[32] + flag[106] == 273 - flag[22]) && (flag[64] * flag[29] == 13915) && (flag[64] == 115) && (flag[42] / 33 == 3) && (flag[42] % 33 == 19) && (flag[42] * flag[115] == 9912) && (flag[38] + flag[57] == flag[89] + 101) && (flag[38] - flag[57] + flag[89] == 89) && (flag[57] + flag[38] == 267 - flag[89]) && (flag[86] / 23 == 2) && (flag[86] % 23 == 19) && (flag[86] * flag[75] == 4225) && (flag[15] / 49 == 2) && (flag[15] % 49 == 7) && (flag[15] * flag[104] == 5880) && (flag[50] + flag[114] == flag[108] + 114) && (flag[50] - flag[114] + flag[108] == 104) && (flag[114] + flag[50] == 218 - flag[108]) && (flag[61] + flag[97] == flag[78] + 57) && (flag[61] - flag[97] + flag[78] == 133) && (flag[97] + flag[61] == 247 - flag[78]) && (flag[111] + flag[23] == flag[79] + 54) && (flag[111] - flag[23] + flag[79] == 58) && (flag[23] + flag[111] == 248 - flag[79]) && (flag[92] + flag[72] == 181) && (flag[72] - flag[92] == 9) && (flag[17] / 48 == 2) && (flag[17] % 48 == 3) && (flag[17] * flag[14] == 11385) && (flag[36] + flag[43] == flag[30] + 68) && (flag[36] - flag[43] + flag[30] == 88) && (flag[43] + flag[36] == 290 - flag[30]) && (flag[76] + flag[60] == flag[65] + 121) && (flag[76] - flag[60] + flag[65] == 107) && (flag[60] + flag[76] == 311 - flag[65]) && (flag[52] / 44 == 2) && (flag[52] % 44 == 22) && (flag[52] * flag[59] == 11550) && (flag[63] + flag[94] == flag[85] + 130) && (flag[63] - flag[94] + flag[85] == 72) && (flag[94] + flag[63] == 236 - flag[85]) && (flag[37] * flag[18] == 3795) && (flag[37] == 55) && (flag[25] + flag[21] == flag[105] + 40) && (flag[25] - flag[21] + flag[105] == 56) && (flag[21] + flag[25] == 154 - flag[105]))){
        return 0;
    }
    if(flag[strlen(flag) - 1] != '}') {
        return 0;
    }
    return 1;
}


int main() {
    char your_flag[200];
    printf("Please enter your flag: ");
    scanf("%s", your_flag);
    int verdict = validate_flag(your_flag);
    if(verdict) {
        printf("Correct!\n");
    } else {
        printf("Wrong!\n");
    }
}
