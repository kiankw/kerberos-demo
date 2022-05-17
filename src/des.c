#include "../include/des.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG 0

void innerencrypt(unsigned char *ciphertext_64bits, unsigned char *plaintext_64bits, unsigned char *key_64bits);
void innerdecrypt(unsigned char *plaintext_64bits, unsigned char *ciphertext_64bits, unsigned char *key_64bits);

unsigned long long DESencrypt(unsigned char * ciphertext, unsigned char*plaintext, unsigned long long len_input, unsigned char *key_64bits) {
//    printf("begin pointer%p\n", (void *)ciphertext);
    unsigned char padSize = 8 - len_input % 8;
    if (padSize > 8) {
        return 0;
    }
    unsigned long long len_buf = len_input + padSize;
    unsigned char *buf = (unsigned char *)malloc(len_buf * sizeof(unsigned char));
    // printf("20\n");
    // ciphertext = (unsigned char *)realloc(ciphertext, len_buf * sizeof(unsigned char));
    // printf("22\n");
    memset(buf, 0, len_buf);
    memcpy(buf, plaintext, len_input);

    for (int i = 0; i < padSize; ++i) {
        memset(buf + len_input + i, padSize, 1);
    }

    unsigned char inputblock[65];
    inputblock[64] = '\0';
    unsigned char outputblock[65];
    memset(outputblock, '0', 64);
    outputblock[64] = '\0';


    for (unsigned int i = 0; i < len_buf / 8; i++) {
        // str to 01
        for (unsigned int j = 0; j < 8; ++j) {
            unsigned char temp = buf[i * 8 + j];
            for (int k = 7; k >= 0; --k) {
                inputblock[j * 8 + (unsigned int)k] = temp % 2 + '0';
                temp = temp / 2;
            }
        }

        // 加密
        innerencrypt(outputblock, inputblock, key_64bits);

        // 01 to str
        for (unsigned int j = 0; j < 8; ++j) {
            unsigned char temp = 0;
            for (int k = 0; k < 8; ++k) {
                temp = temp * 2 + (outputblock[j * 8 + (unsigned int)k] - '0');

            }
            ciphertext[i * 8 + j] = temp;
        }
    }
#if DEBUG
    printf("mid %p\n", (void *)ciphertext);
    for (unsigned int i = 0; i < len_buf; ++i) {
        printf("%02x", ciphertext[i]);
    }
    putchar(10);


    for (unsigned int i = 0; i < len_buf; ++i) {
        printf("%02x", ciphertext[i]);
    }
    putchar(10);

    for (unsigned int i = 0; i < len_buf; ++i) {
        printf("%02x", buf[i]);
    }
    putchar(10);
#endif
    free(buf);
    return len_buf;
}

unsigned long long DESdecrypt(unsigned char *plaintext, unsigned char *ciphertext, unsigned long long len_input, unsigned char *key_64bits) {
    if (len_input % 8) {
        return 0;
    }
    // unsigned char *buf = (unsigned char *)malloc(len_input * sizeof(unsigned char));
    unsigned char buf[len_input];
    memcpy(buf, ciphertext, len_input);
    unsigned char inputblock[65];
    inputblock[64] = '\0';
    unsigned char outputblock[65];
    memset(outputblock, '0', 64);
    outputblock[64] = '\0';
    // plaintext = (unsigned char *)realloc(plaintext, len_input * sizeof(unsigned char));
    for (unsigned int i = 0; i < len_input; i++) {
        // str to 01
        for (unsigned int j = 0; j < 8; ++j) {
            unsigned char temp = buf[i * 8 + j];
            for (int k = 7; k >= 0; --k) {
                inputblock[j * 8 + (unsigned int)k] = temp % 2 + '0';
                temp = temp / 2;
            }
        }
        // 加密
        innerdecrypt(outputblock, inputblock, key_64bits);

        // 01 to str
        for (unsigned int j = 0; j < 8; ++j) {
            unsigned char temp = 0;
            for (int k = 0; k < 8; ++k) {
                temp = temp * 2 + (outputblock[j * 8 + (unsigned int)k] - '0');

            }
            plaintext[i * 8 + j] = temp;
        }
    }

    unsigned int temp = plaintext[len_input - 1];
    // plaintext = (unsigned char *)realloc(plaintext, (len_input - temp) * sizeof(unsigned char));
    // free(buf);
    // return len_input;
    return len_input - temp;
}


int pc1_table[56] = {
    27, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};
int pc2_table[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};
int ip_table[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};
int ip_1_table[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};
int e_expand_table[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};
int sbox[8 * 4 * 16] = {
    14, 4 , 13, 1 , 2 , 15, 11, 8 , 3 , 10, 6 , 12, 5 , 9 , 0 , 7 ,
    0 , 15, 7 , 4 , 14, 2 , 13, 1 , 10, 6 , 12, 11, 9 , 5 , 3 , 8 ,
    4 , 1 , 14, 8 , 13, 6 , 2 , 11, 15, 12, 9 , 7 , 3 , 10, 5 , 0 ,
    15, 12, 8 , 2 , 4 , 9 , 1 , 7 , 5 , 11, 3 , 14, 10, 0 , 6 , 13,

    15, 1 , 8 , 14, 6 , 11, 3 , 4 , 9 , 7 , 2 , 13, 12, 0 , 5 , 10,
    3 , 13, 4 , 7 , 15, 2 , 8 , 14, 12, 0 , 1 , 10, 6 , 9 , 11, 5 ,
    0 , 14, 7 , 11, 10, 4 , 13, 1 , 5 , 8 , 12, 6 , 9 , 3 , 2 , 15,
    13, 8 , 10, 1 , 3 , 15, 4 , 2 , 11, 6 , 7 , 12, 0 , 5 , 14, 9 ,

    10, 0 , 9 , 14, 6 , 3 , 15, 5 , 1 , 13, 12, 7 , 11, 4 , 2 , 8 ,
    13, 7 , 0 , 9 , 3 , 4 , 6 , 10, 2 , 8 , 5 , 14, 12, 11, 15, 1 ,
    13, 6 , 4 , 9 , 8 , 15, 3 , 0 , 11, 1 , 2 , 12, 5 , 10, 14, 7 ,
    1 , 10, 13, 0 , 6 , 9 , 8 , 7 , 4 , 15, 14, 3 , 11, 5 , 2 , 12,

    7 , 13, 14, 3 , 0 , 6 , 9 , 10, 1 , 2 , 8 , 5 , 11, 12, 4 , 15,
    13, 8 , 11, 5 , 6 , 15, 0 , 3 , 4 , 7 , 2 , 12, 1 , 10, 14, 9 ,
    10, 6 , 9 , 0 , 12, 11, 7 , 13, 15, 1 , 3 , 14, 5 , 2 , 8 , 4 ,
    3 , 15, 0 , 6 , 10, 1 , 13, 8 , 9 , 4 , 5 , 11, 12, 7 , 2 , 14,

    2 , 12, 4 , 1 , 7 , 10, 11, 6 , 8 , 5 , 3 , 15, 13, 0 , 14, 9 ,
    14, 11, 2 , 12, 4 , 7 , 13, 1 , 5 , 0 , 15, 10, 3 , 9 , 8 , 6 ,
    4 , 2 , 1 , 11, 10, 13, 7 , 8 , 15, 9 , 12, 5 , 6 , 3 , 0 , 14,
    11, 8 , 12, 7 , 1 , 14, 2 , 13, 6 , 15, 0 , 9 , 10, 4 , 5 , 3 ,

    12, 1 , 10, 15, 9 , 2 , 6 , 8 , 0 , 13, 3 , 4 , 14, 7 , 5 , 11,
    10, 15, 4 , 2 , 7 , 12, 9 , 5 , 6 , 1 , 13, 14, 0 , 11, 3 , 8 ,
    9 , 14, 15, 5 , 2 , 8 , 12, 3 , 7 , 0 , 4 , 10, 1 , 13, 11, 6 ,
    4 , 3 , 2 , 12, 9 , 5 , 15, 10, 11, 14, 1 , 7 , 6 , 0 , 8 , 13,

    4 , 11, 2 , 14, 15, 0 , 8 , 13, 3 , 12, 9 , 7 , 5 , 10, 6 , 1 ,
    13, 0 , 11, 7 , 4 , 9 , 1 , 10, 14, 3 , 5 , 12, 2 , 15, 8 , 6 ,
    1 , 4 , 11, 13, 12, 3 , 7 , 14, 10, 15, 6 , 8 , 0 , 5 , 9 , 2 ,
    6 , 11, 13, 8 , 1 , 4 , 10, 7 , 9 , 5 , 0 , 15, 14, 2 , 3 , 12,

    13, 2 , 8 , 4 , 6 , 15, 11, 1 , 10, 9 , 3 , 14, 5 , 0 , 12, 7 ,
    1 , 15, 13, 8 , 10, 3 , 7 , 4 , 12, 5 , 6 , 11, 0 , 14, 9 , 2 ,
    7 , 11, 4 , 1 , 9 , 12, 14, 2 , 0 , 6 , 10, 13, 15, 3 , 5 , 8 ,
    2 , 1 , 14, 7 , 4 , 10, 8 , 13, 15, 12, 9 , 0 , 3 , 5 , 6 , 11
};

void permutation(unsigned char *ans, unsigned char *data, int *table);
void feistel(unsigned char *ans, unsigned char *r32, unsigned char *k48);
void sboxFunc(unsigned char *after, unsigned char *befor, int i);
void initSubkeys(unsigned char subkeys[17][49], unsigned char *key);
void shift(unsigned char *ans, unsigned char *data, int n);

void innerencrypt(unsigned char *ciphertext_64bits, unsigned char *plaintext_64bits, unsigned char *key_64bits) {
    unsigned char subkeys[17][49];
    for (int i = 0; i <= 16; ++i) {
        memset(subkeys[i], '0', 48);
        subkeys[i][48] = '\0';
    }
    initSubkeys(subkeys, key_64bits);

    unsigned char afterIPtable[65];
    memset(afterIPtable, '0', 64);
    afterIPtable[64] = '\0';
    permutation(afterIPtable, plaintext_64bits, ip_table);

    unsigned char L[17][33];
    for (int i = 0; i <= 16; ++i) {
        memset(L[i], '0', 32);
        L[i][32] = '\0';
    }
    for (int i = 0; i < 32; ++i) {
        L[0][i] = afterIPtable[i];
    }

    unsigned char R[17][33];
    for (int i = 0; i <= 16; ++i) {
        memset(R[i], '0', 32);
        R[i][32] = '\0';
    }
    for (int i = 0; i < 32; ++i) {
        R[0][i] = afterIPtable[i + 32];
    }

    for (int i = 1; i <= 16; ++i) {
        strcpy(L[i], R[i - 1]);
        unsigned char temp[33];
        memset(temp, '0', 32);
        temp[32] = '\0';

        feistel(temp, R[i - 1], subkeys[i]);

        for (int j = 0; j < 32; ++j) {
            if (temp[j] == L[i - 1][j]) {
                R[i][j] = '0';
            } else {
                R[i][j] = '1';
            }
        }
    }

    for (int i = 0; i < 32; ++i) {
        afterIPtable[i] = R[16][i];
        afterIPtable[i + 32] = L[16][i];
    }
    permutation(ciphertext_64bits, afterIPtable, ip_1_table);
    return ;
}


void innerdecrypt(unsigned char *plaintext_64bits, unsigned char *ciphertext_64bits, unsigned char *key_64bits) {
    unsigned char subkeys[17][49];
    for (int i = 0; i <= 16; ++i) {
        memset(subkeys[i], '0', 48);
        subkeys[i][48] = '\0';
    }
    initSubkeys(subkeys, key_64bits);

    unsigned char afterIPtable[65];
    memset(afterIPtable, '0', 64);
    afterIPtable[64] = '\0';
    permutation(afterIPtable, ciphertext_64bits, ip_table);

    unsigned char L[17][33];
    for (int i = 0; i <= 16; ++i) {
        memset(L[i], '0', 32);
        L[i][32] = '\0';
    }
    for (int i = 0; i < 32; ++i) {
        L[0][i] = afterIPtable[i];
    }

    unsigned char R[17][33];
    for (int i = 0; i <= 16; ++i) {
        memset(R[i], '0', 32);
        R[i][32] = '\0';
    }
    for (int i = 0; i < 32; ++i) {
        R[0][i] = afterIPtable[i + 32];
    }

    for (int i = 1; i <= 16; ++i) {
        strcpy(L[i], R[i - 1]);
        unsigned char temp[33];
        memset(temp, '0', 32);
        temp[32] = '\0';


        feistel(temp, R[i - 1], subkeys[17 - i]);
        for (int j = 0; j < 32; ++j) {
            if (temp[j] == L[i - 1][j]) {
                R[i][j] = '0';
            } else {
                R[i][j] = '1';
            }
        }                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
    }

    for (int i = 0; i < 32; ++i) {
        afterIPtable[i] = R[16][i];
        afterIPtable[i + 32] = L[16][i];
    }
    permutation(plaintext_64bits, afterIPtable, ip_1_table);
    return ;
}

void permutation(unsigned char *ans, unsigned char *data, int *table) {
    int len = strlen(ans);
    for (int i = 0; i < len; ++i) {
        ans[i] = data[table[i] - 1];
    }
    return ;
}

void feistel(unsigned char *ans, unsigned char *r32, unsigned char *k48) {
    unsigned char e48[49];
    memset(e48, '0', 48);
    e48[48] = '\0';

    permutation(e48, r32, e_expand_table);

    for (int i = 0; i < 48; ++i) {
        if (e48[i] == k48[i]) {
            e48[i] = '0';
        } else {
            e48[i] = '1';
        }
    }

    unsigned char beforSbox[8][7];
    for (int i = 0; i < 8; ++i) {
        memset(beforSbox[i], '0', 6);
        beforSbox[i][6] = '\0';
    }
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 6; ++j) {
            beforSbox[i][j] = e48[i * 6 + j];
        }
    }

    unsigned char afterSbox[8][5];
    for (int i = 0; i < 8; ++i) {
        memset(afterSbox[i], '0', 4);
        afterSbox[i][4] = '\0';
    }
    for (int i = 0; i < 8; ++i) {
        sboxFunc(afterSbox[i], beforSbox[i], i);
    }

    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 4; ++j) {
            ans[i * 8 + j] = afterSbox[i][j];
        }
    }
    return ;
}

void sboxFunc(unsigned char *after, unsigned char *befor, int i) {
    int n = (befor[0] - '0') * 2 + befor[5] - '0';
    int m = 0;
    for (int i = 1; i <= 4; ++i) {
        m = m * 2 + befor[i] - '0';
    }
    int temp = sbox[i * 64 + n * 16 + m];
    for (int i = 4; i >= 1; --i) {
        after[i] = temp % 2 + '0';
        temp /= 2;
    }
    return ;
}

void initSubkeys(unsigned char subkeys[17][49], unsigned char *key) {
    unsigned char key56[57];
    memset(key56, ' ', 56);
    key56[56] = '\0';
    permutation(key56, key, pc1_table);

    unsigned char c[17][29];
    for (int i = 0; i <= 16; ++i) {
        memset(c[i], '0', 28);
        c[i][28] = '\0';
    }
    for (int i = 0; i < 28; ++i) {
        c[0][i] = key56[i];
    }

    unsigned char d[17][29];
    for (int i = 0; i <= 16; ++i) {
        memset(d[i], ' ', 28);
        d[i][28] = '\0';
    }
    for (int i = 0; i < 28; ++i) {
        d[0][i] = key56[i + 28];
    }

    for (int i = 1; i <= 16; ++i) {
        if (i == 1 || i == 2 || i == 9 || i == 16) {
            shift(c[i], c[i - 1], 1);
            shift(d[i], d[i - 1], 1);
        } else {
            shift(c[i], c[i - 1], 2);
            shift(d[i], d[i - 1], 2);
        }
    }

    unsigned char oldkeys[17][57];
    for (int i = 0; i <= 16; ++i) {
        for (int j = 0; j < 28; ++j) {
            oldkeys[i][j] = c[i][j];
            oldkeys[i][j + 28] = d[i][j];
        }
        oldkeys[i][56] = '\0';
    }

    for (int i = 0; i <= 16; ++i) {
        permutation(subkeys[i], oldkeys[i], pc2_table);
    }
}

void shift(unsigned char *ans, unsigned char *data, int n) {
    int len = strlen(ans);
    for (int i = 0; i < len; ++i) {
        ans[i] = data[(i + n) % len];
    }
    return ;
}
