#include <windows.h>

#include "fastapi.h"
#include "io.hardlock.internal.h"
#include <stdio.h>

static KEY_DATA kd;

#define SEED_1 0xBE03
#define SEED_1_ALT 0xD730
#define SEED_2 0xA335

int main() {
    unsigned char id_ref[8] = { 0x95,0xB4,0xA9,0x73,0xF1,0xB1,0xE5,0xB9 };
    //unsigned char id_ref[8] = { 0xAB,0xB3,0x87,0xE5,0xB9,0xCB,93,0x50 };
    unsigned char id_vfy[8] = { 0x1D,0xC2,0xAF,0x49,0x66,0x18,0x6E,0xC9 };
    //unsigned char id_vfy[8] = { 0x30,0x89,0xF2,0x84,0x5C,0xDA,0xF7,0x9A };
    unsigned char crypt_buffer[0x50] = { 0x00 };






    WORD Seed_1 = 0;
    WORD Seed_2 = 0;
    WORD Seed_3 = 0;
    ZeroMemory(&kd, sizeof(kd));
    kd.DongleType = 2;



    for (Seed_1 = SEED_1; Seed_1 < 0xFFFF; Seed_1++) {
        kd.HdkSeed1 = Seed_1;
        for (Seed_2 = SEED_2; Seed_2 < 0xFFFF; Seed_2++) {
            kd.HdkSeed2 = Seed_2;

            for (Seed_3 = 0; Seed_3 < 0xFFFF; Seed_3++) {

                kd.HdkSeed3 = Seed_3;
                memcpy(crypt_buffer, id_ref, 8);
                HL_CRYPT(&kd, crypt_buffer);
                if (memcmp(crypt_buffer, id_vfy, 8) == 0) {
                    printf("Seed Combo Found: %04X %04X %04X\n", Seed_1, Seed_2, Seed_3);
                    return 0;
                }
            }

        }
    }

    printf("No Seed Found :(\n");
    return 0;
}