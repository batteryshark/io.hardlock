#include "fastapi.h"
#include "io.hardlock.protocol.h"

#include <stdio.h>
unsigned char packet_buffer[1024] = {0x00};
unsigned int packet_size = 0;

void usage(){
    printf("Usage: %s PACKET_BYTE_STR\n");

}

int main(int argc, char* argv[]){
    if(argc != 2){usage();return -1;}
    packet_size = strlen(argv[1]) / 2;
    HexToBin(argv[1],packet_buffer,1024);
    DecryptPacket((HL_API*)packet_buffer);
    DecryptParams((HL_API*)packet_buffer);
    printf("\n -- PACKET INFO -- \n");
    printf("Raw: ");
    print_hex(packet_buffer,packet_size);
    HL_API * hl = (HL_API*)packet_buffer;
    printf("API Version ID: %02X%02X \n", hl->API_Version_ID[0],hl->API_Version_ID[1]);
    printf("API Options: %04X %04X\n", hl->API_Options[0],hl->API_Options[1]);
    printf("Module ID: %d\n",hl->ModID);
    switch(hl->ModID){
        case EYE_DONGLE:
            printf("Dongle Type: HardLock E-Y-E\n");
            printf("\tModule Address [ModAd]: %04X\n",hl->Module.Eye.ModAd);
            printf("\tModule Memory Register Address: %04X\n",hl->Module.Eye.Reg);
            printf("\tModule Memory Value: %04X\n",hl->Module.Eye.Value);
            printf("\tModule Reserved: %04X\n",(unsigned int)hl->Module.Eye.Reserved);
            break;
        case DES_DONGLE:
            printf("Dongle Type: DES\n");
            printf("\tUse Key: %04X\n",hl->Module.Des.Use_Key);
            printf("\tKey: ");
            print_hex(hl->Module.Des.Key,8);
            break;
        case LT_DONGLE:
            printf("Dongle Type: LT\n");
            printf("\tLT Reserved: %04X\n",hl->Module.Lt.LT_Reserved);
            printf("\tMemory Register Address: %04X\n",hl->Module.Lt.Reg);
            printf("\tMemory Value: %04X\n",hl->Module.Lt.Value);
            printf("\tPassword 1: %04X Password 2: %04X\n",hl->Module.Lt.Password[0],hl->Module.Lt.Password[1]);
            break;
        case HASP_DONGLE:
            printf("Dongle Type: HASP\n");
            printf("\tHASP PW1: %04X\n", hl->Module.Hasp.PW1);
            printf("\tHASP PW2: %04X\n", hl->Module.Hasp.PW2);
            printf("\tHASP P1: %04X\n", hl->Module.Hasp.P1);
            break;
        default:
            printf("Dongle Type: Unknown\n");
            break;
    }

    printf("Cipher Data Ptr [LOW]: %04X\n",hl->Data);
    printf("Cipher Block Count: %d\n",hl->Bcnt);
    printf("Function Operation: %04X\n",hl->Function);
    printf("Function Status: %04X\n",hl->Status);
    printf("Remote Dongle?: %d\n",hl->Remote);
    printf("Dongle Port: %04X\n",hl->Port);
    printf("Dongle Port Speed: %d\n",hl->Speed);
    printf("Current Logins: %d\n",hl->NetUsers);
    printf("ID Reference: ");
    print_hex(hl->ID_Ref,8);
    printf("ID Verify: ");
    print_hex(hl->ID_Verify,8);
    printf("Multitasking Program ID: %d\n",hl->Task_ID);
    printf("Max Logins: %d\n",hl->MaxUsers);
    printf("Login Timeout (minutes): %d\n",hl->Timeout);
    printf("ShortLife: %d\n",hl->ShortLife);
    printf("Application Number: %d\n",hl->Application);
    printf("Protocol Flags: %04X\n",hl->Protocol);
    printf("OS Specific Data Ptr [LOW]: %04X\n",hl->OSspecific);
    printf("Port Mask (Local Search IN): %04X\n",hl->PortMask);
    printf("Port Flags (Local Search OUT): %04X\n",hl->PortFlags);
    printf("EnvMask (String Search Local IN): %04X\n",hl->EnvMask);
    printf("EnvFlags (String Search Local OUT): %04X\n",hl->EnvFlags);
    printf("EE Type Flags: %04X\n",hl->EEFlags);
    printf("Prot4Info: %04X\n",hl->Prot4Info);
    printf("Func Options: %04X\n",hl->FuncOptions);
    printf("License Slot Number [LOW]: %04X\n",hl->Slot_ID);
    printf("License Slot Number [HIGH]: %04X\n",hl->Slot_ID_HIGH);
    printf("RUS Expiration Date: %04X\n",hl->RUS_ExpDate);
    printf("Cipher Data Ptr [HIGH]: %04X\n",hl->DataHigh);
    printf("RUS Vendor Key [LOW]: %04X\n",hl->VendorKey);
    printf("RUS Vendor Key [HIGH]: %04X\n",hl->VendorKeyHigh);
    printf("OS Specific Data Ptr [HIGH]: %04X\n",hl->OSspecificHigh);
    printf("RUS Max User Counter: %04X\n",hl->RUS_MaxInfo);
    printf("RUS Current User Counter: %04X\n",hl->RUS_CurInfo);
    printf("RUS FIB Structure: \n");
    printf("\tRUS Marker: %02X%02X\n",hl->RUS_Fib.MARKER[0],hl->RUS_Fib.MARKER[1]);
    printf("\tRUS Serial ID: %04X\n",hl->RUS_Fib.SERIAL_ID);
    printf("\tRUS Version: %02X%02X\n",hl->RUS_Fib.VERSION[0],hl->RUS_Fib.VERSION[1]);
    printf("\tRUS Fixed: %04X\n",hl->RUS_Fib.FIXED);
    printf("\tRUS VAR: %04X\n",hl->RUS_Fib.VAR);
    printf("\tRUS CRC: %04X\n",hl->RUS_Fib.CRC);
    printf("Hardware2 Fields: \n");
    printf("\tHASP P2: %04X\n",hl->Module2.Hasp2.P2);
    printf("\tHASP P3: %04X\n",hl->Module2.Hasp2.P3);
    printf("Reserved Area 2: ");
    print_hex(hl->Reserved2,sizeof(hl->Reserved2));
    printf("Packet Crypt Version: %d\n",hl->CryptVersion);
    printf("Packet Crypt Seed: %04X\n",hl->CryptSeed);
    printf("Reserved Area 3: ");
    print_hex(hl->Reserved3,sizeof(hl->Reserved3));
    printf("Packet Tail: %02X%02X\n",hl->Tail[0],hl->Tail[1]);
    if(packet_size > 256){
        printf("Extra Data: ");
        print_hex(packet_buffer+256,packet_size - 256);
    }

    return 0;
}
