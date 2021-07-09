import struct
import binascii

from fixedint import MutableUInt8, MutableInt16, MutableUInt16, MutableInt32, MutableUInt32

import struct

# Return a Hex Array Dump
def hex_dump(data,line_limit = 16):
    lstr = ""
    for i in range(0,len(data), line_limit):
        cdata = data[i:i + line_limit]

        for cb in cdata:
            lstr += "0x%02X" % cb
            lstr += ", "
        lstr += "\n"
    return lstr[:-3]


def WORD(data,signed=True):
    if signed:
        return struct.unpack("<h",data[0:2])[0]
    else:
        return struct.unpack("<H", data[0:2])[0]

def DWORD(data,signed=True):
    if signed:
        return struct.unpack("<i",data[0:4])[0]
    else:
        return struct.unpack("<I", data[0:4])[0]


def rotation_value(value, rotations, widht=32):
    if int(rotations) != abs(int(rotations)):
        rotations = widht + int(rotations)
    return (int(value)<<(widht-(rotations%widht)) | (int(value)>>(rotations%widht))) & ((1<<widht)-1)

def ROL2(value, rotations):
    return rotation_value(value,-rotations,widht=16)

def ROR2(value, rotations):
    return rotation_value(value, rotations,widht=16)

def ROR16(value, rotations):
    return ROR2(value, rotations)

def ROL16(value, rotations):
    return ROL2(value, rotations)

    #data[1] = data[1] ^ 0x0A + 0x1F ^ data[0xBC]
    # data[6:8] = struct.pack("<H",MutableUInt16((((WORD(data[6:8]) + 0xE9) ^ 0x5131) + 0x11) ^ 0x8450 ^ ROL2(seed, 6)))
from fixedint import MutableUInt8, MutableInt16, MutableUInt16, MutableInt32, MutableUInt32

def test_val(data):
    seed = WORD(data[0xBC:0xBE], signed=False)
    print(seed)

    #*(WORD*)(data + 6) = (((ROL16(seed, 4) ^ *(WORD*)(data + 6) ^ 0x8436) - 14) ^ 0x5131) - 166;
    # 0xB4DA
    o_val = MutableUInt16(struct.unpack("<H",data[74:76])[0])
    print(WORD(data[74:76],signed=False))
    data[74:76] = struct.pack("<H",MutableUInt16((((WORD(data[74:76]) ^ seed) ^ 0x8405) + 0x7F35) ^ 0x5131))
    print(MutableUInt16(struct.unpack("<H",data[74:76])[0]))
    data[74:76] = struct.pack("<H",MutableUInt16(((((WORD(data[74:76]) ^ 0x5131) - 0x7F35) ^ 0x8405) ^ seed)))
    #data[6:8] = struct.pack("<H",MutableUInt16((((WORD(data[6:8]) + 0xE9) ^ 0x5131) + 0x11) ^ 0x8450 ^ ROL2(seed, 6)))
    #data[85] = MutableUInt8(((data[85] - 0x25) ^ 0x38) + (ROL16(seed,7) ^ 0xCD))
    print(MutableUInt16(struct.unpack("<H",data[74:76])[0]))
    print(o_val)
    if MutableUInt16(struct.unpack("<H",data[74:76])[0]) == o_val:
        print("PASS!")
    else:
        print("FAIL!")

"""
orig = 0xbfb7
seed = 0xb4da
res  = 0x5fac
(((0xbfb7 ^ 0xb4da) ^ 0x8405) + 0x7F35) ^ 0x5131 = 0x5fac
((((WORD(data[74:76]) ^ 0x5131) - 0x7F35) ^ 0x8405) ^ seed)
"""

def encode_step_1(data):
    seed = struct.unpack('<H', data[0xBC:0xBE])[0]
    ver  = struct.unpack('<H', data[0xBA:0xBC])[0]

    if not ver:
        return

    for i in range(0, 0xb9):
        w = struct.unpack('<H', data[i:i+2])[0]
        w = (w + seed) & 0xffff
        data[i:i+2] = struct.pack('<H', w)
        seed = ROR16(seed, 15) & 0xffff
        seed = (seed - (w ^ i)) & 0xffff

    for i in range(0xbe, 0xff):
        w = struct.unpack('<H', data[i:i+2])[0]
        w = (w - seed) & 0xffff
        data[i:i+2] = struct.pack('<H', w)
        seed = ROR16(seed, 15) & 0xffff
        seed = (seed + (w ^ i)) & 0xffff

    data[0xbc:0xbe] = struct.pack('<H', seed)
    return data

def decode_step_1(data):
    seed = WORD(data[0xBC:0xBE], signed=False)
    print("Seed: %04X" % seed)
    packet_version = data[0xBA]
    if packet_version:
        for i in range(0xFE, 0xBD, -1):
            sd = struct.unpack("<H",data[i:i+2])[0]
            seed = ROR2(MutableUInt16(seed - (sd ^ i)), 1)
            data[i:i+2] = struct.pack("<H",MutableUInt16(sd + seed))

        for i in range(0xB8, -1, -1):
            sd = struct.unpack("<H",data[i:i+2])[0]
            seed = ROR2(MutableUInt16(seed + (sd ^ i)), 1)
            data[i:i+2] = struct.pack("<H",MutableUInt16(sd - seed))
        # This is the Parameter Seed - if this is fucked, the rest will be fucked.
        data[0xBC:0xBE] = struct.pack("<H", MutableUInt16(seed))
    return data


def decode_step_2(data):
    seed = WORD(data[0xBC:0xBE], signed=False)
    packet_version = data[0xBA]
    if packet_version == 1:
        data[0] = MutableUInt8(((ROL2(seed, 3) ^ data[0]) + 0x7C) ^ 0x14)
        data[1] = MutableUInt8(((data[1] ^ data[0xBC]) - 0x20) ^ 0x1C)
        data[2:4] = struct.pack("<H",MutableUInt16((((WORD(data[2:4]) ^ 0xAA) - ROR2(seed, 7)) ^ 0x5131) - 25))
        data[4:6] = struct.pack("<H",MutableUInt16((ROR2(seed, 1) ^ WORD(data[4:6]) ^ 0x8407) - 15))
        data[6:8] = struct.pack("<H",MutableUInt16((((ROL2(seed, 6) ^ WORD(data[6:8]) ^ 0x8450) - 17) ^ 0x5131) - 233))
        data[8:10] = struct.pack("<H",MutableUInt16((((ROR2(seed, 4) - 11) ^ WORD(data[8:10])) - 17) ^ 0x84EF))
        data[10:12] = struct.pack("<H",MutableUInt16(((WORD(data[10:12]) - seed + 11) ^ 0x5131) - 231))
        data[12:14] = struct.pack("<H",MutableUInt16(((seed - 12) ^ WORD(data[12:14])) - 156))
        data[14:16] = struct.pack("<H",MutableUInt16(((ROL2(seed, 5) - 12) ^ WORD(data[14:16])) - 136))
        data[16:18] = struct.pack("<H",MutableUInt16(((ROL2(seed, 7) - 11) ^ WORD(data[16:18])) + 0x5EDD))
        data[18:22] = struct.pack("<I",MutableUInt16(((seed + 1) ^ WORD(data[18:20])) - 57))
        data[22:24] = struct.pack("<H",MutableUInt16((ROR2(seed, 3) ^ WORD(data[22:24]) ^ 0xF5) - 184))
        data[24:26] = struct.pack("<H",MutableUInt16((((WORD(data[24:26]) - ROL2(seed, 2)) ^ 0x8414) - 0xE9) ^ 0x5131))
        # THESE MAY BE WRONG DUE TO + 250 being - or swapped or otherwise - this is why monitors fuck up btw
        data[26:28] = struct.pack("<H",MutableUInt16((ROR2(seed, 5) + (((WORD(data[26:28]) ^ 0x5131) + 233) ^ 0x8414))))
        data[28:32] = struct.pack("<I",MutableUInt16(ROL2(seed, 3) ^ (WORD(data[28:30]) + 250) ^ 0x8450))
        data[32:34] = struct.pack("<H",MutableUInt16(((WORD(data[32:34]) - ((ROL2(seed, 5)) ^ 0x85)) ^ 0x5120) - 173))
        data[34:36] = struct.pack("<H",MutableUInt16((WORD(data[34:36]) ^ ((seed << 6) | (seed >> 10)) ^ 0x380) - 0xCC6))
        for i in range(36,44):
            data[i] = ((data[i] ^ data[0xBC] - 2) + 0x80) & 0xFF
        for i in range(44, 52):
            data[i] = ((data[i] ^ data[0xBC] - 0x34) + 0x58) & 0xFF
        data[52:56] = struct.pack("<I",MutableUInt16(seed ^ (DWORD(data[52:56],signed=False)  ^ 0x15) - 0x15E))
        data[56:58] = struct.pack("<H",MutableUInt16((ROR2(seed, 3) ^ WORD(data[56:58]) ^ 0x5752) - 0x33D6))
        data[58:62] = struct.pack("<I",MutableUInt32((DWORD(data[58:62], signed=False) ^ ((seed >> 2) | (seed << 14)) ^ 0xFDDE5) - 84))
        data[62:64] = struct.pack("<H",MutableUInt16((WORD(data[62:64]) ^ (seed >> 3 | (seed << 13)) ^ 0x15) - 250))
        data[64:66] = struct.pack("<H",MutableUInt16((((WORD(data[64:66]) ^ seed) - 101) ^ 0x5131) - 32766))
        data[66:68] = struct.pack("<H",MutableUInt16(((WORD(data[66:68]) ^ seed) ^ 0x8492) + 20184))
        data[68:70] = struct.pack("<H",MutableUInt16((WORD(data[68:70]) ^ seed) + 0x40A4))
        data[70:74] = struct.pack("<I",MutableUInt32((DWORD(data[70:74], signed=False) ^ seed) - 157))
        data[74:76] = struct.pack("<H",MutableUInt16((((WORD(data[74:76]) ^ seed) ^ 0x8405) - 28874) ^ 0x5131))

        data[78:80] = struct.pack("<H",MutableUInt16(((WORD(data[76:78]) ^ seed) - 203) ^ 0xF204))
        data[80:82] = struct.pack("<H",MutableUInt16((((WORD(data[80:82]) ^ seed) - 207) ^ 0x5131) - 28679))
        data[82] = MutableUInt8(((data[82] ^ ((32 * data[0xBC]) | (seed >> 11)) ^ 0x85) - 50))
        data[85] = MutableUInt8(((data[85] - (((data[0xBC] << 7) | (seed >> 9)) ^ 0xA3)) ^ 0x3F) - 119)
        data[86:88] = struct.pack("<H",MutableUInt16(((WORD(data[86:88]) ^ seed) ^ 0x15) - 248))
        data[88:90] =  struct.pack("<H",MutableUInt16(((WORD(data[88:90]) ^ seed) ^ 0x2215) - 22248))
        data[96:100] = struct.pack("<I",MutableUInt32((DWORD(data[96:100]) ^ seed) - 0x13D))
        data[108:112] = struct.pack("<I",MutableUInt32((DWORD(data[108:112]) ^ (((32 * seed) | seed >> 11)) - 11) - 51333))
        data[112:116] = struct.pack("<I",MutableUInt32((DWORD(data[112:116]) ^ (((seed >> 6) | (seed << 10)) - 11)) - 51323))
        data[254] = MutableUInt8(((data[254] - ((seed >> 5) ^ 0x55)) ^ 0x20) + 23)
        data[255] = MutableUInt8((data[255] ^ ((2 * data[0xBC]) | (seed < 0)) ^ 0x85) + 6)
        # STUFF FOR PACKET 1 !!!

    elif packet_version == 2:
        data[0] = MutableUInt8(((ROL2(seed, 2) ^ data[0]) + 0x7C) ^ 0x17)
        data[1] = MutableUInt8(((seed ^ data[1]) - 31) ^ 0xA)
        #data[1] = (data[1] ^ 0x0A) + 0x1F ^ data[0xBC]
        data[2:4] = struct.pack("<H",MutableUInt16(((WORD(data[2:4]) ^ 0xBB) - ROR2(seed, 7)) ^ 0x5128))
        data[4:6] = struct.pack("<H",MutableUInt16(ROR2(seed, 1) ^ WORD(data[4:6]) ^ 0x8400) - 115)
        data[6:8] = struct.pack("<H",MutableUInt16((((ROL2(seed, 4) ^ WORD(data[6:8]) ^ 0x8436) - 14) ^ 0x5131) - 166))
        data[8:10] = struct.pack("<H",MutableUInt16((((ROR2(seed, 3) - 18) ^ WORD(data[8:10])) - 17) ^ 0x843C))
        data[10:12] = struct.pack("<H",MutableUInt16(((WORD(data[10:12]) + 32 - seed) ^ 0x5131) - 289))
        data[12:14] = struct.pack("<H",MutableUInt16(((seed - 21) ^ WORD(data[12:14])) - 83))
        data[14:16] = struct.pack("<H",MutableUInt16(((ROL2(seed, 4) - 22) ^ WORD(data[14:16])) - 328))
        data[16:18] = struct.pack("<H",MutableUInt16(((ROL2(seed, 4) - 22) ^ WORD(data[16:18])) - 328))
        data[18:22] = struct.pack("<I",MutableUInt16(((seed + 1) ^ WORD(data[18:20])) - 66))
        data[22:24] = struct.pack("<H",MutableUInt16(((ROR2(seed, 5) ^ WORD(data[22:24]) ^ 0x1A) - 266)))
        data[24:26] = struct.pack("<H",MutableUInt16((((WORD(data[24:26]) - ROL2(seed, 4)) ^ 0x84A2) - 0xC7) ^ 0x5131))
        data[26:28] = struct.pack("<H",MutableUInt16((((WORD(data[26:28]) - ROR2(seed, 3)) ^ 0x8470) - 133) ^ 0x5131))
        data[28:32] = struct.pack("<I",MutableUInt16((ROL2(seed, 3) ^ WORD(data[28:30]) ^ 0x8450) - 138))
        data[32:34] = struct.pack("<H",MutableUInt16(((WORD(data[32:34]) - ((ROL2(seed, 2)) ^ 0x7A)) ^ 0x5176) - 71))
        data[34:36] = struct.pack("<H",MutableUInt16((WORD(data[34:36]) ^ (ROL2(seed,2)) ^ 0xE250) - 0x4EC))
        # Decode the RefKey
        for i in range(36,44):
            data[i] = ((data[i] ^ data[0xBC] - 20) - 0x1F) & 0xFF
        # Decode the VerKey
        for i in range(44, 52):
            data[i] = ((data[i] ^ data[0xBC] - 0x34) + 0x58) & 0xFF
        data[52:56] = struct.pack("<I",MutableUInt32((DWORD(data[52:56],signed=False) ^ seed ^ 0x18) - 0x1C2))
        data[56:58] = struct.pack("<H",MutableUInt16((ROR2(seed, 1) ^ WORD(data[56:58]) ^ 0x6677) - 0x33D7))
        data[58:62] = struct.pack("<I",MutableUInt32((DWORD(data[58:62], signed=False) ^ ((seed >> 3) | (seed << 13)) ^ 0xFDDCC) - 194))
        data[62:64] = struct.pack("<H",MutableUInt16((WORD(data[62:64]) ^ (seed >> 2 | (seed << 14)) ^ 0x19) - 223))
        data[64:66] = struct.pack("<H",MutableUInt16((((WORD(data[64:66]) ^ seed) - 102) ^ 0x5131) - 12766))
        data[66:68] = struct.pack("<H",MutableUInt16(((WORD(data[66:68]) ^ seed) ^ 0x8486) - 15342))
        data[68:70] = struct.pack("<H",MutableUInt16((WORD(data[68:70]) ^ seed) + 0xCBD))
        data[70:74] = struct.pack("<I",MutableUInt32((DWORD(data[70:74], signed=False) ^ seed) - 227))
        data[74:76] = struct.pack("<H",MutableUInt16((((WORD(data[74:76]) ^ seed) ^ 0x8405) + 32565) ^ 0x5131))

        data[78:80] = struct.pack("<H",MutableUInt16(((WORD(data[78:80]) ^ seed) - 23) ^ 0xF107))
        data[80:82] = struct.pack("<H",MutableUInt16((((WORD(data[80:82]) ^ seed) - 217) ^ 0x5131) - 30465))
        data[82] = MutableUInt8((data[82] ^ ((4 * data[0xBC]) | (seed >> 14)) ^ 0x51) - 77)
        data[85] = MutableUInt8(((data[85] - (((data[0xBC] << 7) | (seed >> 9)) ^ 0xCD)) ^ 0x38) + 37)
        data[86:88] = struct.pack("<H",MutableUInt16(((WORD(data[86:88]) ^ seed) ^ 0x25) - 253))
        data[88:90] =  struct.pack("<H",MutableUInt16(((WORD(data[88:90]) ^ seed) ^ 0x231F) - 28500))
        data[96:100] = struct.pack("<I",MutableUInt32((DWORD(data[96:100]) ^ seed) - 0x13E))
        data[108:112] = struct.pack("<I",MutableUInt32((DWORD(data[108:112]) ^ (((4 * seed) | seed >> 14)) - 111) - 41333))
        data[112:116] = struct.pack("<I",MutableUInt32((DWORD(data[112:116]) ^ (((seed >> 1) | (seed << 15)) - 11)) - 51415))
        data[254] = MutableUInt8(((data[254] - ((seed >> 1) ^ 0x5A)) ^ 0x7F) - 99)
        data[255] = MutableUInt8((data[255] ^ ((16 * data[0xBC]) | (seed >> 12)) ^ 0xF1) - 82)
    return data

# struct.pack("<H",MutableUInt16())

FUNC_DB = {
    0x00: "HardLock_Login",
    0x01: "HardLock_Logout",
    0x06: "HardLock_IsHardlock",
    0x0E: "HardLock_Crypt",
    0x11: "HardLock_Code",
    0x17: "HardLock_ReadBlock"
}

MOD_ID_DB = {
    0:"EYE",
    1:"DES",
    4:"HASP",
    3:"LT",
}

def packet_info(data):
    api_version = WORD(data[0:2])
    print(f"API Version ID: %04X" % api_version)
    option_flags = DWORD(data[2:6])
    print(f"API Option Flags: %04X" % option_flags)
    module_id = WORD(data[6:8])
    module_id_name = MOD_ID_DB.get(module_id,"Unknown")
    print("Module ID: %s [%04X]" % (module_id_name,module_id))

    if module_id_name == "EYE":
        eye_mod_ad = WORD(data[8:10])
        print(f"EYE - Module Address [MODAD]: %04X" % eye_mod_ad)
        eye_mem_reg = WORD(data[10:12])
        print(f"EYE - Memory Register Address : %04X" % eye_mem_reg)
        eye_mem_val = WORD(data[12:14])
        print(f"EYE - Memory Register Value : %04X" % eye_mem_val)
        eye_reserved = binascii.hexlify(data[14:18]).decode('ascii').upper()
        print("EYE - Reserved: %s" % eye_reserved)
    elif module_id_name == "DES":
        des_use_key = WORD(data[8:10],signed=False)
        print("DES - Use Key: %04X" % des_use_key)
        des_key = binascii.hexlify(data[10:18]).decode('ascii').upper()
        print("DES - Key: %s" % des_key)
    elif module_id_name == "HASP":
        hasp_pw_1 = DWORD(data[8:12],signed=False)
        print("HASP - PW1: %04X" % hasp_pw_1)
        hasp_pw_2 = DWORD(data[12:16],signed=False)
        print("HASP - PW2: %04X" % hasp_pw_2)
        hasp_p1 =  WORD(data[16:18],signed=False)
        print("HASP - P1: %04X" % hasp_p1)
    elif module_id_name == "LT":
        lt_reserved = WORD(data[8:10],signed=False)
        print("LT - Reserved: %04X" % lt_reserved)
        lt_reg = WORD(data[10:12],signed=False)
        print("LT - Memory Register Address: %04X" % lt_reg)
        lt_value = WORD(data[12:14],signed=False)
        print("LT - Memory Register Value: %04X" % lt_value)
        lt_password_1 = WORD(data[14:16],signed=False)
        print("LT - Access Password 1: %04X" % lt_password_1)
        lt_password_2 = WORD(data[16:18],signed=False)
        print("LT - Access Password 2: %04X" % lt_password_2)

    cipher_data_ptr = DWORD(data[18:22],signed=False)
    print("Cipher Data PTR: %04X" % cipher_data_ptr)
    num_blocks = WORD(data[22:24])
    print("Number of Blocks: %04X" % num_blocks)
    func_id = WORD(data[24:26],signed=False)
    print("Function: %s [%04X]" % (FUNC_DB.get(func_id,"UNKNOWN"),func_id))
    status_code = WORD(data[26:28])
    print("Status Code: %04X" % status_code)
    remote_dongle = WORD(data[28:30])
    print("Is Remote Dongle: %04X" % remote_dongle)
    dongle_port = WORD(data[30:32])
    print("Dongle Port: %04X" % dongle_port)
    port_speed = WORD(data[32:34])
    print("Dongle Port Speed: %04X" % port_speed)
    current_logins = WORD(data[34:36])
    print("Current Logins: %04X" % current_logins)
    ref_key = binascii.hexlify(data[36:44]).decode('ascii').upper()
    print("Ref Key: %s" % ref_key)
    ver_key = binascii.hexlify(data[44:52]).decode('ascii').upper()
    print("Verify Key (Encrypted Ref Key): %s" % ver_key)
    task_id = DWORD(data[52:56])
    print("Task ID: %04X" % task_id)
    max_logins = WORD(data[56:58])
    print("Max Logins: %04X" % max_logins)
    timeout_minutes = DWORD(data[58:62])
    print("Timeout (in Minutes): %04X" % timeout_minutes)
    short_life = WORD(data[62:64])
    print("Short Life: %04X" % short_life)
    app_number = WORD(data[64:66])
    print("Application Number: %04X" % app_number)
    proto_flags = WORD(data[66:68])
    print("Protocol Flags: %04X" % proto_flags)
    pm_host = WORD(data[68:70])
    print("DOS Extender Type: %04X" % pm_host)
    ptr_os_specific_low =  DWORD(data[70:74], signed=False)
    print("Ptr OS Specific Data [Low]: %04X" % ptr_os_specific_low)
    port_mask = WORD(data[74:76])
    print("Port Mask: %04X" % port_mask)
    port_flags = WORD(data[76:78])
    print("Port Flags: %04X" % port_flags)
    env_mask = WORD(data[78:80])
    print("Env Mask: %04X" % env_mask)
    env_flags = WORD(data[80:82],signed=False)
    print("Env Flags: %04X" % env_flags)
    ee_flags = data[82]
    print("EE Flags: %02X" % ee_flags)
    prot_4_info = WORD(data[83:85])
    print("Prot 4 Info %04X" % prot_4_info)
    func_options = data[85]
    print("Function Additional Options: %04X" % func_options)
    slot_id_low = WORD(data[86:88])
    print("Slot ID [Low]: %04X" % slot_id_low)
    slot_id_high = WORD(data[88:90])
    print("Slot ID [High]: %04X" % slot_id_high)
    rus_exp_date = WORD(data[90:92])
    print("RUS Expiration Date: %04X" % rus_exp_date)
    data_high_ptr = DWORD(data[92:96])
    print("Data Ptr [High]: %04X" % data_high_ptr)
    vendor_key_low = DWORD(data[96:100],signed=False)
    print("Ptr to RUS Vendor Key [Low]: %04X" % vendor_key_low)
    vendor_key_high = DWORD(data[100:104],signed=False)
    print("Ptr to RUS Vendor Key [High]: %04X" % vendor_key_high)
    ptr_os_specific_high =  DWORD(data[104:108], signed=False)
    print("Ptr OS Specific Data [High]: %04X" % ptr_os_specific_high)
    rus_max_info = DWORD(data[108:112],signed=False)
    print("RUS Max User / Counter: %04X" % rus_max_info)
    rus_cur_info = DWORD(data[112:116],signed=False)
    print("RUS Current User / Counter: %04X" % rus_cur_info)
    rus_fib_marker = WORD(data[116:118],signed=False)
    print("RUS FIB - Marker: %04X" % rus_fib_marker)
    rus_fib_serial_id = DWORD(data[118:122],signed=False)
    print("RUS FIB - Serial ID: %04X" % rus_fib_serial_id)
    rus_fib_version = WORD(data[122:124],signed=False)
    print("RUS FIB - Version: %04X" % rus_fib_version)
    rus_fib_fixed = WORD(data[124:126],signed=False)
    print("RUS FIB - Fixed: %04X" % rus_fib_fixed)
    rus_fib_var = WORD(data[126:128],signed=False)
    print("RUS FIB - Var: %04X" % rus_fib_var)
    rus_fib_crc = WORD(data[128:130],signed=False)
    print("RUS FIB - CRC: %04X" % rus_fib_crc)
    hasp_mode2_p2 = WORD(data[130:132],signed=False)
    print("HASP MODE2 - P2: %04X" % hasp_mode2_p2)
    hasp_mode2_p3 = WORD(data[132:134],signed=False)
    print("HASP MODE2 - P3: %04X" % hasp_mode2_p3)
    reserved = binascii.hexlify(data[134:254]).decode('ascii').upper()
    print("Reserved Area [DUMP]: %s" % reserved)
    packet_version = WORD(data[0xBA:0xBC])
    print("Reserved - Packet Version: %04X" % packet_version)
    packet_seed = WORD(data[0xBC:0xBE], signed=False)
    print("Reserved - Packet Seed: %04X" % packet_seed)
    if len(data) > 256:
        extra_data = binascii.hexlify(data[0x100:]).decode('ascii').upper()
        print("Extra Data: %s" % extra_data)

if __name__ =="__main__":
    data = bytearray([
        0x17, 0x19, 0x3F, 0xDA, 0xFC, 0x7D, 0xE2, 0xA1, 0x15, 0x91, 0xAD, 0x87, 0x29, 0xBD, 0x15, 0x4D,
        0xCB, 0x72, 0xFF, 0x8A, 0xE9, 0xAE, 0x44, 0x87, 0xAB, 0xC2, 0xA3, 0x07, 0x04, 0x23, 0x26, 0xA6,
        0x71, 0xFA, 0x9B, 0x17, 0x07, 0x22, 0x33, 0xCE, 0x51, 0xE0, 0xB7, 0x07, 0x26, 0x80, 0x53, 0x8C,
        0x68, 0x2C, 0x86, 0x55, 0x0D, 0xAD, 0x66, 0xC7, 0xB5, 0x0A, 0xCF, 0x2F, 0x3A, 0x77, 0x13, 0x1A,
        0xE5, 0x5B, 0x90, 0x86, 0x0F, 0x2C, 0x08, 0x30, 0xD4, 0x61, 0xD3, 0x93, 0x1E, 0xF3, 0x32, 0x48,
        0x6B, 0x24, 0x0E, 0x63, 0xC2, 0xFE, 0x97, 0xD7, 0x82, 0x7A, 0x0B, 0x60, 0x1D, 0x93, 0xF1, 0xCD,
        0xCB, 0xAC, 0x81, 0x7C, 0x37, 0x7B, 0x37, 0x7E, 0x43, 0xBD, 0x07, 0x04, 0x7D, 0x8E, 0xC5, 0x87,
        0x30, 0xD8, 0x8E, 0xD8, 0xBA, 0x90, 0x27, 0xE9, 0x1F, 0xC5, 0xB9, 0x9C, 0x3E, 0x27, 0xE1, 0x0F,
        0x9D, 0x09, 0x79, 0xE3, 0x53, 0xBF, 0x31, 0x9B, 0x07, 0x6F, 0xE5, 0x49, 0xC1, 0x23, 0x89, 0xF9,
        0x6C, 0xCD, 0x2C, 0x8B, 0xEC, 0x50, 0xCC, 0x2C, 0x8E, 0xF4, 0x6B, 0xD6, 0x4D, 0xBA, 0x3B, 0xC2,
        0x15, 0x66, 0xF3, 0x84, 0xD3, 0x1F, 0x75, 0x05, 0x58, 0xAF, 0x48, 0xA1, 0x28, 0xBF, 0x5C, 0xB9,
        0x4C, 0x8F, 0xD0, 0x30, 0xD0, 0x2C, 0xB2, 0x50, 0xAC, 0x0E, 0x02, 0x00, 0xC7, 0x70, 0xDA, 0x40,
        0x93, 0xDF, 0xAF, 0x02, 0x54, 0x27, 0x7E, 0x56, 0x30, 0x7E, 0x5B, 0x3E, 0xA1, 0xEF, 0xD9, 0xBA,
        0x1E, 0x8D, 0xDB, 0xCD, 0x9E, 0x14, 0x89, 0xD3, 0xC5, 0x92, 0xFE, 0xFC, 0xF7, 0xE9, 0xC4, 0x94,
        0x03, 0x49, 0x0E, 0x57, 0x21, 0xA7, 0x36, 0xCA, 0x93, 0xDB, 0xB3, 0x3E, 0xD8, 0xAB, 0x43, 0x0C,
        0x67, 0x69, 0x6F, 0x77, 0xA1, 0x25, 0xB4, 0x5E, 0x4F, 0x22, 0xA5, 0x27, 0xB2, 0x54, 0x33, 0x05
    ])

    data_crypt = bytearray([
        0xA4, 0x3D, 0x17, 0xA6, 0x20, 0x9C, 0xCF, 0x9C, 0x7A, 0x2F, 0x73, 0x9F, 0x29, 0xDB, 0xAB, 0xD3,
        0x19, 0x81, 0xF3, 0x2A, 0x6B, 0xC5, 0xA7, 0x8C, 0x32, 0x01, 0x10, 0x87, 0x6E, 0x92, 0xF3, 0x0B,
        0xCF, 0x72, 0xFB, 0x5F, 0x09, 0xEE, 0x16, 0x5F, 0x24, 0x3F, 0x91, 0xE0, 0xF5, 0x22, 0xA6, 0xD9,
        0x36, 0x7C, 0x52, 0xB3, 0x42, 0xB8, 0xC7, 0x52, 0xCE, 0xB5, 0x74, 0x02, 0x1C, 0x2F, 0x7D, 0xE0,
        0x72, 0x07, 0x08, 0x5E, 0x9E, 0xA6, 0x2F, 0xBE, 0x32, 0x32, 0xF3, 0x93, 0x0C, 0x57, 0x30, 0xCF,
        0x77, 0x22, 0xEB, 0x6D, 0xC0, 0xD1, 0xDF, 0x95, 0x3A, 0x08, 0xEB, 0xF6, 0x12, 0xAA, 0x2E, 0xBF,
        0x72, 0xC4, 0x4D, 0x65, 0xBE, 0x9C, 0x39, 0x0D, 0xAA, 0x8B, 0x2F, 0x14, 0x98, 0x90, 0x72, 0xEF,
        0xC8, 0x0D, 0x1C, 0x46, 0x04, 0x8F, 0x1A, 0xC0, 0xC0, 0xC1, 0xC3, 0xC6, 0xC8, 0xD5, 0xFB, 0x6A,
        0xB9, 0x31, 0xAB, 0x23, 0x9F, 0x19, 0x8F, 0x0B, 0x83, 0xF1, 0x62, 0xD5, 0x42, 0xAF, 0x32, 0xA1,
        0x0A, 0x73, 0xFA, 0x83, 0xF0, 0x74, 0x00, 0x61, 0xC2, 0x21, 0x84, 0xE1, 0x41, 0x9F, 0x33, 0xB3,
        0x31, 0xCB, 0x23, 0xBF, 0x59, 0xAF, 0x4B, 0xA3, 0x39, 0xDB, 0x3B, 0xDF, 0x41, 0x8F, 0xF3, 0x82,
        0xD1, 0x39, 0xE3, 0x6B, 0xF7, 0xA1, 0x27, 0xB5, 0x5D, 0x0A, 0x02, 0x00, 0x9C, 0xA7, 0x3D, 0xED,
        0x92, 0xDC, 0xA4, 0xED, 0xB6, 0x06, 0x55, 0x21, 0x69, 0x3E, 0x95, 0xDB, 0xB9, 0x12, 0x5A, 0x33,
        0x80, 0xC6, 0x8E, 0xDB, 0xC8, 0x90, 0xF7, 0xE8, 0xAE, 0x03, 0x49, 0x1A, 0x91, 0xF3, 0xD9, 0xCE,
        0xAE, 0x31, 0xB5, 0x34, 0xB6, 0x3D, 0xC9, 0x88, 0xCA, 0x9A, 0xEB, 0xFE, 0x12, 0x52, 0x0D, 0x62,
        0x62, 0x60, 0x5E, 0x40, 0xFE, 0x23, 0xA6, 0x2E, 0xB9, 0x65, 0x66, 0x67, 0x6A, 0x77, 0xAE, 0x0D
    ])

    data_test = bytearray([    0xFD, 0xDF, 0xB4, 0x0A, 0x02, 0x9F, 0xA5, 0x6C, 0x96, 0x18, 0x38, 0x95, 0xB7, 0x6F, 0xB0, 0x8D,
                               0xB3, 0xC6, 0xB1, 0xEF, 0x75, 0x5B, 0x7A, 0x80, 0x58, 0xF8, 0x90, 0x73, 0x0C, 0x90, 0xF4, 0x22,
                               0x02, 0x52, 0x2C, 0x87, 0x56, 0x9D, 0x70, 0x4F, 0xC5, 0xD4, 0x88, 0x31, 0x19, 0x73, 0xCA, 0x1F,
                               0x8C, 0x0A, 0x86, 0x29, 0x6C, 0x8E, 0x2D, 0x6B, 0xBC, 0xE9, 0x53, 0xC7, 0x99, 0xFF, 0x2F, 0xCD,
                               0x17, 0x5B, 0x8A, 0xDB, 0x9A, 0xF8, 0x41, 0x8F, 0x40, 0xDB, 0xD6, 0x56, 0xE1, 0x96, 0x77, 0xA9,
                               0x07, 0x50, 0x25, 0xD5, 0x8F, 0x95, 0x96, 0x0E, 0xA9, 0x9D, 0x5D, 0xE4, 0x39, 0x3F, 0x4D, 0xB9,
                               0x48, 0x9F, 0x22, 0x61, 0x1E, 0x22, 0x5C, 0xDE, 0x64, 0x1F, 0x2B, 0x77, 0x4F, 0x6D, 0xC9, 0x40,
                               0x35, 0xF2, 0x8A, 0x48, 0xAD, 0x17, 0x62, 0x45, 0xEF, 0xDD, 0xAE, 0x20, 0x7D, 0x90, 0xCC, 0x7E,
                               0x95, 0xAF, 0xCA, 0xE6, 0x01, 0x18, 0x2B, 0x42, 0x59, 0x7C, 0x9F, 0xC6, 0xDE, 0x09, 0x2E, 0x59,
                               0x7A, 0xA9, 0xBA, 0xEE, 0x01, 0x10, 0x3B, 0x6A, 0x79, 0xB4, 0xDF, 0x1F, 0x61, 0x69, 0x83, 0x8F,
                               0xB6, 0xFE, 0x45, 0x4C, 0x4F, 0x5A, 0x5D, 0x68, 0xAB, 0xFE, 0x52, 0x5A, 0x6E, 0xC6, 0xCE, 0xEB,
                               0x41, 0x41, 0x3F, 0x9F, 0xC1, 0xBE, 0x22, 0x62, 0x9E, 0x4E, 0x02, 0x00, 0xD9, 0x7A, 0x88, 0x8B,
                               0x32, 0xC0, 0xCB, 0xDD, 0xEC, 0x00, 0x8C, 0x1B, 0xAB, 0x42, 0x4C, 0x64, 0x6C, 0x8C, 0x2C, 0xCD,
                               0xED, 0xF6, 0x1E, 0xCA, 0xD1, 0xF7, 0x26, 0xB7, 0x65, 0x68, 0x79, 0xAA, 0x3F, 0xF9, 0x2A, 0xC1,
                               0xC1, 0xC2, 0xC2, 0xC5, 0xC5, 0xCA, 0xC6, 0xCD, 0xD1, 0xCA, 0xD2, 0xCD, 0xD5, 0xD2, 0xC6, 0xC5,
                               0xC1, 0xB2, 0x82, 0xF5, 0x44, 0x3B, 0x08, 0x73, 0xC3, 0xAF, 0x6E, 0xAE, 0x6C, 0xAF, 0x73, 0xA8,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0xA4, 0x09, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xA0, 0x17, 0x00, 0x78, 0x01, 0x14, 0x00])


    data = data_test
    #data = bytearray(binascii.unhexlify("D6F54674D913D11E84FE1C745988FEB34F2DD6A6DE14F9E43B6EBF7A39FF25022A7E2A6D1FBC19767CE0FFE3039940F84E56503E7B92249550C4821EE5C83CEC533C2D798349231C2400FC29D371D7B3DD47F780EB2B8DC833114CE062E570121EDEE0FD1B7799F20D768BF58EF30D79D59BDBF20D37C16144E4C26545EAD599E6FF1B39516787A9C2D8FD21374F7999BBECFC2B404B588394C0CBE90415445178BD040B141F2C77C8DBF13477BE151E3794B10F132D71CBCB4D0200767E77D79422AF3DCCDEF303951CB6414D6D8F33C2C8D1F922A92DBA60656A81069233DB1297199C1CA771B47DCFE122E72BFD504F4A45403B16B9933612AC75D3ED14EB"))
    #data_orig = bytearray(binascii.unhexlify("98189bc5a7a08cf7ef94592e60f22e4a9fe1341634674be46bb82b9fb40ba338a7ab52968b611ab5520dc6f85a4ad8a9fd3c302eed5007e9b526df4f83d329c13bf383e2888241572547e000d0d3f3694ab46cee8453c2bb20885a9d6172a2352b7857e0a1e3a5eeb9091a2b62f1198919030a785469972ee40c86f0360673ba92f559bb1f87ed52b30c77d22d9e0b76d5489d0e65bc33a8f563b3216fcf319b175fa529b133b939bd4b9de978054991cb043dd22ba2157207160200f65bdd419ceec29bf5cfac06633183d6ab0d785632a2f1e2b8297b6c431281cfb52e960f7d8ad9a838c79df4096882d2a22fd5a63ee9f322b1574a1586cca42dc79479e6233e662586e1cc93"))
    #packet_info(binascii.unhexlify("0344010002800000e71500000000000000000000000000000000000001007803000000000dec11b4271401b4a087f548cd7f7fbb00005c770000000000000000000000000000000000000000010000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
    #exit(-1)
    data = bytearray(binascii.unhexlify("52553F9E893A18E2D66F10480DFC566C5119927BDECBA540F8989000EF3E09F70F75DB3FCF82A27ED5585EDFCC512BC277F1DAF0F409F5D04185C5193C3A83C58A30143CB390F0D1C037337ED4B96270129ED1B9F19D01F04C652BD925C9F330AE58C8C4C1BD820079C0B87F476868B17614CA532B9CF30643F0FD1B7FA10E54244D37E5F33F8DA5C0D0DF01111B374D719BC7D6041644527CB2D80F2C47547FC0C3C9CCCED7E1205F6AB5F02C8078C1BA122A629AAEEB235D5601002012D9F5F70CA131C6DEF90BA330C0CDEF16AD4F7AA532E2EF039138E2E9058F2AC2C7DB189F23EC2EFC4552575869BA8F29FC525876D4F2557CDF068F17B48C17B9AD0C"))
    print("Decode - Step 1...")
    data = decode_step_1(data)
    print(hex_dump(data))
    s1_data = data.copy()
    print("Decode - Step 2...")
    data = decode_step_2(data)
    print(hex_dump(data))

    packet_info(data)

    """
    print("Encode - Step 1")
    s1_data = encode_step_1(s1_data)
    print(hex_dump(s1_data))
    if(s1_data == data_orig):
        print("OK!")
    else:
        print("FAIL")
    """


