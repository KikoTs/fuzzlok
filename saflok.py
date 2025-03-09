#!/bin/env python
import json

# Some sort of static encryption key??
DECODE_ARRAY = [
    0xEA, 0x0D, 0xD9, 0x74, 0x4E, 0x28, 0xFD, 0xBA, 0x7B, 0x98, 0x87, 0x78, 0xDD, 0x8D, 0xB5,
    0x1A, 0x0E, 0x30, 0xF3, 0x2F, 0x6A, 0x3B, 0xAC, 0x09, 0xB9, 0x20, 0x6E, 0x5B, 0x2B, 0xB6,
    0x21, 0xAA, 0x17, 0x44, 0x5A, 0x54, 0x57, 0xBE, 0x0A, 0x52, 0x67, 0xC9, 0x50, 0x35, 0xF5,
    0x41, 0xA0, 0x94, 0x60, 0xFE, 0x24, 0xA2, 0x36, 0xEF, 0x1E, 0x6B, 0xF7, 0x9C, 0x69, 0xDA,
    0x9B, 0x6F, 0xAD, 0xD8, 0xFB, 0x97, 0x62, 0x5F, 0x1F, 0x38, 0xC2, 0xD7, 0x71, 0x31, 0xF0,
    0x13, 0xEE, 0x0F, 0xA3, 0xA7, 0x1C, 0xD5, 0x11, 0x4C, 0x45, 0x2C, 0x04, 0xDB, 0xA6, 0x2E,
    0xF8, 0x64, 0x9A, 0xB8, 0x53, 0x66, 0xDC, 0x7A, 0x5D, 0x03, 0x07, 0x80, 0x37, 0xFF, 0xFC,
    0x06, 0xBC, 0x26, 0xC0, 0x95, 0x4A, 0xF1, 0x51, 0x2D, 0x22, 0x18, 0x01, 0x79, 0x5E, 0x76,
    0x1D, 0x7F, 0x14, 0xE3, 0x9E, 0x8A, 0xBB, 0x34, 0xBF, 0xF4, 0xAB, 0x48, 0x63, 0x55, 0x3E,
    0x56, 0x8C, 0xD1, 0x12, 0xED, 0xC3, 0x49, 0x8E, 0x92, 0x9D, 0xCA, 0xB1, 0xE5, 0xCE, 0x4D,
    0x3F, 0xFA, 0x73, 0x05, 0xE0, 0x4B, 0x93, 0xB2, 0xCB, 0x08, 0xE1, 0x96, 0x19, 0x3D, 0x83,
    0x39, 0x75, 0xEC, 0xD6, 0x3C, 0xD0, 0x70, 0x81, 0x16, 0x29, 0x15, 0x6C, 0xC7, 0xE7, 0xE2,
    0xF6, 0xB7, 0xE8, 0x25, 0x6D, 0x3A, 0xE6, 0xC8, 0x99, 0x46, 0xB0, 0x85, 0x02, 0x61, 0x1B,
    0x8B, 0xB3, 0x9F, 0x0B, 0x2A, 0xA8, 0x77, 0x10, 0xC1, 0x88, 0xCC, 0xA4, 0xDE, 0x43, 0x58,
    0x23, 0xB4, 0xA1, 0xA5, 0x5C, 0xAE, 0xA9, 0x7E, 0x42, 0x40, 0x90, 0xD2, 0xE9, 0x84, 0xCF,
    0xE4, 0xEB, 0x47, 0x4F, 0x82, 0xD4, 0xC5, 0x8F, 0xCD, 0xD3, 0x86, 0x00, 0x59, 0xDF, 0xF2,
    0x0C, 0x7C, 0xC6, 0xBD, 0xF9, 0x7D, 0xC4, 0x91, 0x27, 0x89, 0x32, 0x72, 0x33, 0x65, 0x68,
    0xAF
]

KEY_LEVELS = [
    (1, "Guest Key"),
    (2, "Connectors"),
    (3, "Suite"),
    (4, "Limited Use"),
    (5, "Failsafe"),
    (6, "Inhibit"),
    (7, "Pool/Meeting Master"),
    (8, "Housekeeping"),
    (9, "Floor Key"),
    (10, "Section Key"),
    (11, "Rooms Master"),
    (12, "Grand Master"),
    (13, "Emergency"),
    (14, "Electronic Lockout"),
    (15, "Secondary Programming Key (SPK)"),
    (16, "Primary Programming Key (PPK)"),
]

def validate(val, minimum, maximum, text, fmt="int"):
    if not (minimum <= val <= maximum):
        if fmt == 'int':
            mn = minimum
            mx = maximum
            v = val
        elif fmt == 'hex':
            mn = hex(minimum)
            mx = hex(maximum)
            v = hex(val)
        elif fmt == 'bin':
            mn = bin(minimum)
            mx = bin(maximum)
            v = hex(val)
        else:
            raise ValueError("Invalid format string for validation")

        raise ValueError(f"Invalid input: {text} // Valid values: {mn}->{mx} // Given: {v}")

def decrypt_card(ecard_data):
    # Where we put the decrypted card data
    dc = []

    # Setup
    length = 17

    # Stage 1??
    for i in range(0, length):
        num = DECODE_ARRAY[ecard_data[i]] - (i + 1)
        if num < 0:
            num += 256
        dc.append(num)

    # Stage 2
    bob = dc[10]
    # Alice = bob's lsigdig
    alice = bob & 1

    # Stage 3
    # I'm using names here to hopefully make it easier to follow than num1, num2, etc.
    for zeta in range(17, 0, -1):
        bob = dc[zeta - 1]
        for xi in range(8, 0, -1):
            yip = zeta + xi
            if(yip > length):
                yip -= length
            charlie = dc[yip - 1]
            # print(f"charlie({charlie:02x}) = dc[yip({yip:02x}) - 1]")
            # save msigdig from charlie
            david   =  (charlie & 0x80) >> 7
            # print(f"david({david:02x})   =  (charlie({charlie:02x}) & 0x80) >> 7")
            # double charlie, truncate, add alice to the end
            charlie = ((charlie << 1) & 0xFF) | alice
            # print(f"charlie({charlie:02x}) = ((charlie({charlie:02x}) << 1) & 0xFF) | alice({alice:02x})")
            # alice becomes bob's msigdig
            alice   =  (bob & 0x80) >> 7
            # print(f"alice({alice:02x})   =  (bob({bob:02x}) & 0x80) >> 7")
            # bob get's charlie's msigdig
            bob     = ((bob << 1) & 0xFF) | david
            # print(f"bob({bob:02x})     = ((bob({bob:02x}) << 1) & 0xFF) | david({david:02x})")

            dc[yip - 1] = charlie
            # print(f"dc[yip({yip:02x})] = charlie({charlie:02x})")
        dc[zeta - 1] = bob
        # print(f"dc[zeta({zeta:02x})] = bob({bob:02x})")

    return dc

def encrypt_card(dcard_data):

    ec = []

    length = 17
    alice = 0 # ??? not sure how this would be set, it doesn't seem to matter, which is weird...

    for zeta in range(1, 18):
        bob = dcard_data[zeta - 1]
        for xi in range(1, 9):
            yip = zeta + xi
            if(yip > length):
                yip -= length
            charlie = dcard_data[yip - 1]
            # Retrieve charlie's lsigdig aka david
            david   =  bob & 1
            # Put bob back together
            bob     = (bob >> 1) | (alice << 7)
            # Get alice back
            alice   =  charlie & 1
            # Put charlie back together
            charlie = (charlie >> 1) | (david << 7)
            dcard_data[yip - 1] = charlie
        dcard_data[zeta - 1] = bob

    # This works. No need to do anything here
    for i in range(0, length):
        num = dcard_data[i] + (i + 1)
        if num >= 256:
            num -= 256
        ec.append(DECODE_ARRAY.index(num))

    return ec

def decode_card(dcard_data):

    # Here's where we figure out what each byte does
    card = {}

    # Byte 0
    card['key_level_no'], card['key_level_text'] = KEY_LEVELS[(dcard_data[0] & 0xF0) >> 4]
    card['led_warning'] = (dcard_data[0] & 0x08) >> 3

    # Byte 1
    card['key_id'] = hex(dcard_data[1])

    # Byte 2 & 3
    card['key_record_high'] = dcard_data[2] & 0x7F
    card['opening_key'] = (dcard_data[2] & 0x80) >> 7
    card['key_record'] = hex((card['key_record_high'] << 8) | dcard_data[3])

    # Byte 5 & 6
    card['sequence_combination_number'] = hex(((dcard_data[5] & 0x0F) << 8) | dcard_data[6])

    # Property ID and year, bytes 14 & 15
    card['creation_year_bits'] = (dcard_data[14] & 0xF0)
    card['property_id'] = ((dcard_data[14] & 0x0F) << 8) | dcard_data[15]

    # Byte 7 override deadbolt and days
    card['override_deadbolt'] = (dcard_data[7] & 0x80) >> 7
    card['restricted_weekday'] = dcard_data[7] & 0x7F

    card['interval_year'] = dcard_data[8] >> 4
    card['interval_month'] = dcard_data[8] & 0x0f
    card['interval_day'] = (dcard_data[9] >> 3) & 0x1F
    card['interval_hour'] = ((dcard_data[9] & 0x07) << 2) | (dcard_data[10] >> 6)
    card['interval_minute'] = dcard_data[10] & 0x3F

    card['creation_year'] = (((dcard_data[11] & 0xF0) >> 4) + 1980) | card['creation_year_bits']
    card['creation_month'] = dcard_data[11] & 0x0F;
    card['creation_day'] = (dcard_data[12] >> 3) & 0x1F;
    card['creation_hour'] = ((dcard_data[12] & 0x07) << 2) | (dcard_data[13] >> 6);
    card['creation_minute'] = dcard_data[13] & 0x3F;

    card['checksum'] = hex(dcard_data[16])
    card['csum_pass'] = dcard_data[16] == calculate_checksum(dcard_data)

    return card

def calculate_checksum(dcard_data):
    # Let's validate the checksum
    calc_sum = 0

    # Duh, checksum isn't part of the checksum, hence 16 instead of 17
    for i in range(0, 16):
        calc_sum += dcard_data[i]

    calc_sum = 255 - (calc_sum & 0xff)

    return calc_sum
    

def encode_card(card):

    # Initialize all to 0 so we have a valid key
    dcard_data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    # Byte 0
    validate(card['key_level_no'], 1, 16, "key_level_no")
    validate(card['led_warning'], 0, 1, "led_warning")
    dcard_data[0] = ((card['key_level_no'] - 1) << 4) | (card['led_warning'] << 3)

    # Byte 1
    validate(card['key_id'], 0, 255, "key_id", fmt="hex")
    dcard_data[1] = card['key_id']

    # Bytes 2 & 3
    validate(card['key_record'], 0, 0x7fff, 'key_record', fmt='hex')
    validate(card['opening_key'], 0, 1, 'opening_key')
    key_record_high = (card['key_record'] & 0xf00) >> 8
    dcard_data[2] = key_record_high | (card['opening_key'] << 7)
    dcard_data[3] = card['key_record'] & 0xff

    # Bytes 5 & 6
    # card['sequence_combination_number'] = ((dcard_data[5] & 0x0F) << 8) | dcard_data[6]
    validate(card['sequence_combination_number'], 0, 0xfff, 'sequence_combination_number', fmt='hex')
    dcard_data[5] = (card['sequence_combination_number'] & 0xf00) >> 8
    dcard_data[6] = card['sequence_combination_number'] & 0xff

    # Property ID and year, bytes 14 & 15
    # validate(card['creation_year_bits'], 0x10, 0xf0, 'creation_year_bits') # why?? whatever
    validate(card['property_id'], 0, 4095, 'property_id')
    creation_year_bits = (card['creation_year'] - 1980) & 0xf0
    dcard_data[14] = creation_year_bits | (card['property_id'] & 0xf00) >> 8
    dcard_data[15] = card['property_id'] & 0xff

    # Byte 7 override deadbolt and days
    validate(card['override_deadbolt'], 0, 1, 'override_deadbolt')
    validate(card['restricted_weekday'], 0, 127, 'restricted_weekday', fmt='bin')
    dcard_data[7] = (card['override_deadbolt'] << 7) | card['restricted_weekday']

    # Byte 8 year/month
    validate(card['interval_year'], 0, 15, 'interval_year')
    validate(card['interval_month'], 0, 15, 'interval_month')
    dcard_data[8] = (card['interval_year'] << 4) | card['interval_month']

    # Bytes 9/10 interval day/hr/min
    validate(card['interval_day'], 0, 31, 'interval_day')
    validate(card['interval_hour'], 0, 23, 'interval_hour') # 0-31
    validate(card['interval_minute'], 0, 59, 'interval_minute') # 0-63
    dcard_data[9] = (card['interval_day'] << 3) | ((card['interval_hour'] & 0x1c) >> 2)
    dcard_data[10] = ((card['interval_hour'] & 0x3) << 6) | (card['interval_minute'] & 0x3f)

    # Bytes 11 year/month
    validate(card['creation_year'], 1980, 2235, 'creation_year')
    validate(card['creation_month'], 1, 12, 'creation_month') # 0-15
    dcard_data[11] = (((card['creation_year'] - 1980) & 0xf) << 4) | card['creation_month']

    # Bytes 12/13 day/hr/min
    validate(card['creation_day'], 0, 31, 'creation_day')
    validate(card['creation_hour'], 0, 23, 'creation_hour')
    validate(card['creation_minute'], 0, 59, 'interval_minute') # 0-63
    dcard_data[12] = (card['creation_day'] << 3) | ((card['creation_hour'] & 0x1c) >> 2)
    dcard_data[13] = ((card['creation_hour'] & 0x3) << 6) | (card['creation_minute'] & 0x3f)

    dcard_data[16] = calculate_checksum(dcard_data)
    return dcard_data

if __name__ == "__main__":

    # Encrypted Card data
    ecard_data = [
        0x64, 0xC0, 0x6F, 0x56, 0x13, 0x69, 0x20, 0xDB, 0x8B, 0x04, 0xE9, 0x32, 0x34, 0x0F, 0xA4, 0xA0,
        0x8A
    ]
    dcard_data = decrypt_card(ecard_data)
    plaintext = decode_card(dcard_data)
    print(json.dumps(plaintext, indent=1))

    card_text = {
        "key_level_no": 1,
        "key_level_text": "Guest Key",
        "led_warning": 0,
        "key_id": 0xf7,
        "key_record_high": 0,
        "opening_key": 1,
        "key_record": 0x11,
        "sequence_combination_number": 0xe34,
        "creation_year_bits": 32,
        "property_id": 1142,
        "override_deadbolt": 0,
        "restricted_weekday": 0,
        "interval_year": 0,
        "interval_month": 0,
        "interval_day": 1,
        "interval_hour": 13,
        "interval_minute": 0,
        "creation_year": 2025,
        "creation_month": 2,
        "creation_day": 1,
        "creation_hour": 20,
        "creation_minute": 13,
        "checksum": "0x64",
        "csum_pass": True
    }

    dcard_data = encode_card(card_text)
    plaintext = decode_card(dcard_data)
    print(json.dumps(plaintext, indent=1))
