from copy import copy

import numpy as np
from bitarray import bitarray

from aes_constants import sbox, invsbox, rcon




def mat_to_hex(in_mat):
    mat_hex = []
    for i in range(0, 4):
        for j in range(0, 4):
            mat_hex.append(hex(in_mat[i][j]))
    mat_hex = np.array(mat_hex).reshape(4, 4)
    return mat_hex


def array_to_hex(in_arr):
    arr_hex = []
    for i in range(0, 4):
        arr_hex.append(hex(in_arr[i]))
    return arr_hex


def hex_mat_to_ascii(in_arr):
    text = ""
    for j in range(0, 4):
        for i in range(0, 4):
            text += chr(in_arr[i][j])
    return text

def bitarray_to_int(inarr: bitarray):
    int_val = 0
    p = 1
    for i in range(0, 8):
        if inarr[7 - i] == 1:
            int_val += p
        p *= 2
    return int_val


def fmul(b, mul):
    if type(b) is not bitarray:
        b = bitarray(format(b, '08b'))
    ori = b.copy()
    r = b.copy()
    if mul == 1:
        return b
    if mul == 2:
        if b[0] == 0:
            r <<= 1
            return r;

        elif r[0] == 1:
            r <<= 1
            r = r ^ bitarray('00011011')
            return r;

    elif mul == 3:
        if b[0] == 0:
            r <<= 1
            r = r ^ ori
        elif b[0] == 1:
            r <<= 1
            r = r ^ bitarray('00011011')
            r = r ^ ori
        return r;
    elif mul == 9:
        return fadd(fmul(fmul(fmul(b, 2), 2), 2), r)
    elif mul == 11:
        return fadd(fmul(fadd(fmul(fmul(b, 2), 2), r), 2), r)
    elif mul == 13:
        return fadd(fmul(fmul(fadd(fmul(b, 2), r), 2), 2), r)
    elif mul == 14:
        return fmul(fadd(fmul(fadd(fmul(b, 2), r), 2), r), 2)
    return b


def fadd(a, b):
    if type(a) is bitarray:
        a = bitarray_to_int(a)
    if type(b) is bitarray:
        b = bitarray_to_int(b)
    return a ^ b


class AES:
    def __init__(self):
        self.state = None
        self.key = None
        self.keys = []
        self.key_index = 0

    def create_state(self, p_text):
        self.state= None
        text_bytes = bytearray(p_text.encode('latin-1'))
        dif = (16 - len(text_bytes))
        while len(text_bytes) < 16:  # PKCS#7 padding: Adding the number of missing bytes
            text_bytes.append(dif)

        self.state = np.array(text_bytes).reshape(4, 4, order='F')  # By columns

    def create_state_example(self):
        text_bytes = bytearray(
            [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])
        self.state = np.array(text_bytes).reshape(4, 4, order='F')  # By columns

    def add_round_key(self):
        for i in range(0, 4):
            for j in range(0, 4):
                self.state[i][j] = self.state[i][j] ^ self.keys[self.key_index][i][j]

    def __str__(self):
        to_print = ""
        # to_print = f"key:\n{hex(self.keys[self.key_index])}\n"
        to_print += f"state:\n{mat_to_hex(self.state)}\n"
        return to_print

    def create_key(self, p_key):
        key_bytes = bytearray(p_key.encode())
        self.keys = []
        self.key_index = 0
        dif = (16 - len(key_bytes))
        while len(key_bytes) < 16:  # PKCS#7 padding: Adding the number of missing bytes
            key_bytes.append(dif)

        self.key = np.array(key_bytes).reshape(4, 4, order='F')  # By columns

    def create_key_example(self):
        key_bytes = bytearray(
            [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
        self.key = np.array(key_bytes).reshape(4, 4, order='F')  # By columns

    def sub_bytes(self):  # Re-assign values based on the AES S Box
        for i in range(0, 4):
            for j in range(0, 4):
                splittable = format(self.state[i][j], '08b')  # Pads with 0
                x = int(splittable[:4], base=2)  # First nibble (4 bits)
                y = int(splittable[4:], base=2)  # Second nibble
                self.state[i][j] = sbox[x][y]

    def inv_sub_bytes(self):  # Re-assign values based on the AES S InvBox
        for i in range(0, 4):
            for j in range(0, 4):
                splittable = format(self.state[i][j], '08b')  # Pads with 0
                x = int(splittable[:4], base=2)  # First nibble (4 bits)
                y = int(splittable[4:], base=2)  # Second nibble
                self.state[i][j] = invsbox[x][y]

    def shift_rows(self):  # Shift rows by their indices to the left
        self.state = [self.state[0], np.roll(self.state[1], -1), np.roll(self.state[2], -2), np.roll(self.state[3], -3)]

    def inv_shift_rows(self):  # Shift rows by their indices to the right
        self.state = [self.state[0], np.roll(self.state[1], 1), np.roll(self.state[2], 2), np.roll(self.state[3], 3)]

    def mix_columns(self):  # Page 17 https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
        # mix_mat = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        s = copy(self.state)
        sp = []
        for c in range(0, 4):
            col = [0] * 4
            p1 = fadd(fmul(s[0][c], 0x02), fmul(s[1][c], 0x03))
            p2 = fadd(p1, s[2][c])
            p3 = fadd(p2, s[3][c])
            col[0] = p3

            p1 = fadd(fmul(s[1][c], 0x02), fmul(s[2][c], 0x03))
            p2 = fadd(s[0][c], p1)
            p3 = fadd(p2, s[3][c])
            col[1] = p3

            p1 = fadd(fmul(s[2][c], 0x02), fmul(s[3][c], 0x03))
            p2 = fadd(s[0][c], s[1][c])
            p3 = fadd(p2, p1)
            col[2] = p3

            p1 = fmul(s[0][c], 0x03)
            p2 = fadd(p1, s[1][c])
            p3 = fadd(p2, s[2][c])
            p4 = fmul(s[3][c], 0x02)
            p5 = fadd(p3, p4)
            col[3] = p5
            sp.append(col)
        self.state = np.transpose(sp)

    def inv_mix_columns(self):
        s = copy(self.state)
        sp = []
        for c in range(0, 4):
            col = [0] * 4
            p1 = fmul(s[0][c], 0x0E)
            p2 = fmul(s[1][c], 0x0B)
            p3 = fmul(s[2][c], 0x0D)
            p4 = fmul(s[3][c], 0x09)
            col[0] = fadd(fadd(fadd(p1, p2), p3), p4)

            p1 = fmul(s[0][c], 0x09)
            p2 = fmul(s[1][c], 0x0E)
            p3 = fmul(s[2][c], 0x0B)
            p4 = fmul(s[3][c], 0x0D)
            col[1] = fadd(fadd(fadd(p1, p2), p3), p4)

            p1 = fmul(s[0][c], 0x0D)
            p2 = fmul(s[1][c], 0x09)
            p3 = fmul(s[2][c], 0x0E)
            p4 = fmul(s[3][c], 0x0B)
            col[2] = fadd(fadd(fadd(p1, p2), p3), p4)

            p1 = fmul(s[0][c], 0x0B)
            p2 = fmul(s[1][c], 0x0D)
            p3 = fmul(s[2][c], 0x09)
            p4 = fmul(s[3][c], 0x0E)
            col[3] = fadd(fadd(fadd(p1, p2), p3), p4)

            sp.append(col)
        self.state = np.transpose(sp)

    def generate_key(self, old_key, key_number):
        full_key = []
        col = [0] * 4
        for i in range(0, 4):
            col[i] = old_key[i][3]
        carry = col[0]
        col = col[1:4]
        col.append(carry)

        # FIRST COLUMN START
        # Sub-Bytes Phase:
        for i in range(0, 4):
            splittable = format(col[i], '08b')  # Pads with 0
            x = int(splittable[:4], base=2)  # First nibble (4 bits)
            y = int(splittable[4:], base=2)  # Second nibble
            col[i] = sbox[x][y]

        # XOR Phase:
        for i in range(0, 4):
            col[i] = old_key[i][0] ^ col[i]
            col[i] = col[i] ^ rcon[i][key_number]
        full_key.append(col)
        # FIRST COLUMN END

        for i in range(0, 3):
            col = [0] * 4
            for j in range(0, 4):
                val1 = old_key[j][i + 1]
                val2 = full_key[i][j]
                col[j] = val1 ^ val2
            full_key.append(col)
        full_key = np.transpose(full_key)
        return full_key

    def key_expansion(self):
        self.keys.append(self.key)
        for i in range(0, 10):
            self.key = self.generate_key(self.key, i)
            self.keys.append(self.key)
            # print(mat_to_hex(self.key))

    def cipher(self):
        self.key_expansion()
        self.add_round_key()
        for i in range(1, 10):
            self.key_index = i
            self.sub_bytes()
            self.shift_rows()
            self.mix_columns()
            self.add_round_key()
            #print(mat_to_hex(self.state))
        self.sub_bytes()
        self.shift_rows()
        self.key_index += 1
        self.add_round_key()

    def decipher(self):
        self.keys = []
        self.key_index = 10
        self.key_expansion()
        self.add_round_key()
        for i in range(1, 10):
            self.inv_shift_rows()
            self.inv_sub_bytes()
            self.key_index = 10-i
            self.add_round_key()
            self.inv_mix_columns()
            # print(mat_to_hex(self.state))
        self.inv_shift_rows()
        self.inv_sub_bytes()
        self.key_index -= 1
        self.add_round_key()


if __name__ == '__main__':
    plain_text = "Hello World!"
    plain_key = "abcdefghijklmopq"
    aes = AES()
    #aes.create_state_example()
    #aes.create_key_example()
    aes.create_state(plain_text)
    aes.create_key(plain_key)
    print(aes)
    aes.cipher()
    print(hex_mat_to_ascii(aes.state).encode('latin-1'))
    state_ascii=hex_mat_to_ascii(aes.state)
    print(repr(state_ascii))
    aes.create_state(state_ascii)
    print(aes)

    #aes.create_key_example()
    aes.create_key(plain_key)
    aes.decipher()
    print(hex_mat_to_ascii(aes.state).encode('latin-1'))

    plain_text="AAAAAAAI"

    aes.create_state(plain_text)
    aes.create_key(plain_key)
    print(aes)
    aes.cipher()
    print(hex_mat_to_ascii(aes.state).encode('latin-1'))
    state_ascii=hex_mat_to_ascii(aes.state)
    print(repr(state_ascii))
    aes.create_state(state_ascii)
    print(aes)

    aes.create_key(plain_key)
    aes.decipher()
    print(hex_mat_to_ascii(aes.state).encode('latin-1'))
    print(aes)

""" 
Useful: https://formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng-html5.html
"""

""" 
From: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
1: procedure CIPHER(in, Nr, w)
    2: state ← in 
    3: state ← ADDROUNDKEY(state,w[0..3])
    4: for round from 1 to Nr −1 do
        5: state ← SUBBYTES(state) 
        6: state ← SHIFTROWS(state)
        7: state ← MIXCOLUMNS(state) 
        8: state ← ADDROUNDKEY(state,w[4 ∗ round..4 ∗ round +3])
    9: end for
    10: state ← SUBBYTES(state)
    11: state ← SHIFTROWS(state)
    12: state ← ADDROUNDKEY(state,w[4 ∗Nr..4 ∗Nr +3])
    13: return state
14: end procedure 
"""
