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


def bitarray_to_int(inarr: bitarray):
    int_val = 0
    p = 1
    for i in range(0, 8):
        if inarr[7 - i] == 1:
            int_val += p
        p *= 2
    return int_val


def fmul(b, mul):
    b = bitarray(format(b, '08b'))
    ori = b.copy()

    if mul == 1:
        return b
    if mul == 2:
        if b[0] == 0:
            b = b[1:8]
            b.append(0)
        elif b[0] == 1:
            b <<= 1
            b = b ^ bitarray('00011011')
    elif mul == 3:
        if b[0] == 0:
            b <<= 1
            b = b ^ ori
        elif b[0] == 1:
            b <<= 1
            b = b ^ bitarray('00011011')
            b = b ^ ori
    return bitarray_to_int(b)


def fadd(a, b):
    return a ^ b


class AES:
    def __init__(self):
        self.state = None
        self.key = None
        self.keys = []

    def create_state(self, p_text):
        text_bytes = bytearray(p_text.encode())
        dif = (16 - len(text_bytes))
        while len(text_bytes) < 16:  # PKCS#7 padding: Adding the number of missing bytes
            text_bytes.append(dif)

        self.state = np.array(text_bytes).reshape(4, 4, order='F')  # By columns

    def add_round_key(self):
        for i in range(0, 4):
            for j in range(0, 4):
                self.state[i][j] = self.state[i][j] ^ self.key[i][j]

    def __str__(self):
        to_print = ""
        # to_print = f"key:\n{hex(self.key)}\n"
        to_print += f"state:\n{mat_to_hex(self.state)}\n"
        return to_print

    def create_key(self, p_key):
        key_bytes = bytearray(p_key.encode())
        dif = (16 - len(key_bytes))
        while len(key_bytes) < 16:  # PKCS#7 padding: Adding the number of missing bytes
            key_bytes.append(dif)

        self.key = np.array(key_bytes).reshape(4, 4, order='F')  # By columns

    def sub_bytes(self):  # Re-assign values based on the AES S Box
        for i in range(0, 4):
            for j in range(0, 4):
                splittable = format(self.state[i][j], '08b')  # Pads with 0
                x = int(splittable[:4], base=2)  # First nibble (4 bits)
                y = int(splittable[4:], base=2)  # Second nibble
                self.state[i][j] = sbox[x][y]

    def shift_rows(self):  # Shift rows by their indices to the left
        self.state = [self.state[0], np.roll(self.state[1], -1), np.roll(self.state[2], -2), np.roll(self.state[3], -3)]

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
        self.state = sp  # VERY UNSURE IF THIS WORKS

    def key_expansion(self):
        key = self.key.tolist()
        key_count = 1

        col_count = 0
        index = 3
        for r in range(0, 36):
            full_key = []
            col = [0] * 4
            for i in range(0, 4):
                col[i] = key[i][index + r]

            if r % 4 == 0:
                # Rotate Phase:
                carry = col[0]
                col = col[1:4]
                col.append(carry)

                # Sub-Bytes Phase:
                for i in range(0, 4):
                    splittable = format(col[i], '08b')  # Pads with 0
                    x = int(splittable[:4], base=2)  # First nibble (4 bits)
                    y = int(splittable[4:], base=2)  # Second nibble
                    col[i] = sbox[x][y]

                # XOR Phase:
                for i in range(0, 4):
                    col[i] = key[i][r + index - 3] ^ col[i]
                    col[i] = col[i] ^ rcon[i][r % 4]

                # Add to keys columns
                for i in range(0, 4):
                    key[i].append(col[i])
                full_key.append(col)
            else:
                for i in range(0, 4):
                    col[i] = key[i][r + index - 1] ^ col[i]
                # Add to keys columns
                for i in range(0, 4):
                    key[i].append(col[i])
                full_key.append(col)

            if r % 4 and r != 0:
                self.keys.append(full_key)
                full_key = []


if __name__ == '__main__':
    plain_text = "Hello World!"
    plain_key = "abcdefghijklmop"
    aes = AES()
    aes.create_state(plain_text)
    aes.create_key(plain_key)
    print(aes.key)
    aes.key_expansion()
    print(aes.keys) #TODO: FIX THIS

    # print(aes)
    # aes.add_round_key()
    # print(aes)
    # aes.sub_bytes()
    # print(aes)
    # aes.shift_rows()
    # print(aes)
    # aes.mix_columns()
    # print(aes)

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
