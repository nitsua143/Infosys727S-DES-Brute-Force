# S-DES Implementation

# Initial Permutation Table
IP = [2, 6, 3, 1, 4, 8, 5, 7]

# Initial Permutation Inverse Table
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

# Expansion Permutation Table
EP = [4, 1, 2, 3, 2, 3, 4, 1]

# Permutation Function P4
P4 = [2, 4, 3, 1]

# Permutation Function P10
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]

# Permutation Function P8
P8 = [6, 3, 7, 4, 8, 5, 10, 9]

# S-Boxes
S0 = [[1, 0, 3, 2],
      [3, 2, 1, 0],
      [0, 2, 1, 3],
      [3, 1, 3, 2]]

S1 = [[0, 1, 2, 3],
      [2, 0, 1, 3],
      [3, 0, 1, 0],
      [2, 1, 0, 3]]

# Left Circular Shifts
LS_1 = [1, 2]

def permute(original, permutation):
    permuted_list = []
    for i in permutation:
        if i <= len(original):
            permuted_list.append(original[i - 1])
        else:
            raise ValueError("Invalid permutation index")
    return permuted_list

def split_into_half(bits):
    return bits[:len(bits)//2], bits[len(bits)//2:]

def left_circular_shift(bits, n):
    return bits[n:] + bits[:n]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def substitute(bits, sbox):
    row = int(''.join([str(bits[0]), str(bits[3])]), 2)
    col = int(''.join([str(bits[1]), str(bits[2])]), 2)
    return [int(b) for b in format(sbox[row][col], '02b')]

def round_function(bits, key):
    # Expansion Permutation
    bits = permute(bits, EP)
    # XOR with key
    bits = xor(bits, key)
    # Substitution
    sbox0_out = substitute(bits[:4], S0)
    sbox1_out = substitute(bits[4:], S1)
    # Permutation
    bits = permute(sbox0_out + sbox1_out, P4)
    return bits

def generate_subkeys(key):
    key = permute(key, P10)
    left, right = split_into_half(key)
    subkeys = []
    for i in LS_1:
        left = left_circular_shift(left, i)
        right = left_circular_shift(right, i)
        subkeys.append(permute(left + right, P8))
    return subkeys

def encrypt(plaintext, key):
    plaintext = permute(plaintext, IP)
    subkeys = generate_subkeys(key)
    left, right = split_into_half(plaintext)
    for subkey in subkeys:
        left, right = right, xor(left, round_function(right, subkey))
    ciphertext = permute(left + right, IP_INV)
    return ciphertext

def decrypt(ciphertext, key):
    ciphertext = permute(ciphertext, IP)
    subkeys = generate_subkeys(key)
    left, right = split_into_half(ciphertext)
    for subkey in reversed(subkeys):
        left, right = right, xor(left, round_function(right, subkey))
    plaintext = permute(left + right, IP_INV)
    return plaintext

# Function to convert binary string to list of integers
def binary_string_to_list(binary_string):
    return [int(bit) for bit in binary_string]

# Given plaintext-ciphertext pairs
plaintext_ciphertext_pairs = [
    ("00000111", "01100101"), 
    ("00001100", "00110111"),
    ("00001111", "01001011"),
    ("00000010", "11010001"),
    ("00000001", "11101011"),
    ("00001011", "00001010"),
    ("00000100", "00001000"),
    ("00000110", "10110100"),
    ("00000000", "01001101"),
    ("00001000", "10110010"),
    ("00001001", "01110101"),
    ("00000101", "10101010"),
    ("10101010", "10010100"),
    ("00001010", "11111010"),
    ("00001101", "00010000"),
    ("00001110", "01011111"),
    ("00000011", "00100100"),

    # Add more pairs here...
]

# Brute-force search for the key
for plaintext, ciphertext in plaintext_ciphertext_pairs:
    plaintext = binary_string_to_list(plaintext)
    ciphertext = binary_string_to_list(ciphertext)
    
    for i in range(1024):  # 1024 possible keys (2^10)
        key = [int(x) for x in format(i, '010b')]  # Generate all possible 10-bit keys

        # Generate subkeys using the modified key
        subkeys = generate_subkeys(key)

        # Decrypt the ciphertext
        decrypted = decrypt(ciphertext, key)
        encrypted = encrypt(plaintext, key)

        # Check if the decrypted plaintext matches the original plaintext
        if decrypted == plaintext and encrypted == ciphertext:
            print(f"Key found for plaintext {plaintext}: {key}")
            break
    else:
        print(f"Key not found for plaintext {plaintext}")
