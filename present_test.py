from present import Present
# test vectors

# Plaintext         | Key                    | Ciphertext
# ------------------|------------------------|-----------------
# 00000000 00000000 | 00000000 00000000 0000 | 5579C138 7B228445
# 00000000 00000000 | FFFFFFFF FFFFFFFF FFFF | E72C46C0 F5945049
# FFFFFFFF FFFFFFFF | 00000000 00000000 0000 | A112FFC7 2F68417B
# FFFFFFFF FFFFFFFF | FFFFFFFF FFFFFFFF FFFF | 3333DCD3 213210D2


test_vectors = {
    ("0000 0000 0000 0000 0000", "0000 0000 0000 0000"): "5579 C138 7B22 8445",
    ("FFFF FFFF FFFF FFFF FFFF", "0000 0000 0000 0000"): "E72C 46C0 F594 5049",
    ("0000 0000 0000 0000 0000", "FFFF FFFF FFFF FFFF"): "A112 FFC7 2F68 417B",
    ("FFFF FFFF FFFF FFFF FFFF", "FFFF FFFF FFFF FFFF"): "3333 DCD3 2132 10D2"
}


for pair in test_vectors.keys():
    ciphertext = test_vectors[pair]
    key, plaintext = pair
    my_present = Present(key, default_round=32)
    my_ciphertext = my_present.cipher(plaintext)
    print(my_ciphertext)
    print(my_ciphertext == ciphertext.replace(" ", ""))
