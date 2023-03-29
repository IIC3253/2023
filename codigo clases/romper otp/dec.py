# We assume the key length is known in advance
KEY_LEN = 36


def get_decrypted_message(ciphertext, key):
    """
        Decrypts a ciphertext with a given key using OTP
    """
    plaintext = ""
    for i in range(len(ciphertext) // KEY_LEN):
        plaintext += bytes([
            c ^ k for c, k in
            zip(ciphertext[i * KEY_LEN: (i + 1) * KEY_LEN], key)
        ]).decode('utf-8')
    return plaintext


if __name__ == "__main__":

    # let's read the bytes of the encrypted file
    ciphertext = None
    with open('encrypt.ed', 'rb') as cipherfile:
        ciphertext = cipherfile.read()

    # we start by separating the ciphertext in chunks
    chunks = [
        ciphertext[i * KEY_LEN: (i + 1) * KEY_LEN]
        for i in range(len(ciphertext) // KEY_LEN)
    ]

    # this will represent the bytes of the key, initialized in 0
    derived_key = [0] * KEY_LEN

    # for each position i of the key
    for i in range(KEY_LEN):

        # we try to guess the most likely space in position i of a chunk
        max_spaces_count = 0
        for c1 in chunks:

            # by counting the number of xors that look like the xor
            # between a space and a lower case letter
            count = 0
            for c2 in chunks:
                if 64 <= c1[i] ^ c2[i] <= 95:
                    count += 1

            if count > max_spaces_count:
                # assign to that position of the key the corresponding value
                max_spaces_count = count
                derived_key[i] = c1[i] ^ 32

    derived_key = bytes(derived_key)
    print(f"The derived key is \"{derived_key.decode('utf-8')}\"\n")

    print("And the decrypted message is:\n")
    print(get_decrypted_message(ciphertext, derived_key))
