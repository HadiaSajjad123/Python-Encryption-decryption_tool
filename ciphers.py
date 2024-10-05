

def additive_cipher_encrypt(plaintext, key):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            shift = (ord(char) - ord('a') + key) % 26 + ord('a')
            encrypted += chr(shift)
        else:
            encrypted += char  # Non-alphabetic characters remain unchanged
    return encrypted

def additive_cipher_decrypt(ciphertext, key):
    decrypted = ""
    for char in ciphertext:
        if char.isalpha():
            shift = (ord(char) - ord('a') - key) % 26 + ord('a')
            decrypted += chr(shift)
        else:
            decrypted += char  # Non-alphabetic characters remain unchanged
    return decrypted

def multiplicative_cipher_encrypt(plaintext, key):
    if key % 26 == 0 or gcd(key, 26) != 1:
        raise ValueError("Key must be coprime with 26.")
    
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            shift = (ord(char) - ord('a')) * key % 26 + ord('a')
            encrypted += chr(shift)
        else:
            encrypted += char  # Non-alphabetic characters remain unchanged
    return encrypted

def multiplicative_cipher_decrypt(ciphertext, key):
    if key % 26 == 0 or gcd(key, 26) != 1:
        raise ValueError("Key must be coprime with 26.")
    
    inverse_key = pow(key, -1, 26)  # Modular multiplicative inverse
    decrypted = ""
    for char in ciphertext:
        if char.isalpha():
            shift = (ord(char) - ord('a')) * inverse_key % 26 + ord('a')
            decrypted += chr(shift)
        else:
            decrypted += char  # Non-alphabetic characters remain unchanged
    return decrypted

def affine_cipher_encrypt(plaintext, a, b):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            shift = (a * (ord(char) - ord('a')) + b) % 26 + ord('a')
            encrypted += chr(shift)
        else:
            encrypted += char  # Non-alphabetic characters remain unchanged
    return encrypted

def affine_cipher_decrypt(ciphertext, a, b):
    inverse_a = pow(a, -1, 26)  # Modular multiplicative inverse
    decrypted = ""
    for char in ciphertext:
        if char.isalpha():
            shift = (inverse_a * ((ord(char) - ord('a')) - b)) % 26 + ord('a')
            decrypted += chr(shift)
        else:
            decrypted += char  # Non-alphabetic characters remain unchanged
    return decrypted

# Add other cipher functions (Monoalphabetic, Autokey, Playfair, Vigenère, Transpositions) below.
# Ensure each function handles both encryption and decryption.

def monoalphabetic_substitution_encrypt(plaintext, substitution_key):
    encrypted = ""
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    for char in plaintext:
        if char.isalpha():
            index = alphabet.index(char)
            encrypted += substitution_key[index]
        else:
            encrypted += char  # Non-alphabetic characters remain unchanged
    return encrypted

def monoalphabetic_substitution_decrypt(ciphertext, substitution_key):
    decrypted = ""
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    for char in ciphertext:
        if char.isalpha():
            index = substitution_key.index(char)
            decrypted += alphabet[index]
        else:
            decrypted += char  # Non-alphabetic characters remain unchanged
    return decrypted

def autokey_cipher_encrypt(plaintext, keyword):
    encrypted = ""
    key = keyword + plaintext
    for i in range(len(plaintext)):
        if plaintext[i].isalpha():
            shift = (ord(plaintext[i]) - ord('a') + ord(key[i]) - ord('a')) % 26 + ord('a')
            encrypted += chr(shift)
        else:
            encrypted += plaintext[i]  # Non-alphabetic characters remain unchanged
    return encrypted

def autokey_cipher_decrypt(ciphertext, keyword):
    decrypted = ""
    key = list(keyword)
    for i in range(len(ciphertext)):
        if ciphertext[i].isalpha():
            shift = (ord(ciphertext[i]) - ord('a') - ord(key[i]) + ord('a')) % 26 + ord('a')
            decrypted += chr(shift)
            key.append(decrypted[i])  # Extend the key with decrypted characters
        else:
            decrypted += ciphertext[i]  # Non-alphabetic characters remain unchanged
    return decrypted

def create_playfair_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 'J' is omitted
    seen = set()
    matrix = []

    # Add characters from the key
    for char in key.upper():
        if char in alphabet and char not in seen:
            seen.add(char)
            matrix.append(char)

    # Fill in remaining characters
    for char in alphabet:
        if char not in seen:
            seen.add(char)
            matrix.append(char)

    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def find_position(char, matrix):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def encrypt_digraph(digraph, matrix):
    row1, col1 = find_position(digraph[0], matrix)
    row2, col2 = find_position(digraph[1], matrix)

    if row1 == row2:
        return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
    elif col1 == col2:
        return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
    else:
        return matrix[row1][col2] + matrix[row2][col1]

def decrypt_digraph(digraph, matrix):
    row1, col1 = find_position(digraph[0], matrix)
    row2, col2 = find_position(digraph[1], matrix)

    if row1 == row2:
        return matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
    elif col1 == col2:
        return matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
    else:
        return matrix[row1][col2] + matrix[row2][col1]

def format_playfair_plaintext(plaintext):
    plaintext = plaintext.replace(" ", "").upper().replace("J", "I")
    formatted_text = ""

    i = 0
    while i < len(plaintext):
        formatted_text += plaintext[i]

        if i + 1 < len(plaintext):
            if plaintext[i] == plaintext[i + 1]:
                formatted_text += 'X'  # Bogus character for the repeated character
                i += 1
            else:
                formatted_text += plaintext[i + 1]  # Add the next character
                i += 2
        else:
            formatted_text += 'X'  # If odd length, add a bogus character
            i += 1

    return formatted_text

def playfair_cipher_encrypt(plaintext, key):
    matrix = create_playfair_matrix(key)
    formatted_plaintext = format_playfair_plaintext(plaintext)

    ciphertext = ""
    for i in range(0, len(formatted_plaintext), 2):
        digraph = formatted_plaintext[i:i + 2]
        ciphertext += encrypt_digraph(digraph, matrix)

    return ciphertext

def playfair_cipher_decrypt(ciphertext, key):
    matrix = create_playfair_matrix(key)

    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        digraph = ciphertext[i:i + 2]
        decrypted = decrypt_digraph(digraph, matrix)
        
        # If 'X' is found, replace it with the preceding character
        if 'X' in decrypted:
            if decrypted[0] == 'X':
                plaintext += decrypted[1]  # Replace 'X' with the other char
            elif decrypted[1] == 'X':
                plaintext += decrypted[0]  # Replace 'X' with the other char
            else:
                plaintext += decrypted  # If no 'X', add as is
        else:
            plaintext += decrypted

    # Remove trailing 'X' if present
    if plaintext.endswith('X'):
        plaintext = plaintext[:-1]

    return plaintext


def vigenere_cipher_encrypt(plaintext, keyword):
    encrypted = ""
    keyword_repeated = (keyword * (len(plaintext) // len(keyword) + 1))[:len(plaintext)]
    for i in range(len(plaintext)):
        if plaintext[i].isalpha():
            shift = (ord(plaintext[i]) - ord('a') + ord(keyword_repeated[i]) - ord('a')) % 26 + ord('a')
            encrypted += chr(shift)
        else:
            encrypted += plaintext[i]  # Non-alphabetic characters remain unchanged
    return encrypted

def vigenere_cipher_decrypt(ciphertext, keyword):
    decrypted = ""
    keyword_repeated = (keyword * (len(ciphertext) // len(keyword) + 1))[:len(ciphertext)]
    for i in range(len(ciphertext)):
        if ciphertext[i].isalpha():
            shift = (ord(ciphertext[i]) - ord('a') - (ord(keyword_repeated[i]) - ord('a'))) % 26 + ord('a')
            decrypted += chr(shift)
        else:
            decrypted += ciphertext[i]  # Non-alphabetic characters remain unchanged
    return decrypted

# 8. Keyless Transposition Cipher
def keyless_transposition_encrypt(plaintext):
    try:
        n = 2  # Example with two columns
        return ''.join([plaintext[i::n] for i in range(n)])
    except Exception as e:
        return f"Error: {e}"

def keyless_transposition_decrypt(ciphertext):
    try:
        n = 2  # Example with two columns
        mid = len(ciphertext) // n
        return ''.join([ciphertext[i] for i in range(mid)] + [ciphertext[i] for i in range(mid, len(ciphertext))])
    except Exception as e:
        return f"Error: {e}"

# 9. Keyed Transposition Cipher
def keyed_transposition_encrypt(plaintext, key):
    try:
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        padded_plaintext = plaintext + ' ' * (len(key) - len(plaintext) % len(key))  # Padding with spaces
        columns = ['' for _ in key]
        
        for i in range(len(padded_plaintext)):
            columns[i % len(key)] += padded_plaintext[i]
        
        return ''.join(columns[i] for i in key_order)
    except Exception as e:
        return f"Error: {e}"

def keyed_transposition_decrypt(ciphertext, key):
    try:
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        n = len(key)
        rows = [ciphertext[i:i + len(ciphertext) // n] for i in range(0, len(ciphertext), len(ciphertext) // n)]
        columns = ['' for _ in key]
        
        for i in key_order:
            columns[i] = rows.pop(0)
        
        return ''.join(''.join(col) for col in zip(*columns)).replace(' ', '')
    except Exception as e:
        return f"Error: {e}"

# 10. Combined Keyless and Keyed Transposition
def combined_transposition_encrypt(plaintext, key):
    try:
        # First apply Keyless Transposition
        intermediate = keyless_transposition_encrypt(plaintext)
        # Then apply Keyed Transposition
        return keyed_transposition_encrypt(intermediate, key)
    except Exception as e:
        return f"Error: {e}"

def combined_transposition_decrypt(ciphertext, key):
    try:
        # First apply Keyed Transposition
        intermediate = keyed_transposition_decrypt(ciphertext, key)
        # Then apply Keyless Transposition
        return keyless_transposition_decrypt(intermediate)
    except Exception as e:
        return f"Error: {e}"

# 11. Double Transposition Cipher
def double_transposition_encrypt(plaintext, key1, key2):
    try:
        # First apply Keyed Transposition
        first_pass = keyed_transposition_encrypt(plaintext, key1)
        # Then apply another Keyed Transposition
        return keyed_transposition_encrypt(first_pass, key2)
    except Exception as e:
        return f"Error: {e}"

def double_transposition_decrypt(ciphertext, key1, key2):
    try:
        # First apply reverse Keyed Transposition
        first_pass = keyed_transposition_decrypt(ciphertext, key2)
        # Then apply reverse Keyed Transposition
        return keyed_transposition_decrypt(first_pass, key1)
    except Exception as e:
        return f"Error: {e}"

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a
