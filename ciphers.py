

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
    try:
        keyword = (keyword + plaintext).upper().replace(' ', '')  # Remove spaces from keyword
        plaintext = plaintext.upper().replace(' ', '')  # Remove spaces from plaintext
        return ''.join([chr(((ord(plaintext[i]) - 65 + ord(keyword[i]) - 65) % 26) + 65) for i in range(len(plaintext))])
    except Exception as e:
        return f"Error: {e}"

def autokey_cipher_decrypt(ciphertext, keyword):
    try:
        keyword = keyword.upper()
        decrypted = []
        keyword_index = 0  # Index for the keyword
        for i in range(len(ciphertext)):
            if ciphertext[i] == ' ':  # Preserve spaces
                decrypted.append(' ')
                continue
            
            key_char = keyword[keyword_index] if keyword_index < len(keyword) else decrypted[keyword_index - len(keyword)]
            decrypted_char = chr(((ord(ciphertext[i]) - ord(key_char)) % 26) + 65)
            decrypted.append(decrypted_char)
            keyword += decrypted_char
            
            keyword_index += 1
            
        return ''.join(decrypted)
    except Exception as e:
        return f"Error: {e}"

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
        mid = (len(ciphertext) + 1) // n
        first_half = ciphertext[:mid]
        second_half = ciphertext[mid:]
        return ''.join(first_half[i:i+1] + second_half[i:i+1] for i in range(mid))
    except Exception as e:
        return f"Error: {e}"


# 9. Keyed Transposition Cipher
def keyed_transposition_encrypt(plaintext, key):
    try:
        key = str(key)  # Convert the key to a string to avoid 'int' error
        key_order = sorted(range(len(key)), key=lambda k: key[k])  # Get key order
        padded_plaintext = plaintext + ' ' * (len(key) - len(plaintext) % len(key))  # Padding with spaces
        columns = ['' for _ in key]
        
        for i in range(len(padded_plaintext)):
            columns[i % len(key)] += padded_plaintext[i]
        
        return ''.join(columns[i] for i in key_order)  # Return rearranged columns based on the key order
    except Exception as e:
        return f"Error: {e}"

def keyed_transposition_decrypt(ciphertext, key):
    try:
        key = str(key)  # Convert the key to a string
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        n = len(key)
        
        # Determine the number of rows
        num_rows = len(ciphertext) // n
        
        # Create columns based on the length of the key
        columns = [''] * n
        for i in range(n):
            columns[key_order[i]] = ciphertext[i * num_rows:(i + 1) * num_rows]  # Fill columns based on key order
        
        # Read the plaintext from the columns
        plaintext = []
        for row in range(num_rows):
            for col in range(n):
                plaintext.append(columns[col][row])
        
        return ''.join(plaintext).rstrip()  # Return the plaintext, stripped of trailing spaces
    except Exception as e:
        return f"Error: {e}"


# 10. Combined Keyless and Keyed Transposition
def combined_transposition_encrypt(plaintext, key):
    try:
        # Keyless Transposition Encrypt
        intermediate = plaintext[::-1]  # Example: Reverse the plaintext

        # Keyed Transposition Encrypt
        n = len(key)
        matrix = ['' for _ in range(n)]
        
        for i, char in enumerate(intermediate):
            matrix[i % n] += char
        
        # Sorting the matrix based on the alphabetical order of the key
        sorted_indices = sorted(range(len(key)), key=lambda x: key[x])
        sorted_matrix = ['' for _ in range(n)]
        
        for i, index in enumerate(sorted_indices):
            sorted_matrix[i] = matrix[index]
        
        return ''.join(sorted_matrix)
    
    except Exception as e:
        return f"Error: {e}"

def combined_transposition_decrypt(ciphertext, key):
    try:
        # Keyed Transposition Decrypt
        n = len(key)
        num_cols = len(ciphertext) // n
        remainder = len(ciphertext) % n
        cols = ['' for _ in range(n)]
        sorted_indices = sorted(range(len(key)), key=lambda x: key[x])
        
        k = 0
        for i in range(n):
            col_len = num_cols + 1 if sorted_indices[i] < remainder else num_cols
            cols[sorted_indices[i]] = ciphertext[k:k + col_len]
            k += col_len
        
        intermediate = ''
        for i in range(num_cols + 1):
            for col in cols:
                if i < len(col):
                    intermediate += col[i]
        
        # Keyless Transposition Decrypt
        return intermediate[::-1]  # Example: Reverse the intermediate
        
    except Exception as e:
        return f"Error: {e}"

# 11. Double Transposition Cipher
def double_transposition_encrypt(plaintext, key1, key2):
    def create_grid(text, key_length):
        # Pad the text if necessary
        while len(text) % key_length != 0:
            text += 'X'  # Padding with 'X'
        return [text[i:i + key_length] for i in range(0, len(text), key_length)]

    # First encryption pass with key1
    key1_length = len(key1)
    grid1 = create_grid(plaintext.replace(" ", ""), key1_length)

    # Sort key1 and create order indices
    sorted_key1_indices = sorted(range(key1_length), key=lambda k: key1[k])

    # Read columns based on sorted key1 indices
    first_pass = ''.join(''.join(grid1[row][col] for row in range(len(grid1))) for col in sorted_key1_indices)

    # Second encryption pass with key2
    key2_length = len(key2)
    grid2 = create_grid(first_pass, key2_length)

    # Sort key2 and create order indices
    sorted_key2_indices = sorted(range(key2_length), key=lambda k: key2[k])

    # Read columns based on sorted key2 indices
    ciphertext = ''.join(''.join(grid2[row][col] for row in range(len(grid2))) for col in sorted_key2_indices)

    return ciphertext

def double_transposition_decrypt(ciphertext, key1, key2):
    def create_grid(text, key_length):
        num_rows = len(text) // key_length
        return [text[i * key_length:(i + 1) * key_length] for i in range(num_rows)]

    # First decryption pass with key2
    key2_length = len(key2)
    num_rows2 = len(ciphertext) // key2_length
    grid2 = create_grid(ciphertext, key2_length)

    # Sort key2 and create order indices
    sorted_key2_indices = sorted(range(key2_length), key=lambda k: key2[k])

    # Reconstruct the first pass grid based on sorted key2 indices
    intermediate_text = [''] * len(ciphertext)
    index = 0
    for col in sorted_key2_indices:
        for row in range(num_rows2):
            intermediate_text[row * key2_length + col] = ciphertext[index]
            index += 1
    first_pass = ''.join(intermediate_text)

    # Second decryption pass with key1
    key1_length = len(key1)
    num_rows1 = len(first_pass) // key1_length
    grid1 = create_grid(first_pass, key1_length)

    # Sort key1 and create order indices
    sorted_key1_indices = sorted(range(key1_length), key=lambda k: key1[k])

    # Reconstruct the plaintext grid based on sorted key1 indices
    original_text = [''] * len(first_pass)
    index = 0
    for col in sorted_key1_indices:
        for row in range(num_rows1):
            original_text[row * key1_length + col] = first_pass[index]
            index += 1
    plaintext = ''.join(original_text)

    return plaintext.replace('X', '')  # Remove padding characters


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a
