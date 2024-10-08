import tkinter as tk
from tkinter import messagebox
from ciphers import (
    additive_cipher_encrypt, additive_cipher_decrypt,
    multiplicative_cipher_encrypt, multiplicative_cipher_decrypt,
    affine_cipher_encrypt, affine_cipher_decrypt,
    monoalphabetic_substitution_encrypt, monoalphabetic_substitution_decrypt,
    autokey_cipher_encrypt, autokey_cipher_decrypt,
    playfair_cipher_encrypt, playfair_cipher_decrypt,
    vigenere_cipher_encrypt, vigenere_cipher_decrypt,
    keyless_transposition_encrypt, keyless_transposition_decrypt,
    keyed_transposition_encrypt, keyed_transposition_decrypt,
    combined_transposition_encrypt, combined_transposition_decrypt,
    double_transposition_encrypt, double_transposition_decrypt
)

def encrypt_decrypt(plaintext, choice, key1, key2, mode, result_var):
    try:
        # Validate key1 and key2 based on the cipher choice
        if choice in [1, 2]:  # Additive and Multiplicative Ciphers (Numeric key)
            if not key1.isdigit():
                raise ValueError("Key must be numeric for this cipher.")
        
        elif choice == 3:  # Affine Cipher (Two numeric keys)
            if not key1.isdigit() or not key2.isdigit():
                raise ValueError("Both keys must be numeric for Affine Cipher.")
        
        elif choice in [4, 6, 7, 5]:  # Monoalphabetic, Playfair, Vigenère, Autokey (Alphabetic keys)
            if not key1.isalpha():
                raise ValueError("Key must be alphabetic for this cipher.")
        
        elif choice in [9, 11]:  # Keyed and Combined Transposition (Alphabetic key)
            if not key1.isalpha():
                raise ValueError("Key must be alphabetic for Transposition Ciphers.")
        
        elif choice == 10:  # Double Transposition (Two alphabetic keys)
            if not key1.isalpha() or not key2.isalpha():
                raise ValueError("Both keys must be alphabetic for Double Transposition.")

        # Encrypt/Decrypt based on the cipher and mode
        if choice == 1:  # Additive Cipher
            key = int(key1)
            result = additive_cipher_encrypt(plaintext, key) if mode == "E" else additive_cipher_decrypt(plaintext, key)

        elif choice == 2:  # Multiplicative Cipher
            key = int(key1)
            result = multiplicative_cipher_encrypt(plaintext, key) if mode == "E" else multiplicative_cipher_decrypt(plaintext, key)

        elif choice == 3:  # Affine Cipher
            a = int(key1)
            b = int(key2)
            result = affine_cipher_encrypt(plaintext, a, b) if mode == "E" else affine_cipher_decrypt(plaintext, a, b)

        elif choice == 4:  # Monoalphabetic Cipher
            substitution_key = key1  # Assuming the key is the substitution key
            result = monoalphabetic_substitution_encrypt(plaintext, substitution_key) if mode == "E" else monoalphabetic_substitution_decrypt(plaintext, substitution_key)

        elif choice == 5:  # Autokey Cipher
            keyword = key1
            result = autokey_cipher_encrypt(plaintext, keyword) if mode == "E" else autokey_cipher_decrypt(plaintext, keyword)

        elif choice == 6:  # Playfair Cipher
            keyword = key1
            result = playfair_cipher_encrypt(plaintext, keyword) if mode == "E" else playfair_cipher_decrypt(plaintext, keyword)

        elif choice == 7:  # Vigenère Cipher
            keyword = key1
            result = vigenere_cipher_encrypt(plaintext, keyword) if mode == "E" else vigenere_cipher_decrypt(plaintext, keyword)

        elif choice == 8:  # Keyless Transposition
            result = keyless_transposition_encrypt(plaintext) if mode == "E" else keyless_transposition_decrypt(plaintext)

        elif choice == 9:  # Keyed Transposition
            key = key1  # Assuming key1 is a key string
            result = keyed_transposition_encrypt(plaintext, key) if mode == "E" else keyed_transposition_decrypt(plaintext, key)

        elif choice == 10:  # Double Transposition
            key1 = key1.strip()  # Remove extra spaces
            key2 = key2.strip()  # Remove extra spaces
            result = double_transposition_encrypt(plaintext, key1, key2) if mode == "E" else double_transposition_decrypt(plaintext, key1, key2)

        elif choice == 11:  # Combined Transposition (Keyless + Keyed)
            key = key1  # Assuming key1 is a key string for keyed transposition
            result = combined_transposition_encrypt(plaintext, key) if mode == "E" else combined_transposition_decrypt(plaintext, key)

        else:
            raise ValueError("Invalid cipher selection.")

        if mode == "E":
            result_var.set(f"Ciphertext: {result}")
        else:
            result_var.set(f"Plaintext: {result}")

    except ValueError as ve:
        messagebox.showerror("Value Error", str(ve))
    except Exception as e:
        messagebox.showerror("Error", str(e))

def on_cipher_change(cipher_var, key2_entry):
    choice = cipher_var.get()
    # Enable or disable the Key 2 field depending on the selected cipher
    if choice == 3 or choice == 10:  # Affine and Double Transposition need two keys
        key2_entry.config(state='normal')
    else:
        key2_entry.delete(0, tk.END)
        key2_entry.config(state='disabled')

def create_gui():
    root = tk.Tk()
    root.title("Crypto Craft")
    result_var = tk.StringVar(value="Result: ")
    root.config(bg="#73c6b6")

    # Cipher selection
    cipher_var = tk.IntVar(value=1)
    tk.Label(root, text="Select Cipher:", font=("Arial", 12, "bold")).grid(column=0, row=0)

    cipher_names = [
        "Additive Cipher",
        "Multiplicative Cipher",
        "Affine Cipher",
        "Monoalphabetic Substitution Cipher",
        "Autokey Cipher",
        "Playfair Cipher",
        "Vigenère Cipher",
        "Keyless Transposition Cipher",
        "Keyed Transposition Cipher",
        "Double Transposition Cipher",
        "Combination of Keyless and Keyed Transposition"
    ]

    # Use a loop to place each radio button in a separate row
    for i, cipher_name in enumerate(cipher_names, 1):
        tk.Radiobutton(root, text=cipher_name, variable=cipher_var, value=i,
                       command=lambda: on_cipher_change(cipher_var, key2_entry)).grid(column=1, row=i, padx=10, pady=5, sticky="w")

    # Mode selection
    mode_var = tk.StringVar(value="E")
    tk.Label(root, text="Mode:", font=("Arial", 12, "bold")).grid(column=0, row=14, padx=10, pady=5)
    tk.Radiobutton(root, text="Encrypt (E)", variable=mode_var, value="E").grid(column=1, row=14, padx=10, pady=5, sticky="w")
    tk.Radiobutton(root, text="Decrypt (D)", variable=mode_var, value="D").grid(column=1, row=15, padx=10, pady=5, sticky="w")

    # Plaintext entry
    tk.Label(root, text="Enter Plaintext:", font=("Arial", 12, "bold")).grid(column=0, row=16, padx=10, pady=5)
    plaintext_entry = tk.Entry(root, width=25)
    plaintext_entry.grid(column=1, row=16, columnspan=2, padx=10, pady=5, sticky="w")

    # Key entries
    tk.Label(root, text="Key 1:", font=("Arial", 12, "bold"), highlightthickness=0).grid(column=0, row=17, padx=10, pady=5)
    key1_entry = tk.Entry(root, width=25)
    key1_entry.grid(column=1, row=17, columnspan=2, padx=10, pady=5, sticky="w")

    tk.Label(root, text="Key 2: (if needed)", font=("Arial", 12, "bold"), highlightthickness=0).grid(column=0, row=18, padx=10, pady=5)
    key2_entry = tk.Entry(root, width=25)
    key2_entry.grid(column=1, row=18, columnspan=2, padx=10, pady=5, sticky="w")

    # Initially, disable the Key 2 field until required
    key2_entry.config(state='disabled')

    # Encrypt/Decrypt button
    execute_button = tk.Button(root, text="Execute", width=12, font=("Arial", 12, "bold"), highlightthickness=0,
                               command=lambda: encrypt_decrypt(plaintext_entry.get(), cipher_var.get(), key1_entry.get(),
                                                               key2_entry.get(), mode_var.get(), result_var))
    execute_button.grid(column=1, row=19, padx=10, pady=5, sticky="w")

    # Result display
    result_label = tk.Label(root, font=("Arial", 12, "bold"), highlightthickness=0, textvariable=result_var)
    result_label.grid(column=1, row=20, padx=10, pady=5, sticky="w")

    root.mainloop()

if __name__ == "__main__":
    create_gui()
