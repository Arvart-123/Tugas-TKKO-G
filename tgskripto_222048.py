import tkinter as tk
from tkinter import messagebox, ttk

def vigenere_cipher_standard(text, key, mode):
    alphabet_upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    alphabet_lower = 'abcdefghijklmnopqrstuvwxyz'
    result = ''
    key = key.upper()
    key_len = len(key)
    j = 0
    for i, char in enumerate(text):
        if char.isupper():
            shift = alphabet_upper.index(key[j % key_len])
            idx = alphabet_upper.index(char)
            new_idx = (idx + shift) % 26 if mode == 'encrypt' else (idx - shift) % 26
            result += alphabet_upper[new_idx]
            j += 1
        elif char.islower():
            shift = alphabet_upper.index(key[j % key_len])
            idx = alphabet_lower.index(char)
            new_idx = (idx + shift) % 26 if mode == 'encrypt' else (idx - shift) % 26
            result += alphabet_lower[new_idx]
            j += 1
        else:
            result += char
    return result

def vigenere_cipher_extended(text, key, mode):
    result = ''
    key_len = len(key)
    for i, char in enumerate(text):
        shift = ord(key[i % key_len])
        char_code = ord(char)
        new_code = (char_code + shift) % 256 if mode == 'encrypt' else (char_code - shift) % 256
        result += chr(new_code)
    return result

def playfair_cipher(text, key, mode):
    def create_matrix(key):
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        key = ''.join(sorted(set(key.upper()), key=lambda x: key.index(x)))
        matrix = [char for char in key if char in alphabet]
        for char in alphabet:
            if char not in matrix:
                matrix.append(char)
        return [matrix[i:i+5] for i in range(0, 25, 5)]

    def find_position(char, matrix):
        for row_idx, row in enumerate(matrix):
            if char in row:
                return row_idx, row.index(char)

    def process_pair(a, b, matrix, mode):
        ra, ca = find_position(a, matrix)
        rb, cb = find_position(b, matrix)
        if ra == rb:
            return (matrix[ra][(ca+1) % 5] + matrix[rb][(cb+1) % 5]) if mode == 'encrypt' else (matrix[ra][(ca-1) % 5] + matrix[rb][(cb-1) % 5])
        elif ca == cb:
            return (matrix[(ra+1) % 5][ca] + matrix[(rb+1) % 5][cb]) if mode == 'encrypt' else (matrix[(ra-1) % 5][ca] + matrix[(rb-1) % 5][cb])
        else:
            return matrix[ra][cb] + matrix[rb][ca]

    matrix = create_matrix(key)
    text = text.replace('J', 'I').upper().replace(' ', '')
    if len(text) % 2 != 0:
        text += 'X'

    result = ''
    for i in range(0, len(text), 2):
        result += process_pair(text[i], text[i+1], matrix, mode)
    return result

def one_time_pad(text, key, mode):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    result = ''
    key = key.upper()
    key_len = len(key)

    if len(key) < len(text):
        messagebox.showerror("Error", "Key must be at least as long as the text")
        return ""

    for i, char in enumerate(text):
        if char.isalpha():
            shift = alphabet.index(key[i])
            idx = alphabet.index(char.upper())
            new_idx = (idx + shift) % 26 if mode == 'encrypt' else (idx - shift) % 26
            result += alphabet[new_idx] if char.isupper() else alphabet[new_idx].lower()
        else:
            result += char
    return result

def enigma_cipher(text, key, mode):
    rotor_1 = 'EKMFLGDQVZNTOWYHXUSPAIBRCJ'
    rotor_2 = 'AJDKSIRUXBLHWTMCQGZNPYFVOE'
    rotor_3 = 'BDFHJLCPRTXVZNYEIWGAKMUSQO'
    reflector = 'YRUHQSLDPXNGOKMIEBFZCWVJAT'
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    
    rotor_1_position = alphabet.index(key[0].upper())
    rotor_2_position = alphabet.index(key[1].upper())
    rotor_3_position = alphabet.index(key[2].upper())

    result = ''

    def rotate_rotor(rotor):
        return rotor[1:] + rotor[0]

    for char in text.upper():
        if char not in alphabet:
            result += char
            continue
        
        rotor_1 = rotate_rotor(rotor_1)
        rotor_1_position = (rotor_1_position + 1) % 26

        if rotor_1_position == 0:
            rotor_2 = rotate_rotor(rotor_2)
            rotor_2_position = (rotor_2_position + 1) % 26
            
            if rotor_2_position == 0:
                rotor_3 = rotate_rotor(rotor_3)
                rotor_3_position = (rotor_3_position + 1) % 26

        idx = alphabet.index(char)
        idx = alphabet.index(rotor_1[idx])
        idx = alphabet.index(rotor_2[idx])
        idx = alphabet.index(rotor_3[idx])
        idx = alphabet.index(reflector[idx])
        idx = rotor_3.index(alphabet[idx])
        idx = rotor_2.index(alphabet[idx])
        idx = rotor_1.index(alphabet[idx])

        result += alphabet[idx]

    return result

def process_cipher():
    text = input_text.get("1.0", "end-1c")
    key = key_entry.get()
    cipher_type = cipher_var.get()
    mode = mode_var.get()
    
    if cipher_type == "Vigenere Standard":
        result = vigenere_cipher_standard(text, key, mode)
    elif cipher_type == "Vigenere Extended":
        result = vigenere_cipher_extended(text, key, mode)
    elif cipher_type == "Playfair":
        result = playfair_cipher(text, key, mode)
    elif cipher_type == "One-Time Pad":
        result = one_time_pad(text, key, mode)
    elif cipher_type == "Enigma":
        result = enigma_cipher(text, key, mode)
    else:
        messagebox.showerror("Error", "Unsupported cipher type")
        return
    
    output_text.delete("1.0", "end")
    output_text.insert("1.0", result)

root = tk.Tk()
root.title("Cipher GUI")
root.geometry("600x600")
root.config(bg="#f0f5fc")

header = tk.Label(root, text="Cipher Encryption & Decryption", font=("Arial", 16, "bold"), bg="#4a7a8c", fg="white")
header.pack(fill="x")

frame = tk.Frame(root, bg="#e0efff")
frame.pack(expand=True, fill="both", padx=20, pady=20)

tk.Label(frame, text="Input Text:", font=("Arial", 12), bg="#e0efff").grid(row=0, column=0, sticky="w", pady=5)
input_text = tk.Text(frame, height=5, width=50, font=("Arial", 10))
input_text.grid(row=1, column=0, columnspan=2, pady=5)

tk.Label(frame, text="Key:", font=("Arial", 12), bg="#e0efff").grid(row=2, column=0, sticky="w", pady=5)
key_entry = tk.Entry(frame, font=("Arial", 10))
key_entry.grid(row=3, column=0, columnspan=2, pady=5)

cipher_var = tk.StringVar(value="Vigenere Standard")
cipher_menu = ttk.Combobox(frame, textvariable=cipher_var, values=["Vigenere Standard", "Vigenere Extended", "Playfair", "One-Time Pad", "Enigma"], font=("Arial", 10))
cipher_menu.grid(row=5, column=0, columnspan=2, pady=5)

mode_var = tk.StringVar(value="encrypt")
mode_menu = ttk.Combobox(frame, textvariable=mode_var, values=["encrypt", "decrypt"], font=("Arial", 10))
mode_menu.grid(row=7, column=0, columnspan=2, pady=5)

ttk.Button(frame, text="Process", command=process_cipher).grid(row=8, column=0, columnspan=2, pady=10)

output_text = tk.Text(frame, height=5, width=50, font=("Arial", 10))
output_text.grid(row=10, column=0, columnspan=2, pady=5)

root.mainloop()
