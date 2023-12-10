import re
import random
import string
import os
from string import ascii_uppercase
import math


emailtest = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
   

def isValid(email):
    if re.fullmatch(emailtest, email):
      return True
    else:
      return False

def isValidpass(pwd):
    lowercount=0
    majuscount=0
    numbercounter=0
    symbolcounter=0
    if (len(pwd)>=8):
        for c in pwd :
            if (c.islower()):
                lowercount+=1
            if (c.isupper()):
                majuscount+=1
            if (c.isdigit()):
                numbercounter+=1        
            if re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\]', pwd):
                symbolcounter+=1 
    else :
        print("entrer un password de longuer 8 au minimum") 
        return 0           
    if(lowercount==0):
        print("utiliser au minimum un caractere miniscule")
    if(majuscount==0):
        print("utiliser au minimum un caractere majuscule")
    if(numbercounter==0):
        print("utiliser au minimum un chiffre")
    if(symbolcounter==0):
        print("utiliser au minimum un symbol")            
    if (lowercount != 0 and majuscount != 0 and numbercounter != 0 and symbolcounter!= 0):
       return 1
    return 0                        

def genererpass():
    while True :
        test='1'
        pwd=""
        x=random.randint(8,10)
        for i in range(x) :
            p=random.randint(1,4)
            if(p==1):
                pwd+=random.choice(string.ascii_lowercase)
            elif(p==2):
                pwd+=random.choice(string.ascii_uppercase)
            elif(p==3):
                pwd+=random.choice(string.digits)
            elif(p==4):
                pwd+=random.choice(string.punctuation)
        lowercount=0
        majuscount=0
        numbercounter=0
        symbolcounter=0
        for c in pwd :
            if (c.islower()):
                lowercount+=1
            if (c.isupper()):
                majuscount+=1
            if (c.isdigit()):
                numbercounter+=1        
            if (not c.isalnum()):
                symbolcounter+=1                      
        if (lowercount != 0 and majuscount != 0 and numbercounter != 0 and symbolcounter!= 0):
            test ='0'
        if (test =='0'):
            return(pwd)
        
def caesar_cipher(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha(): 
            if char.isupper():
                encrypted_text += chr(((ord(char) - 65 + shift) % 26) + 65)
            else:
                encrypted_text += chr(((ord(char) - 97 + shift) % 26) + 97)
        else:  
            encrypted_text += chr((ord(char) + shift) % 256)
    return encrypted_text

def caesar_decipher(text, shift):
    return caesar_cipher(text, -shift) 

def vigenere_cipher(plaintext, key):
    encrypted_text = [
        chr(((ord(plaintext[i]) + ord(key[i % len(key)]) - 2 * 97) % 26) + 97)
        if plaintext[i].isalpha()
        else plaintext[i]
        for i in range(len(plaintext))
    ]
    return ''.join(encrypted_text)

def vigenere_decipher(ciphertext, key):
    decrypted_text = [
        chr(((ord(ciphertext[i]) - ord(key[i % len(key)]) + 26) % 26) + 97)
        if ciphertext[i].isalpha()
        else ciphertext[i]
        for i in range(len(ciphertext))
    ]
    return ''.join(decrypted_text)

def vigenere_brute_force(ciphertext):
    possible_keys = []
    for key_length in range(1, len(ciphertext) + 1):
        for start in range(key_length):
            possible_key = ''
            for i in range(start, len(ciphertext), key_length):
                possible_key += ciphertext[i]
            possible_keys.append(possible_key)

    decrypted_messages = []
    for key in possible_keys:
        decrypted_text = vigenere_decipher(ciphertext, key)
        decrypted_messages.append(decrypted_text)

    return decrypted_messages


def caesar_brute_force(ciphertext):
    decrypted_messages = []
    for shift in range(26):
        decrypted_text = ""
        for char in ciphertext:
            if char.isalpha():
                if char.isupper():
                    decrypted_text += chr(((ord(char) - 65 - shift) % 26) + 65)
                else:
                    decrypted_text += chr(((ord(char) - 97 - shift) % 26) + 97)
            else:
                decrypted_text += char 
        decrypted_messages.append(decrypted_text)
    return decrypted_messages

def transpose_matrix_cipher(message, key):
    matrix = [[0] * key for _ in range(len(message) // key + (1 if len(message) % key != 0 else 0))]
    
    idx = 0
    for col in range(key):
        for row in range(len(matrix)):
            if idx < len(message):
                matrix[row][col] = message[idx]
                idx += 1
            else:
                break
    
    result = ""
    for row in range(len(matrix)):
        for col in range(key):
            if matrix[row][col] != 0: 
                result += str(matrix[row][col])
    return result

def transpose_matrix_decipher(message, key):
    num_cols = len(message) // key + (1 if len(message) % key != 0 else 0)
    matrix = [[''] * num_cols for _ in range(key)]
    idx = 0
    for col in range(num_cols):
        for row in range(key):
            if idx < len(message):
                matrix[row][col] = message[idx]
                idx += 1
            else:
                break
    result = ""
    for row in range(key):
        for col in range(num_cols):
            result += matrix[row][col]
    
    return result

class PlayfairCipher:
    def __init__(self, key):
        self.key = key
        self.matrix = self.generate_matrix()

    def generate_matrix(self):
        matrix = []
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        key_processed = ""
        for letter in self.key.upper():
            if letter not in key_processed and letter in alphabet:
                key_processed += letter
        for letter in key_processed:
            if len(matrix) == 0 or letter not in matrix[-1]:
                matrix.append([letter])
            else:
                matrix[-1].append(letter)
        for letter in alphabet:
            if letter not in key_processed:
                if len(matrix) == 0 or letter not in matrix[-1]:
                    matrix.append([letter])
                else:
                    matrix[-1].append(letter)
        return matrix

    def find_position(self, letter):
        for i, row in enumerate(self.matrix):
            if letter in row:
                return i, row.index(letter)
        return None

    def encrypt(self, plaintext):
        plaintext = plaintext.upper().replace("J", "I") 
        plaintext = [char for char in plaintext if char.isalpha()]
        encrypted_text = ""
        i = 0
        while i < len(plaintext):
            char1, char2 = plaintext[i], ""
            if i + 1 < len(plaintext):
                char2 = plaintext[i + 1]
            if char1 == char2:
                char2 = "X"
                i -= 1
            row1, col1 = self.find_position(char1)
            row2, col2 = self.find_position(char2)
            if row1 == row2:
                encrypted_text += self.matrix[row1][(col1 + 1) % 5]
                encrypted_text += self.matrix[row2][(col2 + 1) % 5]
            elif col1 == col2:
                encrypted_text += self.matrix[(row1 + 1) % 5][col1]
                encrypted_text += self.matrix[(row2 + 1) % 5][col2]
            else:
                encrypted_text += self.matrix[row1][col2]
                encrypted_text += self.matrix[row2][col1]
            i += 2
        return encrypted_text

    def decrypt(self, ciphertext):
        decrypted_text = ""
        i = 0
        while i < len(ciphertext):
            char1, char2 = ciphertext[i], ciphertext[i + 1]
            row1, col1 = self.find_position(char1)
            row2, col2 = self.find_position(char2)
            if row1 == row2:
                decrypted_text += self.matrix[row1][(col1 - 1) % 5]
                decrypted_text += self.matrix[row2][(col2 - 1) % 5]
            elif col1 == col2:
                decrypted_text += self.matrix[(row1 - 1) % 5][col1]
                decrypted_text += self.matrix[(row2 - 1) % 5][col2]
            else:
                decrypted_text += self.matrix[row1][col2]
                decrypted_text += self.matrix[row2][col1]
            i += 2
        return decrypted_text

class AffineCipher:
    def __init__(self, a, b):
        self.a = a
        self.b = b
        self.alphabet = ascii_uppercase

    def encrypt(self, plaintext):
        ciphertext = ""
        m = len(self.alphabet)

        for char in plaintext.upper():
            if char in self.alphabet:
                index = (self.a * self.alphabet.index(char) + self.b) % m
                ciphertext += self.alphabet[index]
            else:
                ciphertext += char

        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = ""
        m = len(self.alphabet)
        a_inv = None
        for i in range(1, m):
            if (self.a * i) % m == 1:
                a_inv = i
                break
        if a_inv is not None:
            for char in ciphertext.upper():
                if char in self.alphabet:
                    index = (a_inv * (self.alphabet.index(char) - self.b)) % m
                    plaintext += self.alphabet[index]
                else:
                    plaintext += char
        else:
            raise ValueError("Invalid key: 'a' value does not have a modular inverse.")
        return plaintext
    
    def brute_force_decrypt(self, ciphertext):
        decrypted_messages = []
        m = len(self.alphabet)
        for a in range(1, m):
            if math.gcd(a, m) == 1:
                a_inv = None
                for i in range(1, m):
                    if (a * i) % m == 1:
                        a_inv = i
                        break
                if a_inv is not None:
                    for b in range(m):
                        plaintext = ""
                        for char in ciphertext.upper():
                            if char in self.alphabet:
                                index = (a_inv * (self.alphabet.index(char) - b)) % m
                                plaintext += self.alphabet[index]
                            else:
                                plaintext += char
                        decrypted_messages.append(plaintext)
                else:
                    raise ValueError("Invalid key: 'a' value does not have a modular inverse.")
        return decrypted_messages




    



