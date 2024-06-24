# Tkinter imports
import tkinter as tk
from tkinter import Entry, messagebox, simpledialog, filedialog

# Import Sha-256
import hashlib

# import AES-encryption
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# adding salt to the password
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import unpad, pad


class File_Integrity_Checker_Tool:
    def __init__(self, fict): # fict = File Integrity Checker Tool
        self.fict = fict
        self.fict.title("File Integerity Checker Tool \U0001F680 \U0001F680 \U0001F680")

        self.interface()

    def interface(self):

        # This button will be used to select the file
        self.choose_file_button = tk.Button(self.fict, text = "CHOOSE THE FILE", command = self.choose_file)
        self.choose_file_button.pack(pady = 10)

        # This button will be used to check integrity by computing the hash
        self.check_integrity_button = tk.Button(self.fict, text = "COMPUTE THE HASH", command = self.check_integrity)
        self.check_integrity_button.pack(pady = 5)

        # This is the button for encrypting the chosen file
        self.encrypt_file = tk.IntVar()
        self.encrypt_file_button = tk.Button(self.fict, text = "Encrypt the chosen file with AES-128", command = self.encrypted_file)
        self.encrypt_file_button.pack(pady = 5)

        # This is the button for decrypting the chosen file
        self.decrypt_file = tk.IntVar()
        self.decrypt_file_button = tk.Button(self.fict, text = "Decrypt the chosen file with AES-128", command = self.decrypted_file)
        self.decrypt_file_button.pack(pady = 5)

        # Color of the Status label
        self.color_status_label = tk.Label(self.fict, text = "", fg = "green")
        self.color_status_label.pack(pady = 10)

        # Print the Hash into the Text Field
        self.hash_of_the_file = tk.Label(self.fict, text = "SHA-256 Hash")
        self.hash_of_the_file.pack()

        self.hash_value = Entry(self.fict, width = 80)
        self.hash_value.pack(pady = 5)


        # Text fields to paste the hash for comparison of two files 
 
        # File 1
        self.file_hash1 = tk.Label(self.fict, text = "File 1 SHA-256 Hash value")
        self.file_hash1.pack()

        self.file_hash1_value = Entry(self.fict, width = 80)
        self.file_hash1_value.pack(pady = 5)

        # File 2
        self.file_hash2 = tk.Label(self.fict, text = "File 2 SHA-256 Hash value")
        self.file_hash2.pack()

        self.file_hash2_value = Entry(self.fict, width = 80)
        self.file_hash2_value.pack(pady = 5)

        # This is the comparison button to compare the hashes
        self.comparison_hash = tk.Button(self.fict, text = "Compare the two hashes", command = self.compare_the_two_hashes)
        self.comparison_hash.pack(pady = 10)

        # This is to clear the File 1 and 2 Hash values in the text field
        self.clear_hash = tk.Button(self.fict, text = "Clear Hashes", command = self.clear_the_hashes)
        self.clear_hash.pack(pady = 5)

        # This is to clear the File 1 and 2 Hash values in the text field
        self.clear_hash_file = tk.Button(self.fict, text = "Clear", command = self.clear_hash_of_the_file)
        self.clear_hash_file.pack(pady = 5)




    def choose_file(self):
        self.filelocation = filedialog.askopenfilename()
        if self.filelocation:
            self.color_status_label.config(text = f"CHOSEN FILE: {self.filelocation}")
            # Clear the text field
            self.hash_value.delete(0, tk.END)
            # Print the hash to the text field
            self.hash_value.config(state = 'normal')
            # Clear the text field
            self.hash_value.delete(0, tk.END)
            # Text field is set to read-only
            self.hash_value.config(state = 'normal')    
    
    def check_integrity(self):
        if not hasattr(self, 'filelocation') or not self.filelocation:
            messagebox.showerror("Error", "You have not selected a file")
            return
        
        try:
            with open(self.filelocation, 'rb') as f:
                file_contents = f.read()

            # Calulate the SHA-256 Hash value for the chosen file
            hash_value = hashlib.sha256(file_contents).hexdigest()

            # Print the hash value in the SHA-256 Hash field
            self.hash_value.config(state = 'normal')
            self.hash_value.delete(0, tk.END)
            self.hash_value.insert(0, hash_value)
            self.hash_value.config(state = 'normal')

            # We will save the hash to a text file for safe keeping
            hash_text_file_location = self.filelocation + "hash.txt"
            with open(hash_text_file_location, 'w') as f:
                f.write(hash_value)
            
            messagebox.showinfo("Hash of the File is computed", f"The hash of the file has been saved to : \n{hash_text_file_location}")

            # # This is the method to encrypt and decrypt the chosen file
            # if self.encrypt_file.get():
            #     self.encrypted_file(file_contents)
            # elif self.decrypt_file.get():
            #     self.decrypted_file(file_contents)

        except Exception as e:
            messagebox.showerror("Error", f"Issue in checking integrity : {str(e)}")
    
    def encrypted_file(self):

        if not hasattr(self, 'filelocation') or not self.filelocation:
            messagebox.showerror("Error", "You have not selected a file")
            return

        try:
            with open(self.filelocation, 'rb') as f:
                contents_of_file = f.read()


            # Here we will generate the AES key and the Initialization Vector in the below sequence

            # Here we will take the password as input from the user
            password = simpledialog.askstring("Password", "Enter your encryption password : ")

            # For enhanced security, we will add a salt
            salt = get_random_bytes(16)

            # Now we will encode the password in byte formnat with the salt where the length of
            # the key is 32 where the CPU will perform 16384 iterations (2**14), 
            # r is the block size and p is for parallelization threads 
            key = scrypt(password.encode(), salt, 32, N = 2**14, r = 8, p = 1)

            # Here is the random Initialization vector
            IV = get_random_bytes(AES.block_size)

            # Now the content will be padded and then encrypted
            contents_padded = pad(contents_of_file, AES.block_size)


            # This is top encrypt the contents
            cipher = AES.new(key, AES.MODE_CBC, IV)
            encrypted_contents = cipher.encrypt(contents_padded)

            # Now we will save the encrypted contents to a new file
            encrypted_file_location = self.filelocation + ".enc"
            with open(encrypted_file_location, 'wb') as f:
                f.write(salt + IV + encrypted_contents)

            messagebox.showinfo("Encryption", f"The file is encrypted and saved as : \n{encrypted_file_location}")

        except Exception as e:
            messagebox.showerror("Error", f"Error in encrypting the chosen file : {str(e)}")

    def decrypted_file(self):

        if not hasattr(self, 'filelocation') or not self.filelocation:
            messagebox.showerror("Error", "You have not selected a file")
            return
        
        try:
            with open(self.filelocation, 'rb') as f:
                contents = f.read()
            # Now we will generate the AES key and Initialization Vector
            password = simpledialog.askstring("Password", "Enter your decryption password : ")

            # We store the salt from the encryption file
            salt = contents[:16]

            # We store the Initialization Vector from the encrypted file
            IV = contents[16:32]

            # We store the ciphertext from the encrypted file
            ciphertext = contents[32:]

            # We derive the key using the password and salt
            key = scrypt(password.encode(), salt, 32, N = 2**14, r = 8, p = 1)

            # Now we will decrypt the data
            cipher = AES.new(key, AES.MODE_CBC, IV)
            decrypted_contents = cipher.decrypt(ciphertext)

            # Now we will unpad the decrypted data
            contents_unpadded = unpad(decrypted_contents, AES.block_size)

            # Now we will save the decrypted contents to a new file
            decrypted_file_location = self.filelocation.replace('.enc', '_decrypted')
            with open(decrypted_file_location, 'wb') as f:
                f.write(contents_unpadded)
            
            messagebox.showinfo("Decryption", f"File is decrypted and saved as : \n{decrypted_file_location}")

        except Exception as e:
            messagebox.showinfo("Error", f"Error in decrypting the chosen file : {str(e)}")


    def compare_the_two_hashes(self):
        first_hash = self.file_hash1_value.get()
        second_hash = self.file_hash2_value.get()

        if first_hash == second_hash:
            messagebox.showinfo("Results of Comparison", "File has not been tampered \U0001F44D")
        else:
            messagebox.showwarning("Comparison Result", "Alert!!! File has been tampered \U0001F480")

    def clear_the_hashes(self):
        self.file_hash1_value.delete(0, tk.END)
        self.file_hash2_value.delete(0, tk.END)
    

    def clear_hash_of_the_file(self):
        self.hash_value.delete(0, tk.END)




if __name__ == "__main__":
    fict = tk.Tk()
    app = File_Integrity_Checker_Tool(fict)
    fict.mainloop()

















