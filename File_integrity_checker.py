import os
import shutil
import hashlib
from pathlib import Path
from tkinter import ttk, filedialog
import tkinter as tk
from ttkthemes import ThemedStyle


def Sha256_HashCalc(file_name):
    
    buffer_size = 65536
    sha = hashlib.sha256()
    
    with open(file_name,'rb') as file:
        while True:
            data = file.read(buffer_size)
            if not data:
                break
            sha.update(data)
        return sha.hexdigest()
    

def storehash(hash_value):
    hash_file_path = os.path.join('baseline', f"{file_name}.hash")
    with open(hash_file_path, 'w') as hash_file:
        hash_file.write(hash_value)

myfilepath=filedialog.askopenfilename()

with open(myfilepath,'r') as file:
    file_name=file.read()
print(file_name)


#############################---GUI---####################################
#Create the main tkinter window
root = tk.Tk() 
root.title("Secure File Encryption")
root.config(bg="#f2f2f2")  

#Set the theme for ttk widgets
style = ThemedStyle(root) 
style.set_theme("vista")  

#UI title
label = ttk.Label(root, text="Secure File Encryption", font=("Segoe UI", 20), foreground="#3498db", background="#f2f2f2")
label.pack(pady=20)

#Create and pack widgets for the user interface
login_frame = ttk.Frame(root, padding=(5, 5, 5, 5)) 
login_frame.pack()

style.configure("Rounded.TButton", borderwidth=0, relief="flat", padding=10, font=("Segoe UI", 10)) 

root.mainloop()

hash_file=Sha256_HashCalc(myfilepath)
file_name=os.path.basename(myfilepath)
storehash(hash_file)
