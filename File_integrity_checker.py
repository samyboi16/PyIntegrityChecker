import os
import shutil
import hashlib
from pathlib import Path
from tkinter import ttk, filedialog
import tkinter as tk
from ttkthemes import ThemedStyle
#####################################---PyCode---#########################################


    
def open_file(): 
    file_path = filedialog.askopenfilename()
    filename_label.config(text="Selected File: " + os.path.basename(file_path))
    return file_path

def Sha256_HashCalc():
    file_path=open_file()
    buffer_size = 65536
    sha = hashlib.sha256()
    
    with open(file_path,'rb') as file:
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



#############################---GUI---####################################

#Create the main tkinter window
root = tk.Tk() 
root.title("Py File Integrity Checker")
root.config(bg="#f2f2f2")  

#Set the theme for ttk widgets
style = ThemedStyle(root) 
style.set_theme("vista")  

#UI title
label = ttk.Label(root, text="Py File Integrity Checker", font=("Segoe UI", 20), foreground="#3498db", background="#f2f2f2")
label.pack(pady=20)

browse = ttk.Button(text="Browse", command=open_file, style="Rounded.TButton", cursor="hand2")
browse.pack()

style.configure("Rounded.TButton", borderwidth=0, relief="flat", padding=10, font=("Segoe UI", 10)) 

#Create a label to display the selected file status
filename_label = ttk.Label(root, text="Selected File: None", font=("Segoe UI", 12), foreground="black", background="#D3D3D3") 
filename_label.pack(pady=10)

root.mainloop()
######################################################################k
hash_file=Sha256_HashCalc()
#file_name=os.path.basename(myfilepath)
storehash(hash_file)
