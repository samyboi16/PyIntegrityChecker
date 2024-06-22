import os
import shutil
import hashlib
from pathlib import Path
from tkinter import ttk, filedialog


def Sha256_HashCalc(file_name):
    # BUF_SIZE is totally arbitrary, change as per your requirement
    buffer_size = 65536  # 65536 lets read stuff in 64kb chunks!
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

has_file=Sha256_HashCalc(myfilepath)
file_name=os.path.basename(myfilepath)
storehash(p)