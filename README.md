# PyIntegrityCheck 
This tool is designed to help users verify the integrity of their files using the SHA-256 hash algorithm. It also includes encryption and decryption functionality for an added layer of security, all within an intuitive and user-friendly interface written in Python.

# Requirements
Before running the Python program, ensure you have the following programs and packages installed:  
- Python 3.6 or greater installed
  ```
  python --version
  ```  
- tkinter
- PyCryptodome
# Installation


https://github.com/samyboi16/PyIntegrityChecker/assets/95954618/8db316d3-447c-40df-b0e7-ab296420bb97



1. Clone the repository to your system
```
git clone https://github.com/samyboi16/PyIntegrityChecker.git
```
2. Navigate to the cloned folder
```
cd PyIntegrityChecker
```
3. Install the dependencies
```
pip install -r requirements.txt
```
4. Run the program
```
python3 ./File_integrity_checker.py
```

# Interface
After running the program, we are greeted with this interface

![as](https://github.com/samyboi16/PyIntegrityChecker/assets/95954618/3b691410-9bce-492d-ace4-52a59dfb8bf4)

## Usage
### Step 1: Choose the File:  
To use the program, click on `CHOOSE THE FILE` and select the file you want to create the hash of. Here we can see the file selected,

![image](https://github.com/samyboi16/PyIntegrityChecker/assets/95954618/b4142b66-febe-4d73-993c-5f920af5a0ed)

### Step 2: Compute the Hash  
Now we compute the hash of the file by clicking `COMPUTE THE HASH`. This is stored to a directory called `baseline` in the ``user directory. We also get a visual on the hash of the file.

![image](https://github.com/samyboi16/PyIntegrityChecker/assets/95954618/f4eb9353-d264-4077-93ee-c2dd9412010d)

### Step 3:Comparing the Hashes
To compare the hashes, One computed of our selected file and another of previously stored hash file, click on the `Compare the two hashes` button and you one of two messages:
- Your files have not been tampered  
  ![image](https://github.com/samyboi16/PyIntegrityChecker/assets/95954618/641efee3-86ae-48ba-8f65-679f8241af80)

- Your files have been Tampered  
  ![image](https://github.com/samyboi16/PyIntegrityChecker/assets/95954618/6ee7c9c2-a9ee-45e8-8ed5-a1ff264f1815)
  
### Step 4: Updating the Hashes
When you have made changes to your files, choose the file, compute the new hash and then click on `Update`. This will replace the old hash of the file with the new computed hash.

## Additional Features
An additional feature of our Python tool is the capability to encrypt and decrypt files using the advanced AES-128 encryption standard. This feature ensures that your data is securely protected, making it inaccessible to unauthorized users.

### Encryption
Select the file you want to encrypt using `CHOOSE THE FILE`, And then click on `Encrypt the chosen file with AES-128`. This will prompt you with a password.

  ![image](https://github.com/samyboi16/PyIntegrityChecker/assets/95954618/1449a27e-fb13-478e-a81c-0e2657cbe641)

Your file is now securely encrypted in the same folder.
### Decryption
To Decrypt your file, select the encrypted file and then click on `Decrypt the chosen file with AES-128`. this will prompt you with a password.

![image](https://github.com/samyboi16/PyIntegrityChecker/assets/95954618/6d3ee3b1-af0b-4a59-80ee-32a7a0253e11)

Your file is now decrypted.
**************************************************************

LinkedIn:
- https://www.linkedin.com/in/sameer-mohammed-ali-a0b48b244/
- http://www.linkedin.com/in/m-safwan-66b862315
