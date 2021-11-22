
import os
import sys
import numpy as np
import shutil
from typing import Generator
from ecc.curve import secp256k1, Point, Curve
from ecc.key import gen_keypair
from ecc.cipher import ElGamal

PK_NAME = 'Public_key.txt'
SK_NAME = 'Private_key.txt'
GE_NAME = 'Generator.txt'
CI_NAME = 'Ciphertext.txt'
DE_NAME = 'decryped_Text.txt'

CURVE_TYPE = secp256k1
MAX_ENCODE_LEN = 25

#list all the .ui file under dir 
def ListUiFile():
    ls = []
    files = os.listdir('./')
    for filename in files:
        if os.path.splitext(filename)[1] == '.txt':
            ls.append(filename)
    return ls

def cut(obj, sec):
    return [obj[i:i+sec] for i in range(0,len(obj),sec)]

def WritePointObj(pk):
    return [str(pk.x)+"\n"+str(pk.y)+"\n"+str(pk.curve)+"\n"]

def CreatePkSKfile(pk, sk, gen):
    with open(os.getcwd()+'//'+PK_NAME,'w+') as file_PK:
        with open(os.getcwd()+'//'+SK_NAME,'w+') as file_SK:
            with open(os.getcwd()+'//'+GE_NAME,'w') as file_GE:
                    file_SK.write(str(sk))
                    print("private key generated\n")
                    print("Your private key is create in random, the value is:"+ str(sk) + "\nOr you can check in the Private_key.txt\n")

                    file_PK.writelines(WritePointObj(pk))
                    print("public key generated")           
                    
                    file_GE.write(str(gen))
                    print("generator generated \n")
                    print("Your generator is create in random, the value is:"+ str(gen) + "\nOr you can check in the Generator.txt\n")

def mkdir(path):
        path=path.strip() #remove first space
        path=path.rstrip("//") # remove last "/"
        isExists=os.path.exists(path) #see whether is no PATH
        if not isExists:
            os.makedirs(path)
            print(path+ "\nCreate Sucessful")
            return True
        else:
            print(path+"\nPATH EXIST")
            return False
                    
def ecc_main():
    files = ListUiFile()
    #see whether is no files for pk and sk
    if not PK_NAME in files or not SK_NAME in files: 
        print("Did not find private key or public key Files in "+os.getcwd())
        pri_key, pub_key, generatorG = gen_keypair(CURVE_TYPE)
        CreatePkSKfile(pub_key, pri_key,generatorG)

    #see whether is pk or sk is empty
    if os.path.getsize(PK_NAME) == 0 or os.path.getsize(SK_NAME) == 0: 
        print("pk or sk files are empty, generating public key and secrity key in random")
        pri_key, pub_key, generatorG = gen_keypair(CURVE_TYPE)
        CreatePkSKfile(pub_key, pri_key,generatorG)
        


    #--------Encryption------- 
    #Read pk
    with open(os.getcwd()+'//'+PK_NAME,'r') as file_PK:
                pubs = file_PK.readlines()
                pub_key = Point(x = int(pubs[0].strip()), y = int(pubs[1].strip()), curve = CURVE_TYPE)

    #Encrypt
    plainlist = []
    uList = []
    vList = []
    RandBList = []

    print("\n------------------------ Encryption ----------------------\n")
    print("\n---------The Eliptic Curves You used is secp256k1---------\n")
    plaintext = input("What message you want to encrypt:")
    print("\nYour message that going to be encrypt is \n"+plaintext+'\n')
    plainlist = cut(plaintext.encode('utf-8'), MAX_ENCODE_LEN)
    Cipher_Instance = ElGamal(pub_key.curve)

    for plainElement in plainlist:
        u,v,RandB = Cipher_Instance.encrypt(plainElement, pub_key)
        uList.append(u)
        vList.append(v)
        RandBList.append(RandB)
    print("b = "+ str(RandB) +"\n")
    #Write to file 
    with open(os.getcwd()+'//'+CI_NAME,'w') as file_Ciphertext:
        with open(os.getcwd()+'//'+GE_NAME,'a') as file_GE:
            for u,v,RandB in zip(uList,vList,RandBList):
                file_Ciphertext.writelines(WritePointObj(u))
                file_Ciphertext.writelines(WritePointObj(v))
                file_GE.write(str(RandB)+'\n')   
    print('Finish encryption!\n')
    
    #decryption
    #Read sk
    decryptlist = []
    print("\n------------------------ Decryption ------------------------\n")
    with open(os.getcwd()+'//'+SK_NAME,'r') as file_SK:
            pri_key = int(file_SK.read())
            print("Found the private key")
            
    for u,v in zip(uList,vList):
        decryptText = Cipher_Instance.decrypt(pri_key, u, v).decode('utf-8')
        decryptlist.append(str(decryptText))
        
    decryptText = ''.join(decryptlist)
        
    with open(os.getcwd()+'//'+DE_NAME,'w') as file_DE:
        file_DE.write(decryptText)
    print("Your decrypt message is :\n"+decryptText)

    create = input("""Do you want to keep information?\n
             1.Keep And Save in the current Path.\n
             2.Keep And Create a new Path to Save them.\n
             3.Keep Private/Public key and Generator in this Current Path, and Copy All file in a New Path.\n
             4.Just Keep Private/Public key and Generator\n
             5.Delete them.\n""")
    if create == str(1):
        print("DONE")
    elif create == str(2):
        filename = input("What file name do you want to create:")
        mkdir(os.getcwd()+'//'+filename)
        shutil.move(os.getcwd()+'//'+PK_NAME,os.getcwd()+'//'+filename)
        shutil.move(os.getcwd()+'//'+SK_NAME,os.getcwd()+'//'+filename)
        shutil.move(os.getcwd()+'//'+GE_NAME,os.getcwd()+'//'+filename)
        shutil.move(os.getcwd()+'//'+CI_NAME,os.getcwd()+'//'+filename)
        shutil.move(os.getcwd()+'//'+DE_NAME,os.getcwd()+'//'+filename)
        print("DONE")
    elif create == str(3):
        filename = input("What file name do you want to create:")
        mkdir(os.getcwd()+'//'+filename)
        shutil.move(os.getcwd()+'//'+PK_NAME,os.getcwd()+'//'+filename)
        shutil.move(os.getcwd()+'//'+SK_NAME,os.getcwd()+'//'+filename)
        shutil.move(os.getcwd()+'//'+GE_NAME,os.getcwd()+'//'+filename)
        shutil.move(os.getcwd()+'//'+CI_NAME,os.getcwd()+'//'+filename)
        shutil.move(os.getcwd()+'//'+DE_NAME,os.getcwd()+'//'+filename)
        os.remove(os.getcwd()+'//'+CI_NAME)
        os.remove(os.getcwd()+'//'+DE_NAME)
        print("DONE")
    elif create == str(4):
        os.remove(os.getcwd()+'//'+CI_NAME)
        os.remove(os.getcwd()+'//'+DE_NAME)
        print("DONE")
    elif create == str(5):
        os.remove(os.getcwd()+'//'+PK_NAME)
        os.remove(os.getcwd()+'//'+SK_NAME)
        os.remove(os.getcwd()+'//'+GE_NAME)
        os.remove(os.getcwd()+'//'+CI_NAME)
        os.remove(os.getcwd()+'//'+DE_NAME)
        print("DONE")
    else:
        print("Your Select is not Defined, Just keep all files\n")
   
if __name__ == "__main__":
    ecc_main()