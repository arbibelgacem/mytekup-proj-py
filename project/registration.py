import ast
import maskpass
import re
import string
import random
from pyfiglet import Figlet
from termcolor import colored 
import hashlib
import bcrypt
#import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyfiglet
from art import text2art









##########################################
a= text2art("catch-me-if-u-can")
print(a)

ff= Figlet(font='slant')
print(colored(ff.renderText("ARBOUCH"),'green')) 

fff= Figlet(font='slant')
print(colored(fff.renderText("SIRS-N"),'yellow')) 

banner = '''
*********************S********************S**********S********************S*****
*S********S**********S**************#SS###SS*******************S**********S*****
****S*******************S********SSSSSSS##SSSSSS*********S**********************
****************S************S*SS####S##S#S##S#**********************S**********
**S****S*******S*************SS&####SS#SS##&#S#S#SS****S************S***********
******SS*******************S#SS#SSS####SS###S#&##S*#S******SS*******************
********************SS****SS####SSSS#SS###SS###SSSS#SS*******************SS*****
**********SS********S*S***S*SSS#S#S*#S###S*S###S#SS#S#*********SS********S*S****
*******S**********S*******#SSSS#S#SS#S####S#SS#S#SS#SS******SS*********SS*******
************************SS#SSSS#S####S#**####S#SSS#&#SS#************************
************************##SS#SS#SSSSS*S**SS#SS#S####S#SSS*****S*****************
***********************S#SSS&#S&#S************#S####SSSSS****S************S*****
***S******************S##S#SS##**S************S**###SS#SSS**********************
***********************SS##SS*S********************SSS###S**********************
*********************S*S##SS#**********************SSS#S#S**********************
*********************#S##S*********************S******SS#SS***************S*S***
*S********S**********#S#SS*SS###SS###SS#####SS####SS**SS#S#****S****************
*********************SS#SS*SS###*SS##S####S#SS#SSSSS**SS#S#*********************
****************S****#*S***SS#S#S#########S#SSSS###S****SS&**********S**********
**S****S*******S*****#S#SS***##&#S#S#S##S#S##SSS##S***SS#S#*SS******S***********
******S***************S#SS&S*###SS##S*SSS#SS###S###*SS###S*SS****S******S*******
********************S**SS##SSSSSS##SS*SSSS*SS##S#SSSS###SS******S********SS*****
**********S******S****S*SSSS#**SSSS*#SS#SSS#SS#S#**#S#S********S*********S*S****
******SS****************S*##&#S*SSSS#SSSS###S*#S*SS#SSSS****S***********S*******
S****************SSSS**S###SSSS#S*SSSSS###SS***SSSS#S#SSSSSSS*******************
********S*****SSSSS#SSS##S#SSSS&SSSSS*S##S*SS**S#SS##&#S#S##S#*S****************
*******S*****S###SSSS#S#S*S*##S&####***SS***#S#S#S#&#S###SSSS#S#S*S*************
***********#S####*S##SSSS*#SSSS#SSS###SSS###S#&##SS#S####*S##SSSS*#SS***********
****S****SS#S##S#S#SS#SSS##S####SSSS#SS###S####SSSS#S##S#S#SS#SSS##S#SS*********
*********#S#S#SSSS#SS#SS##S*SSS#S#S*#S###SSS###S##S#S#SSSS#SS#SS##S*S#S*********
*********SS#SS##S*##SSS&#SSSSSS#S#SS#S#SS#S##S#S#SS#SS##SS#SSSS&#SSSSSS***S*****
****S****S#&#S###SSSS##&#S#SSSS#S####SSSS###SS&SSS#&#S###SSSS##&#S#SSSSS*****S**
*******SS###S#SS#S#SS#S###SS#SS#SS##SS##S#S#SS#S####S#SS#S#SS#S###SS#SS#S*******
*******SS###SSSS####S#S###SS&#S&####SS#SS#S#SSSS####SSSS####S#S##SSS&#S#S*******

                                                    *By ArbiMaatoug https://github.com/arbibelgacem 
'''
  
#f= Figlet(font='banner3-D') 
#print(colored(f.renderText("PA"),'green')+''+colored(f.renderText("LES"),'white')+''+colored(f.renderText("TINE"),'red')) 
print(colored("",'yellow'))
print(colored("Processus d'enregistrement: \n",'yellow'))
print("\t 1-Email: \n")
print("\t\t a-Introduire nom et prenom pour l'email : \n")
print("\t\t b-Introduire email automatic : \n")
print("\t 2-Password : \n")
print("\t\t a-Inroduire password valide : \n")
print("\t\t b-Générer automatiquement un password : \n")

####################################""""
# Générer une paire de clés RSA
def generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,)

    # Sauvegarder la clé privée dans un fichier (par exemple, private_key.pem)
    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))

        # Générer la clé publique depuis la clé privée
        public_key = private_key.public_key()

        # Sauvegarder la clé publique dans un fichier (par exemple, public_key.pem)
        with open("public_key.pem", "wb") as public_key_file:
            public_key_file.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))

################

def gen_cert_autosign():
    #b- Générer un certificat autosigné avec la clé privée RSA :

    # Générer un certificat autosigné 
    with open("private_key.pem", "rb") as private_key_file:
        private_key=private_key_file.read()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tunisia"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Tunis"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "arbouch.com"),])
    # Adjust validity period as needed
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()
        ).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(
        private_key, hashes.SHA256())

    # Sauvegarder le certificat autosigné dans un fichier (par exemple, cert.pem)
    with open("cert.pem", "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
 
     

################


def chiffrer_msg(): 
    with open('public_key.pem', 'rb') as public_key_file:
        public_key_pem = public_key_file.read()
        public_key = load_pem_public_key(public_key_pem, default_backend()) 
    message = input("Donner message a chiffrer: \n").encode() 
    ciphertext = public_key.encrypt(message,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    with open("encrypter.message","wb") as f:
        f.write(ciphertext) 

import rsa
def generate_keys():
    public_key, private_key= rsa.newkeys(1024)
    with open("keys/public.pem","wb") as f:
        f.write(public_key.save_pkcs1("PEM"))
    with open("keys/private.pem","wb") as f:
        f.write(private_key.save_pkcs1("PEM"))


def encrypt_msg():
    message = input("Enter a message to encrypt:\n")
    with open("keys/public.pem","rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    encrypted_message = rsa.encrypt(message.encode(),public_key)
    print(encrypted_message)
    with open("encrypted.message","wb") as f:
        f.write(encrypted_message)


def decrypt_message():
    with open("keys/private.pem","rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    encrypted_messge = open("encrypted.message","rb").read()
    clear_message = rsa.decrypt(encrypted_messge,private_key)
    #print(clear_message.decode())
    print(colored('Congratulation ! Message Decrypted =>','yellow'))
    print(colored(clear_message.decode(),'green'))


def sign_rsa():
    with open("keys/private.pem","rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    message =input("Enter a message to Sign with RSA:\n")
    signature =rsa.sign(message.encode(),private_key,"SHA-256")
    with open("signature",'wb') as f: 
        f.write(signature)
    print(colored("Done",'green'))

def verify_sign():
    message = input("enter the message to verify integrity :\n")
    with open("keys/public.pem","rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    with open("signature",'rb') as f:
        signature=f.read()
    print(rsa.verify(message.encode(),signature ,public_key))




regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9]+(\.[A-Z|a-z]{2,})+')
exit=''
brsa=''
crsa=''
num1=1
menu=''
D={}
Dict={}
auth=False 
found=False

while exit!='e':
    x=input(colored("click==> 'l'  login __ 'r'  register __ 'e'  exit __ ",'yellow'))
    #registration    
    if x=='r':
        y= input(colored("choose 'a' for manual mail or 'b' for automatic mail : ",'yellow'))
        num=num1
        d={}
        if (y == "a"):
            while True:
                email = input(colored("Enter your email (ex.: <arbi.Belgacem@gmail.com>): \n",'yellow'))
                if(re.fullmatch(regex,email)):
                    print (colored("Valid Email Address!\n",'green'))
                    print(colored(f'"{email}"','yellow'))
                    d['Login']=email 
                    break
                else:
                    print(colored("Wrong email format",'red')) 
        elif (y=="b"):
            firstName= input("Type Your FirstName: \n") 
            lastName= input("Type Your LastName: \n")
            mail= firstName+"."+lastName+"@gmail.com"
            print(colored(f'"{mail}"','yellow'))
            d['Login']=mail   
        else: 
            print("Invalid choice")
            
        m=input("choose 'a' for manual password or 'b' to generate password automatic: ")
        if m=='a':
            password= maskpass.askpass("Enter Password: \n")

            flag = 0
            while True:
                if(len(password)<8):
                    print(colored("Password is too short & must be 8 digits ! \n",'red'))
                    flag= -1
                    break
                
                elif not re.search("[a-z]",password):
                    print(colored("Password should contain at least one lowercase letter ! ",'red'))
                    flag= -1
                    break
                elif not re.search("[A-Z]",password):
                    print(colored("Password should contain at least one uppercase letter !",'red'))
                    flag= -1
                    break
                elif not re.search("[_@$]",password):
                    print(colored("Password should contain at least one special character !",'red'))
                    flag= -1
                    break
                else:
                    flag=0
                    print(colored("Valid Password",'green'))
                    print(colored(f'"{password}"','yellow'))
                    d['Password']=password 
                    D[num]=d
                    break
            
            if flag == -1:
                print("Not a valid password ") 

        elif m== 'b':
            a=string.ascii_uppercase
            b=string.ascii_lowercase
            c=string.digits
            s=string.punctuation
            password=''.join(random.choice(a+b+c+s) for _ in range(8))
            print(colored(f'"{password}"','yellow'))
            d['Password']=password 
                
        else: 
            print(colored("Invalid choice",'red'))

        D[num]=d
        num1+=1
        print(D)
        with open('SSIR.txt', 'w',encoding='utf-8') as file:
            file.write(str(D)) 

    #authentication
    elif x=='l':
        with open('SSIR.txt') as f: 
            data = f.read() 
        D = ast.literal_eval(data) 
        #print(D) 
        login=input("donner votre login: \n")
        password= maskpass.askpass("donner votre Password: \n")
        for i in D.values():
            x=i['Login']
            y=i['Password']
            if login == x and password==y:
                auth=True
        if auth:
            print(colored("ACCESS GRANTED",'green')) 
            
            print(banner)
            while menu !='q':

                print("\t\tA- Donnez un mot à haché")
                print("\t\tB- Chiffrement (RSA)")
                print("\t\tC- Certificat (RSA)")
                print("\t\td- Quit")
                menu=input(colored("enter you choice 'a,b or c': ",'yellow'))
                if menu=='a':
                    mot=maskpass.askpass(colored("A. Donnez le mot à hacher (NB : 3 lettre 'lowercase'): ",'yellow')) 
                    print("\t\ta- SHA256Haché le mot par sha256")
                    print("\t\tb- Haché le mot en générant un salt (bcrypt)")
                    print("\t\tc- Attaquer par dictionnaire le mot inséré.")
                    print("\t\td- Revenir au menu principal")   
                    choix=''
                    while choix != 'd' :
                            choix=input(colored('Donnez votre choix : ','yellow'))
                            if choix == 'a' :
                                h=hashlib.sha256(mot.encode()).hexdigest()
                                print(f"\t\tle haché de votre mot est {h}")
                                
                            elif choix =='b':
                                s=bcrypt.gensalt() 
                                salted=bcrypt.hashpw(mot.encode(),s)
                                print("\t\t",salted)   
                            elif choix == 'c' : 
                                with open('alphalist.txt','r') as f:
                                    data = f.read()
                                Dict = ast.literal_eval(data)
                                for i in Dict.values():
                                    if h == i:
                                        print(colored("password found !",'green')) 
                                        for key,value in Dict.items():
                                            if i==value:
                                                print(key)  

                                        found=True
                                        break
                                if found==False:
                                    print(colored('not found !', 'red'))
                            elif choix == 'd' :
                                print("\n#############################################")
                                f= Figlet(font='binary')
                                j= Figlet(font='digital')
                                print(colored(j.renderText("Bye Bye"),'green')) 
                                print(colored(f.renderText("Bye Bye"),'green')) 
                                print("#############################################\n\n\n")
                                break
                            else :
                                print(colored("Merci d'introduire soit a,b,c ou bien d",'yellow'))

                elif menu=='b':
                    print("Chiffrement (RSA)")
                    print("\t\ta- Générer les paires de clés dans un fichier")
                    print("\t\tb- Chiffrer un message de votre choix par RSA")
                    print("\t\tc- Déchiffrer le message (b)")
                    print("\t\td- Signer un message de votre choix par RSA") 
                    print("\t\te- Vérifier la signature du message (d)")
                    print("\t\tf- Revenir au menu principal ")
                    while brsa !='f':
                        h = input(colored("Donner votre choix :\n",'yellow'))
                        if h == 'a':
                            generate_keys()
                            print(colored("Done Successfully! \n Public key & Private key was Generated ",'green'))
                        elif h == 'b':
                            encrypt_msg()
                            print(colored("Your message was Successfully encrypted !"))
                        elif h == 'c':
                            decrypt_message()
                        elif h == 'd':
                            sign_rsa()
                        elif h == 'e':
                            try:
                                verify_sign()
                                print(colored("Signature verified with Success!",'green'))
                            except :
                                print(SystemError)
                                print(colored('Integrity altered or falsified !','red'))
                                
                        elif h == 'f':
                            brsa=h
                        else:
                            print(colored("svp veuiller entrer un choix du liste:\n","red"))
                            

                      
                elif menu=='c':
                    print("Certificat (RSA)")
                    print("\t\ta- Générer les paires de clés dans un fichier ")
                    print("\t\tb- Générer un certificat autosigné par RSA") 
                    print("\t\tc- Chiffrer un message de votre choix par ce certificat")
                    print("\t\td- Revenir au menu principal ")
                    while crsa !='d':
                        g = input(colored("Donner votre choix :\n","yellow"))
                        if g== 'a':
                            try:
                                generate_keypair()
                                print(colored("Done Successfully! \n Public key & Private key was Generated ",'green'))
                            except:
                                print("Error")
                                print(SystemError)
                        elif g == 'b':
                            try:
                                gen_cert_autosign()
                                print(colored("Done Successfully! \n Public key & Private key was Generated ",'green'))
                            except:
                                print("Error")
                                print(SystemError)
                            
                        elif g== 'c':
                            try:
                                chiffrer_msg()
                                print(colored("Your message was Successfully encrypted !"))
                            except:
                                print("Error")
                                print(SystemError) 
                        elif g == 'd':
                            crsa = g
                        else:
                            print(colored("svp veuiller entrer un choix du liste:\n","red"))

                elif menu=='d':
                    print('quit')
                    break
                else:
                    print(colored("please enter a valid input !",'red'))
                
        else:
            print(colored("ACCESS DENIED",'red'))  

    #exit    
    elif x=='e':
        exit=x 
    else:
        print(colored("please enter a valid choice !",'red'))    



print("\n\n\n************************************************************")
print("************************************************************")
bye= Figlet(font='slant')
print(colored(bye.renderText("Good Bye"),'green')) 
print("************************************************************")
print("************************************************************\n\n\n")                              



 