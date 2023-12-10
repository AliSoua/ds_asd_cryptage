import tkinter
import customtkinter    
from CTkMessagebox import CTkMessagebox
from Sub_Functions import *
from PIL import Image, ImageTk
import qrcode
import hashlib
from data import *
import pyotp
import qrcode

customtkinter.set_appearance_mode("system")
customtkinter.set_default_color_theme("green")
app = customtkinter.CTk()
app.geometry("600x440")
app.title("Project Python")
my_image = ImageTk.PhotoImage(Image.open('bgp2.jpg'))
button = customtkinter.CTkLabel(app, image=my_image ,)
button.pack()


def caesar_cipher_call() :
    msg = caesar_cipher(caesar_text.get(),int(caesar_key.get()))
    CTkMessagebox(title="Info", message=msg)
def caesar_decipher_call() :
    msg = caesar_decipher(caesar_text.get(),int(caesar_key.get()))
    CTkMessagebox(title="Info", message=msg)
def caesar_brute_call() :
    msg = caesar_brute_force(caesar_text.get())
    CTkMessagebox(title="Info", message=msg)

def vigenere_cipher_call() :
    msg = vigenere_cipher(vigenere_text.get(),vigenere_key.get())
    CTkMessagebox(title="Info", message=msg)
def vigenere_decipher_call() :
    msg = vigenere_decipher(vigenere_text.get(),vigenere_key.get())
    CTkMessagebox(title="Info", message=msg)
def vigenere_brute_call() :
    msg = vigenere_brute_force(vigenere_text.get())
    CTkMessagebox(title="Info", message=msg)

def transposition_cipher_call() :
    msg = transpose_matrix_cipher(transposition_text.get(),int(transposition_key.get()))
    CTkMessagebox(title="Info", message=msg)
def transposition_decipher_call() :
    msg = transpose_matrix_decipher(transposition_text.get(),int(transposition_key.get()))
    CTkMessagebox(title="Info", message=msg)

def playfair_cipher_call() :
    pfcipher = PlayfairCipher(playfair_key.get())
    msg = pfcipher.encrypt(playfair_text.get())
    CTkMessagebox(title="Info", message=msg)
def playfair_decipher_call() :
    pfcipher = PlayfairCipher(playfair_key.get())
    msg = pfcipher.decrypt(playfair_text.get())
    CTkMessagebox(title="Info", message=msg)

def affine_cipher_call() :
    pfcipher = AffineCipher(int(affine_key.get()),int(affine_key2.get()))
    msg = pfcipher.encrypt(affine_text.get())
    print(msg)
def affine_decipher_call() :
    pfcipher = AffineCipher(int(affine_key.get()),int(affine_key2.get()))
    msg = pfcipher.decrypt(affine_text.get())
    CTkMessagebox(title="Info", message=msg)
def affine_brute_call() :
    pfcipher = AffineCipher(int(affine_key.get()),int(affine_key2.get()))
    msg = pfcipher.brute_force_decrypt(affine_text.get())
    CTkMessagebox(title="Info", message=msg)

def registerrandompass () :

    if wel_email.get()=="" or wel_pwd.get()!="" or wel_pwd2.get()!="" :
        CTkMessagebox(title="Error", message="To register using this feature you need just to fill email and leave the other textboxes empty")
    else:
        if check_email_existence(wel_email.get()) == False :
                if isValid(wel_email.get()) :
                    password = genererpass()
                    passqr = customtkinter.CTkLabel(qrframe , text="This is your pass : " + password , font=('century gothic', 16))
                    passqr.place(x=55 , y=20)

                    password = hashlib.sha256(wel_pwd.get().encode()).hexdigest()
                    add_user(wel_email.get(),password)
                    CTkMessagebox(title="Info", message="valid registration " ) 
                    registerframe.place_forget() 
                    key = "alisouasecretkey"
                    uri = pyotp.totp.TOTP(key).provisioning_uri(name="alisoua", issuer_name="crypt app")
                    totp = pyotp.TOTP(key)
                    qrcode.make(uri).save("qr.png")
                    my_imageqr = ImageTk.PhotoImage(Image.open('qr.png').resize((230,230)))
                    btnbackqr = customtkinter.CTkLabel(qrframe, image=my_imageqr , text="" ,)
                    btnbackqr.place(x=70 , y=140)
                    qrframe.place(relx=0.5 , rely=0.5 ,anchor =tkinter.CENTER )
                else :
                    CTkMessagebox(title="Info", message="Enter a valid email " )
        else :
            CTkMessagebox(title="Info", message="This email is already used in our database")


#This function reads from files the existing email and pass to verify and grant access
def log() :
    password = hashlib.sha256(log_pwd.get().encode()).hexdigest()
    if check_credentials(log_email.get(),password) :
            
            CTkMessagebox(title="Info", message="Access granted ") 
            login.place_forget()
            key = "alisouasecretkey"
            uri = pyotp.totp.TOTP(key).provisioning_uri(name="alisoua", issuer_name="crypt app")
            totp = pyotp.TOTP(key)
            qrcode.make(uri).save("qr.png")
            my_imageqr = ImageTk.PhotoImage(Image.open('qr.png').resize((220,220)))
            btnbackqr = customtkinter.CTkLabel(qrframe, image=my_imageqr , text="" ,)
            btnbackqr.place(x=65 , y=140)
            qrframe.place(relx=0.5 , rely=0.5 ,anchor =tkinter.CENTER )
    else : 
        CTkMessagebox(title="Info", message="Compte invalid !!")

def register2 () :
    if wel_email.get()=="" or wel_pwd.get()=="" or wel_pwd2.get()=="" :
        CTkMessagebox(title="Error", message="To register you need to fill the form")
    else:
        if check_email_existence (wel_email.get()) == False :
            if wel_pwd2.get() == wel_pwd.get() :    
                if isValid(wel_email.get()) and isValidpass(wel_pwd.get()):

                    password = hashlib.sha256(wel_pwd.get().encode()).hexdigest()
                    add_user(wel_email.get(),password)

                    CTkMessagebox(title="Info", message="valid registration") 
                    registerframe.place_forget()
                    key = "alisouasecretkey"
                    uri = pyotp.totp.TOTP(key).provisioning_uri(name="alisoua", issuer_name="crypt app")
                    totp = pyotp.TOTP(key)
                    qrcode.make(uri).save("qr.png")
                    my_imageqr = ImageTk.PhotoImage(Image.open('qr.png').resize((200,200)))
                    btnbackqr = customtkinter.CTkLabel(qrframe, image=my_imageqr , text="" ,)
                    btnbackqr.place(x=55 , y=100)
                    qrframe.place(relx=0.5 , rely=0.5 ,anchor =tkinter.CENTER )
                else :
                    CTkMessagebox(title="Info", message="Check the validity of both of your email and pass")
            else :
                CTkMessagebox(title="Info", message="Your password must match your confirmation")
        else :
            CTkMessagebox(title="Info", message="This email is already used in our database")

### All btns that Swap frames ##      
def gotoregister() :
    welcome.place_forget()
    registerframe.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER)
def gotologin() :
    welcome.place_forget()
    login.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER)  
def qrframetohome() :
    key = "alisouasecretkey"
    totp = pyotp.TOTP(key)
    if (totp.verify(qrframe_answer.get())) :
        qrframe.place_forget()
        home.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER)
    else :
        CTkMessagebox(title="Info", message="False Code .. Enter again !!")
def backwelcome() :
    login.place_forget()
    welcome.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER)
def backwelcome2() :
    registerframe.place_forget()
    welcome.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER)   

def backwelcome3() :
    caesarframe.place_forget()
    home.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER) 
def backwelcome4() :
    vigenereframe.place_forget()
    home.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER) 
def backwelcome5() :
    transpositionframe.place_forget()
    home.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER) 
def backwelcome6() :
    playfairframe.place_forget()
    home.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER) 
def backwelcome7() :
    affineframe.place_forget()
    home.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER) 


def btnfhere() :
    login.place_forget()
    registerframe.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER) 
def hometocaesar() :
    home.place_forget()
    caesarframe.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER) 
def hometovigenere() :
    home.place_forget()
    vigenereframe.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER) 
def hometotransposition() :
    home.place_forget()
    transpositionframe.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER) 
def hometoaffine() :
    home.place_forget()
    affineframe.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER)
def hometoplayfair() :
    home.place_forget()
    playfairframe.place(relx=0.5 , rely=0.5 , anchor=tkinter.CENTER) 



### First Frame to show up(welcome) ##
welcome = customtkinter.CTkFrame(master=button , width=280 ,height=330, corner_radius=16 ,)
log_label = customtkinter.CTkLabel(master=welcome , text="Welcome" , font=('century gothic', 36))
log_label.place(x=50 , y=50)
btnlogin = customtkinter.CTkButton(welcome , text="Login" , command=gotologin)
btnlogin.place(x=75 , y=200)
btnregister = customtkinter.CTkButton(welcome , text="Register" , command=gotoregister)
btnregister.place(x=75 , y=150)
welcome.place(relx=0.5,rely=0.5 , anchor=tkinter.CENTER)

######Login page###########
login = customtkinter.CTkFrame(master=button , width=280 ,height=330 , corner_radius=16 ,)
log_label = customtkinter.CTkLabel(master=login , text="Log into your account" , font=('century gothic', 20))
log_label.place(x=30 , y=50)
log_email = customtkinter.CTkEntry(master=login , width=220 , placeholder_text="Email")
log_email.place(x=30 , y=105)
log_pwd = customtkinter.CTkEntry(master=login , width=220 , placeholder_text="Password" ,show="*")
log_pwd.place(x=30 , y= 150)
log_label = customtkinter.CTkLabel(master=login , text="Forget Password" , font=('century gothic', 12))
log_label.place(x=150 , y=180)
btn_login = customtkinter.CTkButton(master=login , width=220 , text="Login" , corner_radius=8 , command=log)
btn_login.place(x=30 , y=210)
log_label = customtkinter.CTkLabel(master=login , text="Create Account Here" , font=('century gothic', 12))
log_label.place(x=70 , y=240)


#######register page#############
registerframe = customtkinter.CTkFrame(master=button , width=280 ,height=330 , corner_radius=16 ,)
wel_label = customtkinter.CTkLabel(master=registerframe , text="Register an account" , font=('century gothic', 20))
wel_label.place(x=40 , y=50)
wel_email = customtkinter.CTkEntry(master=registerframe , width=220 , placeholder_text="Email")
wel_email.place(x=30 , y=105)
wel_pwd = customtkinter.CTkEntry(master=registerframe, width=220 , placeholder_text="Password" ,show="*")
wel_pwd.place(x=30 , y= 150)
wel_pwd2 = customtkinter.CTkEntry(master=registerframe , width=220 , placeholder_text="Confirm Password",show="*")
wel_pwd2.place(x=30 , y= 195)
btn_login = customtkinter.CTkButton(master=registerframe , width=220 , text="Register" , corner_radius=8 ,command=register2)
btn_login.place(x=30 , y=240)
btn_login2 = customtkinter.CTkButton(master=registerframe , width=220 , text="Register (Using Pass Generator)" , corner_radius=8 ,command=registerrandompass)
btn_login2.place(x=30 , y=285)


######qr page###########
qrframe = customtkinter.CTkFrame(master=button , width=330 ,height=380 , corner_radius=16 ,)
qrframe_label = customtkinter.CTkLabel(master=qrframe , text="Scan this to get Access" , font=('century gothic', 20))
qrframe_label.place(x=50 , y=65)
qrframe_answer = customtkinter.CTkEntry(master=qrframe , width=220 , placeholder_text="Enter Qr Code",)
qrframe_answer.place(x=55 , y= 100)
btn_qrframe = customtkinter.CTkButton(master=qrframe , width=220 , text="Go to Home" , corner_radius=8 , command=qrframetohome)
btn_qrframe.place(x=60 , y=340)

###home
home = customtkinter.CTkFrame(master=button , width=280 ,height=330, corner_radius=16 ,)
btnfunctcesar2 = customtkinter.CTkButton(master=home,  text="   Caesar Cipher  ",  width=130 ,height=40 ,hover_color="#4158D0", command=hometocaesar)
btnfunctcesar2.place(x=70, y=30,)
btnfunctdataset3 = customtkinter.CTkButton(master=home,text="  Vigenere Cipher  ",  width=100 ,height=40 ,hover_color="#4158D0",command=hometovigenere)
btnfunctdataset3.place(x=70, y=90,)
btnfunctupdate4 = customtkinter.CTkButton(master=home, text="  Affine Cipher  ",  width=120 ,height=40 ,hover_color="#4158D0",command=hometoaffine)
btnfunctupdate4.place(x=70, y=150,)
btnfunctupdate4 = customtkinter.CTkButton(master=home, text="  Playfair Cipher  ",  width=120 ,height=40 ,hover_color="#4158D0",command=hometoplayfair)
btnfunctupdate4.place(x=70, y=210,)
btnfunctupdate4 = customtkinter.CTkButton(master=home, text="  Transposition Cipher  ",  width=120 ,height=40 ,hover_color="#4158D0",command=hometotransposition)
btnfunctupdate4.place(x=70, y=270,)

#caesarframe
caesarframe = customtkinter.CTkFrame(master=button , width=280 ,height=330, corner_radius=16 ,)
caesar_text = customtkinter.CTkEntry(master=caesarframe, width=220 , placeholder_text="Text to crypt/decrypt" )
caesar_text.place(x=30 , y= 50)
caesar_key = customtkinter.CTkEntry(master=caesarframe , width=220 , placeholder_text="key")
caesar_key.place(x=30 , y= 100)
caesar_c = customtkinter.CTkButton(master=caesarframe, text="  Cipher  ",  width=120 ,height=40 ,hover_color="#4158D0", command=caesar_cipher_call)
caesar_c.place(x=70, y=150,)
caesar_d = customtkinter.CTkButton(master=caesarframe, text="  Decipher  ",  width=120 ,height=40 ,hover_color="#4158D0", command=caesar_decipher_call)
caesar_d.place(x=70, y=200,)
caesar_b = customtkinter.CTkButton(master=caesarframe, text="  Brute Force  ",  width=120 ,height=40 ,hover_color="#4158D0", command=caesar_brute_call)
caesar_b.place(x=70, y=250,)

#vigenereframe
vigenereframe = customtkinter.CTkFrame(master=button , width=280 ,height=330, corner_radius=16 ,)
vigenere_text = customtkinter.CTkEntry(master=vigenereframe, width=220 , placeholder_text="Text to crypt/decrypt" )
vigenere_text.place(x=30 , y= 50)
vigenere_key = customtkinter.CTkEntry(master=vigenereframe , width=220 , placeholder_text="key")
vigenere_key.place(x=30 , y= 100)
vigenere_c = customtkinter.CTkButton(master=vigenereframe, text="  Cipher  ",  width=120 ,height=40 ,hover_color="#4158D0", command=vigenere_cipher_call)
vigenere_c.place(x=70, y=150,)
vigenere_d = customtkinter.CTkButton(master=vigenereframe, text="  Decipher  ",  width=120 ,height=40 ,hover_color="#4158D0", command=vigenere_decipher_call)
vigenere_d.place(x=70, y=200,)
vigenere_b = customtkinter.CTkButton(master=vigenereframe, text="  Brute Force  ",  width=120 ,height=40 ,hover_color="#4158D0", command=vigenere_brute_call)
vigenere_b.place(x=70, y=250,)

#transpositionframe
transpositionframe = customtkinter.CTkFrame(master=button , width=280 ,height=330, corner_radius=16 ,)
transposition_text = customtkinter.CTkEntry(master=transpositionframe, width=220 , placeholder_text="Text to crypt/decrypt" )
transposition_text.place(x=30 , y= 50)
transposition_key = customtkinter.CTkEntry(master=transpositionframe , width=220 , placeholder_text="key")
transposition_key.place(x=30 , y= 100)
transposition_c = customtkinter.CTkButton(master=transpositionframe, text="  Cipher  ",  width=120 ,height=40 ,hover_color="#4158D0", command=transposition_cipher_call)
transposition_c.place(x=70, y=150,)
transposition_d = customtkinter.CTkButton(master=transpositionframe, text="  Decipher  ",  width=120 ,height=40 ,hover_color="#4158D0", command=transposition_decipher_call)
transposition_d.place(x=70, y=200,)

#affineframe
affineframe = customtkinter.CTkFrame(master=button , width=280 ,height=330, corner_radius=16 ,)
affine_text = customtkinter.CTkEntry(master=affineframe, width=220 , placeholder_text="Text to crypt/decrypt" )
affine_text.place(x=30 , y= 50)
affine_key = customtkinter.CTkEntry(master=affineframe , width=220 , placeholder_text=" key a ")
affine_key.place(x=30 , y= 100)
affine_key2 = customtkinter.CTkEntry(master=affineframe , width=220 , placeholder_text=" key b ")
affine_key2.place(x=30 , y= 150)
affine_c = customtkinter.CTkButton(master=affineframe, text="  Cipher  ",  width=120 ,height=40 ,hover_color="#4158D0", command=affine_cipher_call)
affine_c.place(x=70, y=180,)
affine_d = customtkinter.CTkButton(master=affineframe, text="  Decipher  ",  width=120 ,height=40 ,hover_color="#4158D0", command=affine_decipher_call)
affine_d.place(x=70, y=225,)
affine_b = customtkinter.CTkButton(master=affineframe, text="  Brute Force  ",  width=120 ,height=40 ,hover_color="#4158D0", command=affine_brute_call)
affine_b.place(x=70, y=270,)

#playfairframe
playfairframe = customtkinter.CTkFrame(master=button , width=280 ,height=330, corner_radius=16 ,)
playfair_text = customtkinter.CTkEntry(master=playfairframe, width=220 , placeholder_text="Text to crypt/decrypt" )
playfair_text.place(x=30 , y= 50)
playfair_key = customtkinter.CTkEntry(master=playfairframe , width=220 , placeholder_text="key")
playfair_key.place(x=30 , y= 100)
playfair_c = customtkinter.CTkButton(master=playfairframe, text="  Cipher  ",  width=120 ,height=40 ,hover_color="#4158D0", command=playfair_cipher_call)
playfair_c.place(x=70, y=150,)
playfair_d = customtkinter.CTkButton(master=playfairframe, text="  Decipher  ",  width=120 ,height=40 ,hover_color="#4158D0", command=playfair_decipher_call)
playfair_d.place(x=70, y=200,)

my_image1 = ImageTk.PhotoImage(Image.open('backbtn2.png').resize((30,30)))
btnback1 = customtkinter.CTkButton(login, image=my_image1 , text="" ,width=40, fg_color="#2B2B2B" ,bg_color="#2B2B2B" ,hover_color="#2B2B2B" ,command=backwelcome)
btnback1.place(x=10 , y=10)
my_image2 = ImageTk.PhotoImage(Image.open('backbtn2.png').resize((30,30)))
btnback2 = customtkinter.CTkButton(registerframe, image=my_image2 , text="" ,width=40, fg_color="#2B2B2B" ,bg_color="#2B2B2B" ,hover_color="#2B2B2B" ,command=backwelcome2)
btnback2.place(x=10 , y=10)
my_image3 = ImageTk.PhotoImage(Image.open('backbtn2.png').resize((30,30)))
btnback3 = customtkinter.CTkButton(caesarframe, image=my_image3 , text="" ,width=40, fg_color="#2B2B2B" ,bg_color="#2B2B2B" ,hover_color="#2B2B2B" ,command=backwelcome3)
btnback3.place(x=10 , y=10)
my_image4 = ImageTk.PhotoImage(Image.open('backbtn2.png').resize((30,30)))
btnback4 = customtkinter.CTkButton(vigenereframe, image=my_image4 , text="" ,width=40, fg_color="#2B2B2B" ,bg_color="#2B2B2B" ,hover_color="#2B2B2B" ,command=backwelcome4)
btnback4.place(x=10 , y=10)
my_image5 = ImageTk.PhotoImage(Image.open('backbtn2.png').resize((30,30)))
btnback5 = customtkinter.CTkButton(transpositionframe, image=my_image5 , text="" ,width=40, fg_color="#2B2B2B" ,bg_color="#2B2B2B" ,hover_color="#2B2B2B" ,command=backwelcome5)
btnback5.place(x=10 , y=10)
my_image6 = ImageTk.PhotoImage(Image.open('backbtn2.png').resize((30,30)))
btnback6 = customtkinter.CTkButton(playfairframe, image=my_image6 , text="" ,width=40, fg_color="#2B2B2B" ,bg_color="#2B2B2B" ,hover_color="#2B2B2B" ,command=backwelcome6)
btnback6.place(x=10 , y=10)
my_image7 = ImageTk.PhotoImage(Image.open('backbtn2.png').resize((30,30)))
btnback7 = customtkinter.CTkButton(affineframe, image=my_image7 , text="" ,width=40, fg_color="#2B2B2B" ,bg_color="#2B2B2B" ,hover_color="#2B2B2B" ,command=backwelcome7)
btnback7.place(x=10 , y=10)

btnhere = customtkinter.CTkButton(login , text="Here" , text_color="blue" , font=('century gothic', 13) , width=10, fg_color="#2B2B2B" ,bg_color="#2B2B2B" ,hover_color="#2B2B2B" ,command=btnfhere)
btnhere.place(x=166 , y=240)

app.mainloop()
