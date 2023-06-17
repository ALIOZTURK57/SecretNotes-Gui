
#SecretNotes gui

from tkinter import *
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()
def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
def button1_clicked():
    title=my_entry.get()
    message=my_text.get("1.0",END) #baştan sonda kadar mesajları alıyor
    master_secret=my_entry2.get()

    message_encrypted = encode(master_secret, message)
    if len(title)==0 or len(message)==0:

        new_window=Tk()
        new_window.title("warning message")
        new_window.minsize(width=150,height=150)
        new_label=Label(master=new_window,text="Please enter all information!!!!").pack()
    else:
        message_encrypted = encode(master_secret, message)
        try:
            with open("mysecret.txt","a") as data_file:
                data_file.write( "\n {}\n{}".format(title,message_encrypted))
        except FileNotFoundError:
            with open("mysecret.txt","w") as data_file:    #burda w komutu yazıyla yazsın yoksa sonra zazten yazdıkltan sonra bulacağı için a komutun dönecek
                data_file.write( "\n {}\n{}".format(title,message_encrypted))

        finally:
            my_entry.delete(0,END)
            my_entry2.delete(0,END)
            my_text.delete('1.0',END)

#decrypt notes
def decrypt_notes():
    message_encrypted=my_text.get("1.0",END)
    master_secret= my_entry2.get()
    if len(message_encrypted)==0 or len(master_secret)==0:
        new_window = Tk()
        new_window.title("warning message")
        new_window.minsize(width=150, height=150)
        new_label = Label(master=new_window, text="Please enter all information!!!!")


    else:

        try:
            decrypted_message=decode(master_secret,message_encrypted)
            my_entry2.delete("1.0",END)
            my_entry2.insert("1.0",decrypted_message)
        except:
            new_window = Tk()
            new_window.title("warning message")
            new_window.minsize(width=150, height=150)
            new_label = Label(master=new_window, text="Please make sure of encrypted info!!!!").pack()

window=Tk()
window.title("Secret Notes")
window.minsize(width=400,height=400)
window.config(padx=20,pady=20)

foto=PhotoImage(file="924946.png")


canvas=Canvas(height=200,width=200)   #foto için kodlar
canvas.create_image(100,100,image=foto)
canvas.pack()



my_label=Label(text="Secret Notes",font=("Arial",10,"bold"))
my_label.config(bg="black")
my_label.config(fg="white")
my_label.config(padx=20,pady=20)
my_label.pack()

title_label=Label(text="Enter your title",font=("Arial",10))

title_label.pack()

my_entry=Entry(width=20)
my_entry.pack()
title_label2=Label(text="Enter your title",font=("Arial",10))

title_label2.pack()

my_text=Text(width=15,height=10)
my_text.pack()
title_label3=Label(text="Enter master key",font=("Arial",10))
title_label3.pack()

my_entry2=Entry(width=20)
my_entry2.pack()

my_button1=Button(text="save & encrypt",command=button1_clicked)
my_button1.pack()

my_button2=Button(text="decrypt",command=decrypt_notes)
my_button2.pack()

window.mainloop()

