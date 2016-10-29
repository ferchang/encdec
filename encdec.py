from tkinter import *
import os
from tkinter import simpledialog
from tkinter.filedialog import askopenfilename
from crypto import *
import tkinter.messagebox

class Application(Frame):
	
	def createWidgets(self):
		
		container=Frame(self)
		
		btn=Button(container, text='Encrypt')
		btn["command"]=lambda command='encrypt': self.btnClick(command)
		btn.pack(side=LEFT, padx=5, pady=5)
		
		btn=Button(container, text='Decrypt')
		btn["command"]=lambda command='decrypt': self.btnClick(command)
		btn.pack(side=LEFT, padx=5, pady=5)
		
		container.pack()
		
#-------------------------------------------

	def btnClick(self, command):
		if not self.password:
			password=simpledialog.askstring('Password', 'Enter password:')
			if password==None or not password: return
			else: self.password=password
		filename=askopenfilename(initialdir=self.lastFileOpenDir)
		if not filename: return
		self.lastFileOpenDir=os.path.dirname(filename)
		with open(filename, mode='rb') as f: data=f.read()
		if command=='encrypt':
			if filename.endswith('.encrypted'):
				tkinter.messagebox.showerror('Error', 'File already encrypted!')
				return
			ciphertext=encrypt(data, self.password)
			with open(filename+'.encrypted', mode='wb') as f: f.write(ciphertext)
		else:
			plaintext=decrypt(data, self.password)
			if plaintext==None:
				tkinter.messagebox.showerror('Error', 'Decryption error!')
				return
			if filename.endswith('.encrypted'): filename=filename[:-10]
			with open(filename, mode='wb') as f: f.write(plaintext)

#-------------------------------------------
			
	def __init__(self, master=None):
		
		self.password=''
		self.lastFileOpenDir=''
	
		Frame.__init__(self, master)
		self.createWidgets()
		self.pack()

#-------------------------------------------

try:
	root=Tk()
	root.title('Encrypt/Decrypt')
	app=Application(master=root)
	app.mainloop()
except KeyboardInterrupt: print('<*******************KeyboardInterrupt*******************>')
