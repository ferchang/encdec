import configparser
from ask_file_overwrite import AskFileOverwrite
from tkinter import *
import os
from tkinter import simpledialog
from tkinter.filedialog import askopenfilename
from crypto import *
import tkinter.messagebox
import sys

EXT128='.aes128'
EXT256='.aes256'

class Application(Frame):
	
	def createWidgets(self):
		
		container=Frame(self)
		
		#-------------------------
	
		btn=Button(container, text='Password')
		btn["command"]=lambda: self.getPassword()
		btn.pack(side=TOP, padx=5, pady=5, fill=BOTH)
		
		w=OptionMenu(container, self.algo, 'AES-128', 'AES-256')
		w.pack(side=TOP, padx=5, pady=5, fill=BOTH)
		
		btn=Button(container, text='Encrypt')
		btn["command"]=lambda command='encrypt': self.btnClick(command)
		btn.pack(side=TOP, padx=5, pady=5, fill=BOTH)
		
		btn=Button(container, text='Decrypt')
		btn["command"]=lambda command='decrypt': self.btnClick(command)
		btn.pack(side=TOP, padx=5, pady=5, fill=BOTH)
		
		btn=Button(container, text='About')
		btn["command"]=lambda: self.about()
		btn.pack(side=TOP, padx=5, pady=5, fill=BOTH)
		
		container.pack()
		
#-------------------------------------------

	def about(self):
		msg='Program by: hmz2627 -=At=- gmail -=Dot=- com'
		msg+='\n\nEncryption algorithm: PBKDF2 + AES(CBC) + HMAC-SHA256'
		tkinter.messagebox.showinfo('About', msg)

#-------------------------------------------

	def getPassword(self):
		password=simpledialog.askstring('Password', 'Enter password:')
		if not password: return False
		self.password=password
		return True
		
#-------------------------------------------

	def getExtension(self):
		if self.algo.get()=='AES-128': return EXT128
		else: return EXT256

#-------------------------------------------

	def writeConfigs(self):
		self.config.set('general', 'default_algo', self.algo.get())
		file=open(sys.path[0]+'/config.ini', 'w', encoding='utf-8')
		self.config.write(file)
		file.close()

#-------------------------------------------

	def btnClick(self, command):
		if not self.password and not self.getPassword(): return
		filename=askopenfilename(initialdir=self.lastFileOpenDir)
		if not filename: return
		self.lastFileOpenDir=os.path.dirname(filename)
		with open(filename, mode='rb') as f: data=f.read()
		os.chdir(os.path.dirname(filename))
		self.writeConfigs()
		if command=='encrypt':
			ciphertext=encrypt(data, self.password, self.algo.get())
			filename=os.path.basename(filename.encode()).decode()
			filename=filename+self.getExtension()
			if os.path.exists(filename): 
				filename=AskFileOverwrite(self, filename).getResult()
			if filename:
				with open(filename, mode='wb') as f: f.write(ciphertext)
			else: print('abort')
		else:
			plaintext, err_msg=decrypt(data, self.password)
			if plaintext==None:
				tkinter.messagebox.showerror('Decryption error!', err_msg)
				return
			if filename.endswith(self.getExtension()): filename=filename[:-len(self.getExtension())]
			filename=os.path.basename(filename.encode()).decode()
			if os.path.exists(filename): 
				filename=AskFileOverwrite(self, filename).getResult()
			if filename:
				with open(filename, mode='wb') as f: f.write(plaintext)
			else: print('abort')

#-------------------------------------------
			
	def __init__(self, master=None):
		
		self.password=''
		self.lastFileOpenDir=''
		
		self.config=configparser.RawConfigParser()
		self.config.read(sys.path[0]+'/config.ini', encoding='utf-8')
		
		self.algo=StringVar()
		self.algo.set(self.config.get('general', 'default_algo'))
	
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
