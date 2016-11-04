from tkinter import *
import os

class AskFileOverwrite(Toplevel):

	def __init__(self, parent, filename):
		self.filename=filename
		self.var = StringVar()
		Toplevel.__init__(self, parent)
		self.transient(parent)
		self.title('Warning')
		self.parent = parent
		self.result = None
		body = Frame(self)
		self.initial_focus = self.body(body)
		body.pack(padx=5, pady=5)
		self.buttonbox()
		self.grab_set()
		if not self.initial_focus:
			self.initial_focus = self
		self.protocol("WM_DELETE_WINDOW", self.cancel)
		self.geometry("+%d+%d" % (parent.winfo_rootx()+50,
								  parent.winfo_rooty()+50))
		self.initial_focus.focus_set()
		self.wait_window(self)
		
	def getResult(self): return self.var.get()

	def body(self, master):
		frm=Frame(master)
		frm.pack()
		Label(frm, text='File already exists!\nEnter new filename:').pack({"side": "top", 'padx': 1, 'pady': 1})
		self.txt=Entry(frm)
		self.txt.insert(0, self.filename)
		self.txt.pack()
		self.txt.focus_set()
		return frm

	def buttonbox(self):
		box = Frame(self)
		w = Button(box, text="Save", width=10, command=self.save, default=ACTIVE)
		w.pack(side=LEFT, padx=5, pady=5)
		self.bind("<Return>", self.save)
		self.bind("<Escape>", self.cancel)
		#-----------------
		w = Button(box, text="Cancel", width=10, command=self.cancel)
		w.pack(side=LEFT, padx=5, pady=5)
		#-----------------
		box.pack()

	def save(self, event=None):
		self.var.set(self.txt.get())
		self.withdraw()
		self.update_idletasks()
		self.cancel()

	def cancel(self, event=None):
		self.parent.focus_set()
		self.destroy()
		