#!/usr/bin/env python3
import os, sys
try:
    import tkinter as tk
    from tkinter import ttk, filedialog
except:
    print("Install tk: sudo pacman -S tk")
    sys.exit(1)
import cv2
from PIL import Image, ImageTk
from pathlib import Path

class ImageViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Viewer")
        self.root.geometry("1000x600")
        self.images = []
        self.idx = 0
        
        ttk.Button(root, text="Select Folder", command=self.load_folder).pack(pady=10)
        self.listbox = tk.Listbox(root, width=30)
        self.listbox.pack(side=tk.LEFT, fill=tk.Y)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)
        
        self.canvas = tk.Canvas(root, bg="gray")
        self.canvas.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        ttk.Button(root, text="◀", command=self.prev).place(x=450, y=550)
        ttk.Button(root, text="▶", command=self.next).place(x=500, y=550)
    
    def load_folder(self):
        folder = filedialog.askdirectory()
        if not folder: return
        exts = ['*.jpg', '*.jpeg', '*.png', '*.gif', '*.bmp', '*.JPG', '*.JPEG', '*.PNG']
        self.images = []
        for ext in exts:
            self.images.extend(Path(folder).glob(ext))
        self.images = sorted(self.images)
        self.listbox.delete(0, tk.END)
        for img in self.images:
            self.listbox.insert(tk.END, img.name)
        if self.images:
            self.listbox.selection_set(0)
            self.show_image(0)
    
    def on_select(self, e):
        sel = self.listbox.curselection()
        if sel:
            self.show_image(sel[0])
    
    def show_image(self, idx):
        if not self.images or idx < 0 or idx >= len(self.images): return
        self.idx = idx
        try:
            img = cv2.imread(str(self.images[idx]))
            if img is None:
                return
            img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            h, w = img.shape[:2]
            cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
            if cw < 10: cw, ch = 800, 500
            scale = min((cw-20)/w, (ch-20)/h, 1)
            img = cv2.resize(img, (int(w*scale), int(h*scale)))
            photo = ImageTk.PhotoImage(Image.fromarray(img))
            self.canvas.delete("all")
            self.canvas.create_image(cw//2, ch//2, image=photo, anchor=tk.CENTER)
            self.canvas.image = photo
        except Exception as e:
            print(f"Error: {e}")
    
    def prev(self):
        if self.images and self.idx > 0:
            self.show_image(self.idx - 1)
            self.listbox.selection_clear(0, tk.END)
            self.listbox.selection_set(self.idx)
    
    def next(self):
        if self.images and self.idx < len(self.images) - 1:
            self.show_image(self.idx + 1)
            self.listbox.selection_clear(0, tk.END)
            self.listbox.selection_set(self.idx)

if __name__ == "__main__":
    root = tk.Tk()
    ImageViewer(root)
    root.mainloop()
