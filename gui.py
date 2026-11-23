"""Optional Tkinter front-end."""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from secure_db import SecureDB, AuthError, FIELDS


class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.title("AES Secure Database"); self.geometry("820x460")
        self.db = SecureDB("secure.db")
        pw = simpledialog.askstring("Login" if self.db.is_initialized() else "Create master password",
                                    "Master password:", show="*")
        try:
            self.db.login(pw or "") if self.db.is_initialized() else self.db.setup(pw or "")
        except AuthError as e:
            messagebox.showerror("Error", str(e)); self.destroy(); return
        self.entries = {}
        form = ttk.Frame(self); form.pack(fill="x", padx=8, pady=8)
        for i, f in enumerate(FIELDS):
            ttk.Label(form, text=f).grid(row=0, column=i)
            self.entries[f] = ttk.Entry(form, width=15); self.entries[f].grid(row=1, column=i, padx=2)
        bar = ttk.Frame(self); bar.pack(fill="x", padx=8)
        for t, cmd in (("Add", self.add), ("Update", self.upd), ("Delete", self.rem),
                       ("Search", self.find), ("Show all", self.refresh)):
            ttk.Button(bar, text=t, command=cmd).pack(side="left", padx=2)
        self.q = ttk.Entry(bar, width=20); self.q.pack(side="left", padx=6)
        self.tree = ttk.Treeview(self, columns=("id", *FIELDS), show="headings")
        for c in ("id", *FIELDS): self.tree.heading(c, text=c); self.tree.column(c, width=60 if c == "id" else 130)
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)
        self.tree.bind("<<TreeviewSelect>>", self.pick); self.refresh()

    def data(self): return {f: e.get() for f, e in self.entries.items()}
    def sel(self):
        s = self.tree.selection(); return int(self.tree.item(s[0])["values"][0]) if s else None
    def show(self, rows):
        self.tree.delete(*self.tree.get_children())
        for r in rows: self.tree.insert("", "end", values=(r["id"], *[r[f] for f in FIELDS]))
    def refresh(self): self.show(self.db.list_all())
    def find(self): self.show(self.db.search(self.q.get()))
    def add(self): self.db.insert(self.data()); self.refresh()
    def upd(self):
        if self.sel(): self.db.update(self.sel(), self.data()); self.refresh()
    def rem(self):
        if self.sel() and messagebox.askyesno("Delete", "Delete record?"): self.db.delete(self.sel()); self.refresh()
    def pick(self, _):
        s = self.tree.selection()
        if s:
            for e, v in zip(self.entries.values(), self.tree.item(s[0])["values"][1:]):
                e.delete(0, "end"); e.insert(0, v)


if __name__ == "__main__":
    App().mainloop()
