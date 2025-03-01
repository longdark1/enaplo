import json
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

# Adatmodell osztályok
class Diak:
    def __init__(self, nev, diak_id):
        self.nev = nev
        self.diak_id = diak_id
        
    def to_dict(self):
        return {'nev': self.nev, 'diak_id': self.diak_id}

class Tantargy:
    def __init__(self, nev, tantargy_kod):
        self.nev = nev
        self.tantargy_kod = tantargy_kod
        
    def to_dict(self):
        return {'nev': self.nev, 'tantargy_kod': self.tantargy_kod}

class Jegy:
    def __init__(self, diak_id, tantargy_kod, jegy, datum):
        self.diak_id = diak_id
        self.tantargy_kod = tantargy_kod
        self.jegy = jegy
        self.datum = datum
        
    def to_dict(self):
        return {
            'diak_id': self.diak_id,
            'tantargy_kod': self.tantargy_kod,
            'jegy': self.jegy,
            'datum': self.datum.strftime("%Y-%m-%d")
        }

# Új osztály a hiányzások kezelésére
class Hianyzas:
    def __init__(self, diak_id, datum, tantargy_kod=None, igazolt=False):
        self.diak_id = diak_id
        self.datum = datum
        self.tantargy_kod = tantargy_kod  # None, ha egész napos hiányzás
        self.igazolt = igazolt
        
    def to_dict(self):
        return {
            'diak_id': self.diak_id,
            'datum': self.datum.strftime("%Y-%m-%d"),
            'tantargy_kod': self.tantargy_kod,
            'igazolt': self.igazolt
        }

class User:
    def __init__(self, username, password_hash, role):
        self.username = username
        self.password_hash = password_hash
        self.role = role
        
    def to_dict(self):
        return {
            'username': self.username,
            'password_hash': self.password_hash,
            'role': self.role
        }

class Osztalynaplo:
    def __init__(self):
        self.diakok = []
        self.tantargyak = []
        self.jegyek = []
        self.users = []
        self.hianyzasok = []  # Új lista a hiányzások tárolására
        self.current_user = None
        
        self.load_data()
        
    def save_data(self):
        data = {
            'diakok': [d.to_dict() for d in self.diakok],
            'tantargyak': [t.to_dict() for t in self.tantargyak],
            'jegyek': [j.to_dict() for j in self.jegyek],
            'users': [u.to_dict() for u in self.users],
            'hianyzasok': [h.to_dict() for h in self.hianyzasok]  # Hiányzások mentése
        }
        
        with open('naplo_data.json', 'w') as f:
            json.dump(data, f)
            
    def load_data(self):
        try:
            with open('naplo_data.json', 'r') as f:
                data = json.load(f)
                
            self.diakok = [Diak(d['nev'], d['diak_id']) for d in data['diakok']]
            self.tantargyak = [Tantargy(t['nev'], t['tantargy_kod']) for t in data['tantargyak']]
            self.jegyek = [Jegy(j['diak_id'], j['tantargy_kod'], j['jegy'], 
                          datetime.strptime(j['datum'], "%Y-%m-%d")) for j in data.get('jegyek', [])]
            self.users = [User(u['username'], u['password_hash'], u['role']) for u in data.get('users', [])]
            
            # Hiányzások betöltése
            if 'hianyzasok' in data:
                self.hianyzasok = [
                    Hianyzas(
                        h['diak_id'], 
                        datetime.strptime(h['datum'], "%Y-%m-%d"),
                        h.get('tantargy_kod'),  # Lehet None
                        h.get('igazolt', False)
                    ) for h in data['hianyzasok']
                ]
        except FileNotFoundError:
            pass
            
    def register_user(self, username, password, role):
        if any(u.username == username for u in self.users):
            return False
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.users.append(User(username, password_hash, role))
        self.save_data()
        return True
    
    def login(self, username, password):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        user = next((u for u in self.users if u.username == username and u.password_hash == password_hash), None)
        if user:
            self.current_user = user
            return True
        return False
    
    def atlag_szamitas(self, diak_id=None, tantargy_kod=None):
        if diak_id and tantargy_kod:
            jegyek = [j.jegy for j in self.jegyek 
                      if j.diak_id == diak_id 
                      and j.tantargy_kod == tantargy_kod]
        elif diak_id:
            jegyek = [j.jegy for j in self.jegyek if j.diak_id == diak_id]
        elif tantargy_kod:
            jegyek = [j.jegy for j in self.jegyek if j.tantargy_kod == tantargy_kod]
        else:
            jegyek = [j.jegy for j in self.jegyek]
            
        return sum(jegyek)/len(jegyek) if jegyek else 0
    
    def hianyzo_jegyek(self):
        hianyzasok = []
        for diak in self.diakok:
            for tantargy in self.tantargyak:
                jegyek = [j for j in self.jegyek if j.diak_id == diak.diak_id 
                         and j.tantargy_kod == tantargy.tantargy_kod]
                if len(jegyek) < 3:
                    hianyzasok.append((diak, tantargy, len(jegyek)))
        return hianyzasok
    
    def diak_hozzaad(self, nev, diak_id):
        if not any(d.diak_id == diak_id for d in self.diakok):
            self.diakok.append(Diak(nev, diak_id))
            self.save_data()
            return True
        return False
    
    def tantargy_hozzaad(self, nev, kod):
        if not any(t.tantargy_kod == kod for t in self.tantargyak):
            self.tantargyak.append(Tantargy(nev, kod))
            self.save_data()
            return True
        return False
    
    def jegy_hozzaad(self, diak_id, tantargy_kod, jegy):
        if 1 <= jegy <= 5:
            self.jegyek.append(Jegy(diak_id, tantargy_kod, jegy, datetime.now()))
            self.save_data()
            return True
        return False
    
    # Új metódusok a hiányzások kezeléséhez
    def hianyzas_hozzaad(self, diak_id, datum, tantargy_kod=None, igazolt=False):
        # Ellenőrizzük, hogy létezik-e már ugyanilyen hiányzás
        for h in self.hianyzasok:
            if (h.diak_id == diak_id and h.datum.date() == datum.date() and 
                h.tantargy_kod == tantargy_kod):
                return False
                
        self.hianyzasok.append(Hianyzas(diak_id, datum, tantargy_kod, igazolt))
        self.save_data()
        return True
    
    def hianyzas_igazolas(self, hianyzas_index, igazolt=True):
        if 0 <= hianyzas_index < len(self.hianyzasok):
            self.hianyzasok[hianyzas_index].igazolt = igazolt
            self.save_data()
            return True
        return False
    
    def diak_hianyzasai(self, diak_id):
        return [h for h in self.hianyzasok if h.diak_id == diak_id]
    
    def osszes_hianyzas(self):
        return self.hianyzasok
    
    def igazolatlan_hianyzasok(self):
        return [h for h in self.hianyzasok if not h.igazolt]
    
    def hianyzasi_statisztika(self):
        # Diákonként összesített hiányzások
        stat = {}
        for diak in self.diakok:
            osszes = len([h for h in self.hianyzasok if h.diak_id == diak.diak_id])
            igazolt = len([h for h in self.hianyzasok if h.diak_id == diak.diak_id and h.igazolt])
            igazolatlan = osszes - igazolt
            stat[diak.diak_id] = {
                'nev': diak.nev,
                'osszes': osszes,
                'igazolt': igazolt,
                'igazolatlan': igazolatlan
            }
        return stat

class Application(tk.Tk):
    def __init__(self, naplo):
        super().__init__()
        self.naplo = naplo
        self.title("📚 Elektronikus Osztálynapló")
        self.geometry("1000x700")
        self.configure(bg="#F0F2F5")
        
        self.login_window()
        
    def login_window(self):
        self.clear_window()
        
        tk.Label(self, text="Felhasználónév:").pack(pady=5)
        self.username_entry = tk.Entry(self)
        self.username_entry.pack(pady=5)
        
        tk.Label(self, text="Jelszó:").pack(pady=5)
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack(pady=5)
        
        tk.Button(self, text="Bejelentkezés", command=self.handle_login).pack(pady=20)
        
    def handle_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if self.naplo.login(username, password):
            if self.naplo.current_user.role == "admin":
                self.admin_main_menu()
            else:
                self.teacher_main_menu()
        else:
            messagebox.showerror("Hiba", "Érvénytelen bejelentkezési adatok!")
    
    def admin_main_menu(self):
        self.clear_window()
        
        menu_frame = tk.Frame(self)
        menu_frame.pack(pady=20)
        
        menu_items = [
            ("Diákok kezelése", self.manage_students),
            ("Tantárgyak kezelése", self.manage_subjects),
            ("Felhasználók kezelése", self.manage_users),
            ("Hiányzások kezelése", self.manage_absences),  # Új menüpont
            ("Hiányzási statisztikák", self.absence_statistics),  # Új menüpont
            ("Statisztikák", self.show_statistics),
            ("Kijelentkezés", self.login_window)
        ]
        
        for text, command in menu_items:
            tk.Button(menu_frame, text=text, command=command, width=20).pack(pady=5)
            
    def teacher_main_menu(self):
        self.clear_window()
        
        menu_frame = tk.Frame(self)
        menu_frame.pack(pady=20)
        
        menu_items = [
            ("Jegyek rögzítése", self.record_grades),
            ("Hiányzások rögzítése", self.record_absences),  # Új menüpont
            ("Hiányzások igazolása", self.justify_absences),  # Új menüpont
            ("Hiányzó jegyek", self.show_missing_grades),
            ("Hiányzási statisztikák", self.absence_statistics),  # Új menüpont
            ("Statisztikák", self.show_statistics),
            ("Kijelentkezés", self.login_window)
        ]
        
        for text, command in menu_items:
            tk.Button(menu_frame, text=text, command=command, width=20).pack(pady=5)
    
    def manage_students(self):
        self.clear_window()
        
        tree_frame = tk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tree = ttk.Treeview(tree_frame, columns=("ID", "Név"), show="headings")
        tree.heading("ID", text="Diák ID")
        tree.heading("Név", text="Név")
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscroll=scrollbar.set)
        
        for diak in self.naplo.diakok:
            tree.insert("", "end", values=(diak.diak_id, diak.nev))
            
        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Új diák", command=self.add_student).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Vissza", command=self.admin_main_menu).pack(side=tk.LEFT, padx=5)
        
    def add_student(self):
        dialog = tk.Toplevel(self)
        dialog.title("Új diák hozzáadása")
        
        tk.Label(dialog, text="Név:").grid(row=0, column=0, padx=5, pady=5)
        name_entry = tk.Entry(dialog)
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(dialog, text="Diák ID:").grid(row=1, column=0, padx=5, pady=5)
        id_entry = tk.Entry(dialog)
        id_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def save():
            if self.naplo.diak_hozzaad(name_entry.get(), id_entry.get()):
                dialog.destroy()
                self.manage_students()
            else:
                messagebox.showerror("Hiba", "Érvénytelen adatok vagy már létező ID!")
        
        tk.Button(dialog, text="Mentés", command=save).grid(row=2, columnspan=2, pady=10)
    
    def manage_subjects(self):
        self.clear_window()
        
        tree_frame = tk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tree = ttk.Treeview(tree_frame, columns=("Kód", "Név"), show="headings")
        tree.heading("Kód", text="Tantárgy kód")
        tree.heading("Név", text="Tantárgy neve")
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscroll=scrollbar.set)
        
        for tantargy in self.naplo.tantargyak:
            tree.insert("", "end", values=(tantargy.tantargy_kod, tantargy.nev))
            
        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Új tantárgy", command=self.add_subject).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Vissza", command=self.admin_main_menu).pack(side=tk.LEFT, padx=5)
        
    def add_subject(self):
        dialog = tk.Toplevel(self)
        dialog.title("Új tantárgy hozzáadása")
        
        tk.Label(dialog, text="Név:").grid(row=0, column=0, padx=5, pady=5)
        name_entry = tk.Entry(dialog)
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(dialog, text="Tantárgy kód:").grid(row=1, column=0, padx=5, pady=5)
        code_entry = tk.Entry(dialog)
        code_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def save():
            if self.naplo.tantargy_hozzaad(name_entry.get(), code_entry.get()):
                dialog.destroy()
                self.manage_subjects()
            else:
                messagebox.showerror("Hiba", "Érvénytelen adatok vagy már létező kód!")
        
        tk.Button(dialog, text="Mentés", command=save).grid(row=2, columnspan=2, pady=10)
    
    def manage_users(self):
        self.clear_window()
        
        tree_frame = tk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tree = ttk.Treeview(tree_frame, columns=("Felhasználónév", "Szerepkör"), show="headings")
        tree.heading("Felhasználónév", text="Felhasználónév")
        tree.heading("Szerepkör", text="Szerepkör")
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscroll=scrollbar.set)
        
        for user in self.naplo.users:
            tree.insert("", "end", values=(user.username, user.role))
            
        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Új felhasználó", command=self.add_user).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Vissza", command=self.admin_main_menu).pack(side=tk.LEFT, padx=5)
        
    def add_user(self):
        dialog = tk.Toplevel(self)
        dialog.title("Új felhasználó hozzáadása")
        
        tk.Label(dialog, text="Felhasználónév:").grid(row=0, column=0, padx=5, pady=5)
        username_entry = tk.Entry(dialog)
        username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(dialog, text="Jelszó:").grid(row=1, column=0, padx=5, pady=5)
        password_entry = tk.Entry(dialog, show="*")
        password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(dialog, text="Szerepkör:").grid(row=2, column=0, padx=5, pady=5)
        role_var = tk.StringVar(value="tanar")
        tk.OptionMenu(dialog, role_var, "admin", "tanar").grid(row=2, column=1, padx=5, pady=5)
        
        def save():
            if self.naplo.register_user(username_entry.get(), password_entry.get(), role_var.get()):
                dialog.destroy()
                self.manage_users()
            else:
                messagebox.showerror("Hiba", "Érvénytelen adatok vagy már létező felhasználónév!")
        
        tk.Button(dialog, text="Mentés", command=save).grid(row=3, columnspan=2, pady=10)
    
    def show_statistics(self):
        self.clear_window()
        
        stats_frame = tk.Frame(self)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Diákok átlagai
        tk.Label(stats_frame, text="Diákok átlagai:", font=('Arial', 12, 'bold')).pack(pady=5)
        for diak in self.naplo.diakok:
            avg = self.naplo.atlag_szamitas(diak_id=diak.diak_id)
            tk.Label(stats_frame, text=f"{diak.nev}: {avg:.2f}").pack()
        
        # Tantárgyak átlagai
        tk.Label(stats_frame, text="\nTantárgyak átlagai:", font=('Arial', 12, 'bold')).pack(pady=5)
        for tantargy in self.naplo.tantargyak:
            avg = self.naplo.atlag_szamitas(tantargy_kod=tantargy.tantargy_kod)
            tk.Label(stats_frame, text=f"{tantargy.nev}: {avg:.2f}").pack()
            
        # Vissza gomb
        tk.Button(stats_frame, text="Vissza", command=lambda: 
                 self.admin_main_menu() if self.naplo.current_user.role == "admin" 
                 else self.teacher_main_menu()).pack(pady=10)
    
    def show_missing_grades(self):
        self.clear_window()
        
        hianyok = self.naplo.hianyzo_jegyek()
        if not hianyok:
            tk.Label(self, text="Nincsenek hiányzó jegyek!").pack(pady=20)
            tk.Button(self, text="Vissza", command=self.teacher_main_menu).pack()
            return
        
        scroll_frame = tk.Frame(self)
        scroll_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        canvas = tk.Canvas(scroll_frame)
        scrollbar = tk.Scrollbar(scroll_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        tk.Label(scrollable_frame, text="Hiányzó jegyek:", font=('Arial', 12, 'bold')).pack(pady=5)
        for diak, tantargy, db in hianyok:
            tk.Label(scrollable_frame, 
                   text=f"{diak.nev} - {tantargy.nev}: {db} jegy").pack(anchor='w')
                   
        tk.Button(scrollable_frame, text="Vissza", command=self.teacher_main_menu).pack(pady=10)
    
    def record_grades(self):
        self.clear_window()
        
        main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Diák választó
        tk.Label(main_frame, text="Válassz diákot:").pack()
        diak_var = tk.StringVar()
        diak_combobox = ttk.Combobox(main_frame, textvariable=diak_var)
        diak_combobox['values'] = [f"{d.diak_id} - {d.nev}" for d in self.naplo.diakok]
        diak_combobox.pack(pady=5)
        
        # Tantárgy választó
        tk.Label(main_frame, text="Válassz tantárgyat:").pack()
        tantargy_var = tk.StringVar()
        tantargy_combobox = ttk.Combobox(main_frame, textvariable=tantargy_var)
        tantargy_combobox['values'] = [f"{t.tantargy_kod} - {t.nev}" for t in self.naplo.tantargyak]
        tantargy_combobox.pack(pady=5)
        
        # Jegy bevitel
        tk.Label(main_frame, text="Jegy (1-5):").pack()
        jegy_entry = tk.Entry(main_frame)
        jegy_entry.pack(pady=5)
        
        def save_grade():
            try:
                diak_id = diak_combobox.get().split(" - ")[0]
                tantargy_kod = tantargy_combobox.get().split(" - ")[0]
                jegy = int(jegy_entry.get())
                
                if self.naplo.jegy_hozzaad(diak_id, tantargy_kod, jegy):
                    messagebox.showinfo("Siker", "Jegy sikeresen rögzítve!")
                else:
                    messagebox.showerror("Hiba", "Érvénytelen jegyérték!")
            except (ValueError, IndexError):
                messagebox.showerror("Hiba", "Érvénytelen beviteli adatok!")
        
        tk.Button(main_frame, text="Mentés", command=save_grade).pack(pady=10)
        tk.Button(main_frame, text="Vissza", command=self.teacher_main_menu).pack()
    
    # Új metódusok a hiányzások kezeléséhez
    def record_absences(self):
        self.clear_window()
        
        main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Diák választó
        tk.Label(main_frame, text="Válassz diákot:").pack()
        diak_var = tk.StringVar()
        diak_combobox = ttk.Combobox(main_frame, textvariable=diak_var)
        diak_combobox['values'] = [f"{d.diak_id} - {d.nev}" for d in self.naplo.diakok]
        diak_combobox.pack(pady=5)
        
        # Dátum választó (egyszerű beviteli mező helyett)
        date_frame = tk.Frame(main_frame)
        date_frame.pack(pady=5)
        
        tk.Label(date_frame, text="Dátum:").grid(row=0, column=0, padx=5)
        
        # Év, hónap, nap választók
        ev_var = tk.StringVar(value=str(datetime.now().year))
        honap_var = tk.StringVar(value=str(datetime.now().month))
        nap_var = tk.StringVar(value=str(datetime.now().day))
        
        # Év választó
        ev_spinbox = tk.Spinbox(date_frame, from_=2000, to=2100, width=5, textvariable=ev_var)
        ev_spinbox.grid(row=0, column=1, padx=2)
        
        tk.Label(date_frame, text="-").grid(row=0, column=2)
        
        # Hónap választó
        honap_spinbox = tk.Spinbox(date_frame, from_=1, to=12, width=3, textvariable=honap_var)
        honap_spinbox.grid(row=0, column=3, padx=2)
        
        tk.Label(date_frame, text="-").grid(row=0, column=4)
        
        # Nap választó
        nap_spinbox = tk.Spinbox(date_frame, from_=1, to=31, width=3, textvariable=nap_var)
        nap_spinbox.grid(row=0, column=5, padx=2)
        
        # Hiányzás típusa
        tk.Label(main_frame, text="Hiányzás típusa:").pack(pady=5)
        tipus_var = tk.StringVar(value="teljes_nap")
        tk.Radiobutton(main_frame, text="Teljes nap", variable=tipus_var, 
                      value="teljes_nap").pack(anchor='w')
        tk.Radiobutton(main_frame, text="Tantárgy", variable=tipus_var, 
                      value="tantargy").pack(anchor='w')
        
        # Tantárgy választó (csak ha tantárgy típusú hiányzás)
        tantargy_frame = tk.Frame(main_frame)
        tantargy_frame.pack(pady=5, fill='x')
        
        tk.Label(tantargy_frame, text="Tantárgy:").pack()
        tantargy_var = tk.StringVar()
        tantargy_combobox = ttk.Combobox(tantargy_frame, textvariable=tantargy_var)
        tantargy_combobox['values'] = [f"{t.tantargy_kod} - {t.nev}" for t in self.naplo.tantargyak]
        tantargy_combobox.pack(pady=5)
        
        # Igazolt-e
        igazolt_var = tk.BooleanVar(value=False)
        tk.Checkbutton(main_frame, text="Igazolt hiányzás", variable=igazolt_var).pack(pady=5)
        
        def save_absence():
            try:
                diak_id = diak_combobox.get().split(" - ")[0]
                
                # Dátum összeállítása a spinboxokból
                ev = int(ev_var.get())
                honap = int(honap_var.get())
                nap = int(nap_var.get())
                
                try:
                    datum = datetime(ev, honap, nap)
                except ValueError:
                    messagebox.showerror("Hiba", "Érvénytelen dátum!")
                    return
                
                tantargy_kod = None
                if tipus_var.get() == "tantargy":
                    tantargy_kod = tantargy_combobox.get().split(" - ")[0]
                
                if self.naplo.hianyzas_hozzaad(diak_id, datum, tantargy_kod, igazolt_var.get()):
                    messagebox.showinfo("Siker", "Hiányzás sikeresen rögzítve!")
                else:
                    messagebox.showerror("Hiba", "Ez a hiányzás már rögzítve van!")
            except (ValueError, IndexError):
                messagebox.showerror("Hiba", "Érvénytelen beviteli adatok!")
        
        tk.Button(main_frame, text="Mentés", command=save_absence).pack(pady=10)
        tk.Button(main_frame, text="Vissza", command=lambda: 
                 self.admin_main_menu() if self.naplo.current_user.role == "admin" 
                 else self.teacher_main_menu()).pack()
    
    def justify_absences(self):
        self.clear_window()
        
        main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Diák választó
        tk.Label(main_frame, text="Válassz diákot:").pack()
        diak_var = tk.StringVar()
        diak_combobox = ttk.Combobox(main_frame, textvariable=diak_var)
        diak_combobox['values'] = [f"{d.        diak_id} - {d.nev}" for d in self.naplo.diakok]
        diak_combobox.pack(pady=5)
        
        # Hiányzások listája
        list_frame = tk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        tree = ttk.Treeview(list_frame, columns=("Dátum", "Tantárgy", "Igazolt"), show="headings")
        tree.heading("Dátum", text="Dátum")
        tree.heading("Tantárgy", text="Tantárgy")
        tree.heading("Igazolt", text="Igazolt")
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscroll=scrollbar.set)
        
        def load_absences():
            # Töröljük a korábbi elemeket
            for item in tree.get_children():
                tree.delete(item)
                
            try:
                diak_id = diak_combobox.get().split(" - ")[0]
                hianyzasok = self.naplo.diak_hianyzasai(diak_id)
                
                for i, h in enumerate(hianyzasok):
                    tantargy_nev = "Egész nap"
                    if h.tantargy_kod:
                        tantargy = next((t for t in self.naplo.tantargyak if t.tantargy_kod == h.tantargy_kod), None)
                        if tantargy:
                            tantargy_nev = tantargy.nev
                    
                    tree.insert("", "end", values=(
                        h.datum.strftime("%Y-%m-%d"),
                        tantargy_nev,
                        "Igen" if h.igazolt else "Nem"
                    ), tags=(str(i),))
            except (ValueError, IndexError):
                messagebox.showerror("Hiba", "Válassz diákot!")
        
        def igazolas():
            selected = tree.selection()
            if not selected:
                messagebox.showerror("Hiba", "Nincs kiválasztott hiányzás!")
                return
                
            for item in selected:
                index = int(tree.item(item, "tags")[0])
                self.naplo.hianyzas_igazolas(index, True)
            
            load_absences()
            messagebox.showinfo("Siker", "Hiányzás(ok) sikeresen igazolva!")
        
        tk.Button(main_frame, text="Hiányzások betöltése", command=load_absences).pack(pady=5)
        tk.Button(main_frame, text="Kijelölt hiányzás(ok) igazolása", command=igazolas).pack(pady=5)
        tk.Button(main_frame, text="Vissza", command=self.teacher_main_menu).pack(pady=10)
    
    def manage_absences(self):
        self.clear_window()
        
        main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Hiányzások listája
        list_frame = tk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        tree = ttk.Treeview(list_frame, columns=("Diák", "Dátum", "Tantárgy", "Igazolt"), show="headings")
        tree.heading("Diák", text="Diák")
        tree.heading("Dátum", text="Dátum")
        tree.heading("Tantárgy", text="Tantárgy")
        tree.heading("Igazolt", text="Igazolt")
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscroll=scrollbar.set)
        
        # Hiányzások betöltése
        hianyzasok = self.naplo.osszes_hianyzas()
        for i, h in enumerate(hianyzasok):
            diak = next((d for d in self.naplo.diakok if d.diak_id == h.diak_id), None)
            diak_nev = diak.nev if diak else "Ismeretlen"
            
            tantargy_nev = "Egész nap"
            if h.tantargy_kod:
                tantargy = next((t for t in self.naplo.tantargyak if t.tantargy_kod == h.tantargy_kod), None)
                if tantargy:
                    tantargy_nev = tantargy.nev
            
            tree.insert("", "end", values=(
                diak_nev,
                h.datum.strftime("%Y-%m-%d"),
                tantargy_nev,
                "Igen" if h.igazolt else "Nem"
            ), tags=(str(i),))
        
        def igazolas():
            selected = tree.selection()
            if not selected:
                messagebox.showerror("Hiba", "Nincs kiválasztott hiányzás!")
                return
                
            for item in selected:
                index = int(tree.item(item, "tags")[0])
                self.naplo.hianyzas_igazolas(index, True)
            
            self.manage_absences()  # Frissítjük a listát
        
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Új hiányzás", command=self.record_absences).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Kijelölt hiányzás(ok) igazolása", command=igazolas).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Vissza", command=self.admin_main_menu).pack(side=tk.LEFT, padx=5)
    
    def absence_statistics(self):
        self.clear_window()
        
        stats_frame = tk.Frame(self)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Hiányzási statisztikák
        tk.Label(stats_frame, text="Hiányzási statisztikák:", font=('Arial', 12, 'bold')).pack(pady=5)
        
        stat = self.naplo.hianyzasi_statisztika()
        for diak_id, adatok in stat.items():
            tk.Label(stats_frame, text=f"{adatok['nev']}:").pack(anchor='w')
            tk.Label(stats_frame, text=f"  Összes hiányzás: {adatok['osszes']}").pack(anchor='w')
            tk.Label(stats_frame, text=f"  Igazolt: {adatok['igazolt']}").pack(anchor='w')
            tk.Label(stats_frame, text=f"  Igazolatlan: {adatok['igazolatlan']}").pack(anchor='w')
            tk.Label(stats_frame, text="").pack()  # Üres sor
        
        # Vissza gomb
        tk.Button(stats_frame, text="Vissza", command=lambda: 
                 self.admin_main_menu() if self.naplo.current_user.role == "admin" 
                 else self.teacher_main_menu()).pack(pady=10)
    
    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    naplo = Osztalynaplo()
    
    # Alap admin felhasználó létrehozása ha nem létezik
    if not any(u.username == "admin" for u in naplo.users):
        naplo.register_user("admin", "admin123", "admin")
    
    app = Application(naplo)
    app.mainloop()