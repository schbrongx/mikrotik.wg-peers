#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import json
import os
import logging
from nacl.public import PrivateKey
import base64
import routeros_api

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

def generate_keypair():
    """
    Erzeugt ein neues Schlüsselpaar (privater und öffentlicher Schlüssel)
    mithilfe von PyNaCl.
    """
    priv = PrivateKey.generate()
    priv_key = base64.b64encode(priv.encode()).decode('ascii')
    pub_key = base64.b64encode(priv.public_key.encode()).decode('ascii')
    return priv_key, pub_key

# -------------------------------
# ConfigManager: Speichert und lädt Konfigurationsdaten (z. B. Login und Fenstergeometrie)
# -------------------------------
class ConfigManager:
    def __init__(self, filename="config.json"):
        self.filename = filename
        self.config = {}
        self.load()
        
    def load(self):
        if os.path.exists(self.filename):
            try:
                with open(self.filename, "r") as f:
                    self.config = json.load(f)
            except Exception as e:
                logging.error("Fehler beim Laden der Konfiguration: %s", e)
                self.config = {}
        else:
            self.config = {}
            
    def save(self):
        try:
            with open(self.filename, "w") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error("Fehler beim Speichern der Konfiguration: %s", e)
            
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value

# -------------------------------
# Neuer LoginDialog: Alle Logindaten in einem Fenster abfragen
# -------------------------------
class LoginDialog(tk.Toplevel):
    def __init__(self, master, config_manager):
        super().__init__(master)
        self.title("Login zum Router")
        self.transient(master)
        self.lift()
        self.attributes("-topmost", True)
        self.after(100, lambda: self.attributes("-topmost", False))
        self.config_manager = config_manager
        self.result = None
        self.save_password_var = tk.BooleanVar()
        login_defaults = self.config_manager.get("login", {})
        self.save_password_var.set(login_defaults.get("save_password", False))
        self.create_widgets()
        self.center()
        self.bind("<Escape>", lambda event: self.destroy())
        self.grab_set()  # Modal
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.wait_window(self)

    def create_widgets(self):
        login_defaults = self.config_manager.get("login", {})
        host_default = login_defaults.get("host", "")
        username_default = login_defaults.get("username", "")
        password_default = login_defaults.get("password", "") if login_defaults.get("save_password") else ""
        port_default = login_defaults.get("port", 8728)

        label_host = tk.Label(self, text="Router IP/Hostname:")
        label_host.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.entry_host = tk.Entry(self, width=40)
        self.entry_host.grid(row=0, column=1, padx=5, pady=5)
        self.entry_host.insert(0, host_default)

        label_username = tk.Label(self, text="Username:")
        label_username.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.entry_username = tk.Entry(self, width=40)
        self.entry_username.grid(row=1, column=1, padx=5, pady=5)
        self.entry_username.insert(0, username_default)

        label_password = tk.Label(self, text="Password:")
        label_password.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.entry_password = tk.Entry(self, width=40, show="*")
        self.entry_password.grid(row=2, column=1, padx=5, pady=5)
        self.entry_password.insert(0, password_default)

        label_port = tk.Label(self, text="Port:")
        label_port.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.entry_port = tk.Entry(self, width=40)
        self.entry_port.grid(row=3, column=1, padx=5, pady=5)
        self.entry_port.insert(0, str(port_default))

        self.check_save_password = tk.Checkbutton(self, text="Passwort speichern", variable=self.save_password_var)
        self.check_save_password.grid(row=4, column=0, columnspan=2, pady=5)

        button_frame = tk.Frame(self)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        ok_button = tk.Button(button_frame, text="OK", command=self.on_ok)
        ok_button.pack(side="left", padx=5)
        cancel_button = tk.Button(button_frame, text="Abbrechen", command=self.on_cancel)
        cancel_button.pack(side="left", padx=5)

    def center(self):
        self.update_idletasks()  # Aktualisiert die Fenstermaße
        master = self.master
        
        # Abfrage der Position und Größe des Hauptfensters
        master_x = master.winfo_rootx()
        master_y = master.winfo_rooty()
        master_width = master.winfo_width()
        master_height = master.winfo_height()
        
        # Abfrage der Dimensionen des Login-Fensters
        dialog_width = self.winfo_width()
        dialog_height = self.winfo_height()
        
        # Berechnung der neuen Position (Zentrierung)
        x = master_x + (master_width // 2) - (dialog_width // 2)
        y = master_y + (master_height // 2) - (dialog_height // 2)
        
        self.geometry("+{}+{}".format(x, y))

    def on_ok(self):
        host = self.entry_host.get().strip()
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        try:
            port = int(self.entry_port.get().strip())
        except ValueError:
            messagebox.showerror("Fehler", "Ungültiger Port. Bitte eine Zahl eingeben.")
            return
        if not host or not username or not password:
            messagebox.showerror("Fehler", "Bitte alle Felder ausfüllen.")
            return
        self.result = {
            "host": host,
            "username": username,
            "password": password if self.save_password_var.get() else "",
            "port": port,
            "save_password": self.save_password_var.get()
        }
        self.grab_release()
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.grab_release()
        self.destroy()

# -------------------------------
# Klasse zur Verwaltung der Router-Verbindung
# -------------------------------
class RouterConnection:
    def __init__(self, host, username, password, port=8728):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.api = None

    def connect(self):
        try:
            logger = logging.getLogger("routeros_api")
            logging.debug("Verbindung zu Router '%s' auf Port %s herstellen...", self.host, self.port)
            pool = routeros_api.RouterOsApiPool(
                self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                plaintext_login=True
            )
            self.api = pool.get_api()
            logging.debug("Verbindung erfolgreich hergestellt.")
        except Exception as e:
            raise Exception("Fehler beim Verbinden: " + str(e))

    def get_peers(self):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            logging.debug("Sende Befehl: /interface/wireguard/peers/print")
            peers = peers_resource.get()
            logging.debug("Empfangen: %s", peers)
            return peers
        except Exception as e:
            raise Exception("Fehler beim Abrufen der Peers: " + str(e))

    def add_peer(self, config):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            logging.debug("Sende Befehl zum Hinzufügen eines Peers mit Konfiguration: %s", config)
            peers_resource.add(**config)
            logging.debug("Peer erfolgreich hinzugefügt.")
        except Exception as e:
            raise Exception("Fehler beim Hinzufügen des Peers: " + str(e))

    def update_peer(self, peer_id, config):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            logging.debug("Sende Befehl zum Aktualisieren des Peers mit ID '%s' und Konfiguration: %s", peer_id, config)
            peers_resource.set(id=peer_id, **config)
            logging.debug("Peer mit ID '%s' erfolgreich aktualisiert.", peer_id)
        except Exception as e:
            raise Exception("Fehler beim Aktualisieren des Peers: " + str(e))

    def delete_peer(self, peer_id):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            logging.debug("Sende Befehl zum Löschen des Peers mit ID '%s'", peer_id)
            peers_resource.remove(id=peer_id)
            logging.debug("Peer mit ID '%s' erfolgreich gelöscht.", peer_id)
        except Exception as e:
            raise Exception("Fehler beim Löschen des Peers: " + str(e))

# -------------------------------
# Klasse zur Verwaltung von Peer-Vorlagen
# -------------------------------
class TemplateManager:
    def __init__(self, filename="wg_peer_templates.json"):
        self.filename = filename
        self.templates = {}
        self.load_templates()

    def load_templates(self):
        if os.path.exists(self.filename):
            with open(self.filename, "r") as f:
                self.templates = json.load(f)
        else:
            self.templates = {}

    def save_templates(self):
        with open(self.filename, "w") as f:
            json.dump(self.templates, f, indent=4)

    def add_template(self, name, config):
        self.templates[name] = config
        self.save_templates()

    def update_template(self, name, config):
        if name in self.templates:
            self.templates[name] = config
            self.save_templates()

    def delete_template(self, name):
        if name in self.templates:
            del self.templates[name]
            self.save_templates()

    def get_templates(self):
        return self.templates

# -------------------------------
# Dialog zur Auswahl eines Templates
# -------------------------------
class TemplateSelectionDialog(tk.Toplevel):
    def __init__(self, master, template_manager):
        super().__init__(master)
        self.template_manager = template_manager
        self.title("Vorlage auswählen")
        self.selected_template = None
        self.create_widgets()
        self.bind("<Escape>", lambda event: self.destroy())
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.wait_window(self)

    def create_widgets(self):
        self.listbox = tk.Listbox(self, width=50)
        self.listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        for name in self.template_manager.get_templates().keys():
            self.listbox.insert(tk.END, name)
        button_frame = tk.Frame(self)
        button_frame.pack(padx=10, pady=10)
        ok_button = tk.Button(button_frame, text="OK", command=self.on_ok)
        ok_button.pack(side="left", padx=5)
        cancel_button = tk.Button(button_frame, text="Abbrechen", command=self.on_cancel)
        cancel_button.pack(side="left", padx=5)

    def on_ok(self):
        selection = self.listbox.curselection()
        if selection:
            self.selected_template = self.listbox.get(selection[0])
        self.destroy()

    def on_cancel(self):
        self.selected_template = None
        self.destroy()

# -------------------------------
# Dialog zur Bearbeitung/Hinzufügung eines Peers
# -------------------------------
class PeerEditor(tk.Toplevel):
    def __init__(self, master, router_connection, peer=None, callback=None):
        super().__init__(master)
        self.router_connection = router_connection
        self.peer = peer
        self.callback = callback  # Rückruf nach erfolgreicher Änderung
        self.title("Peer bearbeiten" if peer else "Peer hinzufügen")
        self.create_widgets()
        self.bind("<Escape>", lambda event: self.destroy())
        self.grab_set()  # Modal

    def create_widgets(self):
        self.entries = {}
        fields = []
        if self.peer and self.peer.get(".id") is not None:
            fields.append(("id", "ID"))
        fields.extend([
            ("comment", "Comment"),
            ("name", "Name"),
            ("interface", "Interface"),
            ("public-key", "Public Key"),
            ("private-key", "Private Key"),
            ("allowed-address", "Allowed Address"),
            ("client-address", "Client Address"),
            ("client-dns", "Client DNS"),
            ("client-endpoint", "Client Endpoint"),
            ("client-listen-port", "Client Listen Port")
        ])
        row = 0
        for key, label_text in fields:
            label = tk.Label(self, text=label_text)
            label.grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
            entry = tk.Entry(self, width=50)
            entry.grid(row=row, column=1, padx=5, pady=5)
            if key == "id" and self.peer:
                entry.insert(0, self.peer.get(".id", ""))
                entry.configure(state="disabled")
            else:
                if self.peer:
                    entry.insert(0, self.peer.get(key, ""))
            self.entries[key] = entry
            row += 1

        keygen_button = tk.Button(self, text="Schlüsselpaar generieren", command=self.generate_keys)
        keygen_button.grid(row=row, column=0, columnspan=2, padx=5, pady=5)
        row += 1

        save_button = tk.Button(self, text="Speichern", command=self.save)
        save_button.grid(row=row, column=0, padx=5, pady=5)
        cancel_button = tk.Button(self, text="Abbrechen", command=self.destroy)
        cancel_button.grid(row=row, column=1, padx=5, pady=5)

    def generate_keys(self):
        current_pub = self.entries["public-key"].get()
        current_priv = self.entries["private-key"].get()
        if current_pub or current_priv:
            overwrite = messagebox.askyesno("Überschreiben?", "Ein Schlüsselpaar existiert bereits. Möchten Sie es überschreiben?")
            if not overwrite:
                return
        priv_key, pub_key = generate_keypair()
        self.entries["public-key"].delete(0, tk.END)
        self.entries["public-key"].insert(0, pub_key)
        self.entries["private-key"].delete(0, tk.END)
        self.entries["private-key"].insert(0, priv_key)
        logging.debug("Neues Schlüsselpaar generiert: Public Key: %s, Private Key: %s", pub_key, priv_key)

    def save(self):
        config = {}
        for key in self.entries:
            value = self.entries[key].get()
            config[key] = value if value is not None else ""
        try:
            if self.peer and self.peer.get("id"):
                peer_id = self.peer.get("id")
                self.router_connection.update_peer(peer_id, config)
            else:
                self.router_connection.add_peer(config)
            if self.callback:
                self.callback()
            self.destroy()
        except Exception as e:
            messagebox.showerror("Fehler", str(e))

# -------------------------------
# UI zur Verwaltung von Vorlagen
# -------------------------------
class TemplateManagerUI(tk.Toplevel):
    def __init__(self, master, template_manager):
        super().__init__(master)
        self.template_manager = template_manager
        self.title("Vorlagen verwalten")
        self.create_widgets()
        self.refresh_list()
        self.bind("<Escape>", lambda event: self.destroy())
        self.grab_set()

    def create_widgets(self):
        self.listbox = tk.Listbox(self, width=50)
        self.listbox.grid(row=0, column=0, columnspan=2, padx=5, pady=5)
        add_button = tk.Button(self, text="Hinzufügen", command=self.add_template)
        add_button.grid(row=1, column=0, padx=5, pady=5)
        edit_button = tk.Button(self, text="Bearbeiten", command=self.edit_template)
        edit_button.grid(row=1, column=1, padx=5, pady=5)
        delete_button = tk.Button(self, text="Löschen", command=self.delete_template)
        delete_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def refresh_list(self):
        self.listbox.delete(0, tk.END)
        for name in self.template_manager.get_templates().keys():
            self.listbox.insert(tk.END, name)

    def add_template(self):
        name = simpledialog.askstring("Neue Vorlage", "Name der Vorlage:")
        if name:
            TemplateEditor(self, name, self.template_manager, new_template=True, callback=self.refresh_list)

    def edit_template(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Warnung", "Bitte wählen Sie eine Vorlage aus.")
            return
        name = self.listbox.get(selection[0])
        TemplateEditor(self, name, self.template_manager, new_template=False, callback=self.refresh_list)

    def delete_template(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Warnung", "Bitte wählen Sie eine Vorlage aus.")
            return
        name = self.listbox.get(selection[0])
        if messagebox.askyesno("Bestätigen", f"Vorlage '{name}' wirklich löschen?"):
            self.template_manager.delete_template(name)
            self.refresh_list()

# -------------------------------
# Editor-Fenster für Vorlagen (ähnlich wie PeerEditor)
# -------------------------------
class TemplateEditor(tk.Toplevel):
    def __init__(self, master, template_name, template_manager, new_template=True, callback=None):
        super().__init__(master)
        self.template_name = template_name
        self.template_manager = template_manager
        self.new_template = new_template
        self.callback = callback
        self.title("Vorlage bearbeiten" if not new_template else "Vorlage hinzufügen")
        self.create_widgets()
        self.bind("<Escape>", lambda event: self.destroy())
        self.grab_set()

    def create_widgets(self):
        self.entries = {}
        fields = [
            ("comment", "Comment"),
            ("name", "Name"),
            ("interface", "Interface"),
            ("public-key", "Public Key"),
            ("private-key", "Private Key"),
            ("allowed-address", "Allowed Address"),
            ("client-address", "Client Address"),
            ("client-dns", "Client DNS"),
            ("client-endpoint", "Client Endpoint"),
            ("client-listen-port", "Client Listen Port")
        ]
        row = 0
        for key, label_text in fields:
            label = tk.Label(self, text=label_text)
            label.grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
            entry = tk.Entry(self, width=50)
            entry.grid(row=row, column=1, padx=5, pady=5)
            self.entries[key] = entry
            row += 1

        if not self.new_template:
            config = self.template_manager.get_templates().get(self.template_name, {})
            for key in self.entries:
                self.entries[key].insert(0, config.get(key, ""))

        save_button = tk.Button(self, text="Speichern", command=self.save)
        save_button.grid(row=row, column=0, padx=5, pady=5)
        cancel_button = tk.Button(self, text="Abbrechen", command=self.destroy)
        cancel_button.grid(row=row, column=1, padx=5, pady=5)

    def save(self):
        config = {}
        for key in self.entries:
            config[key] = self.entries[key].get()
        if self.new_template:
            self.template_manager.add_template(self.template_name, config)
        else:
            self.template_manager.update_template(self.template_name, config)
        if self.callback:
            self.callback()
        self.destroy()

# -------------------------------
# Hauptanwendung: GUI für die Verwaltung der Wireguard-Peers
# -------------------------------
class WireguardManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Wireguard Peer Manager")
        self.config_manager = ConfigManager()  # ConfigManager initialisieren
        self.router_connection = None
        self.template_manager = TemplateManager()
        self.create_widgets()
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.bind("<Delete>", lambda event: self.delete_peer())
        self.bind("<Double-1>", lambda event: self.edit_peer())
        self.bind("<Return>", lambda event: self.edit_peer())
        self.connect_to_router()

    def create_widgets(self):
        columns = ("id", "comment", "name", "interface", "public-key", "private-key", 
                   "allowed-address", "client-address", "client-dns", "client-endpoint", "client-listen-port")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=100, anchor="w")
        
        self.tree.grid(row=0, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=4, sticky="ns")
        self.tree.configure(yscrollcommand=vsb.set)
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        refresh_button = tk.Button(self, text="Aktualisieren", command=self.refresh_peers)
        refresh_button.grid(row=1, column=0, padx=5, pady=5)
        add_button = tk.Button(self, text="Peer hinzufügen", command=self.add_peer)
        add_button.grid(row=1, column=1, padx=5, pady=5)
        edit_button = tk.Button(self, text="Peer bearbeiten", command=self.edit_peer)
        edit_button.grid(row=1, column=2, padx=5, pady=5)
        delete_button = tk.Button(self, text="Peer löschen", command=self.delete_peer)
        delete_button.grid(row=1, column=3, padx=5, pady=5)
        template_button = tk.Button(self, text="Vorlagen verwalten", command=self.manage_templates)
        template_button.grid(row=2, column=0, columnspan=4, padx=5, pady=5)

    def connect_to_router(self):
        # Verwenden Sie den neuen LoginDialog, um alle Login-Daten in einem Fenster abzufragen.
        login_dialog = LoginDialog(self, self.config_manager)
        if login_dialog.result is None:
            self.quit()
            return
        result = login_dialog.result
        host = result["host"]
        username = result["username"]
        password = result["password"]
        port = result["port"]

        self.router_connection = RouterConnection(host, username, password, port)
        try:
            self.router_connection.connect()
            self.refresh_peers()
            # Speichern der Logindaten (inklusive Passwort, wenn gewählt)
            login_data = {"host": host, "username": username, "port": port}
            if result.get("save_password"):
                login_data["password"] = password
            login_data["save_password"] = result.get("save_password")
            self.config_manager.set("login", login_data)
            self.config_manager.save()
        except Exception as e:
            messagebox.showerror("Verbindungsfehler", str(e))
            self.quit()

    def refresh_peers(self):
        try:
            peers = self.router_connection.get_peers()
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.peers_data = {}
            for idx, peer in enumerate(peers):
                real_id = peer.get("id")
                tree_id = real_id or f"peer_{idx}"
                displayed_id = real_id if real_id else ""
                row_values = (
                    displayed_id,
                    peer.get("comment", ""),
                    peer.get("name", ""),
                    peer.get("interface", ""),
                    peer.get("public-key", ""),
                    peer.get("private-key", ""),
                    peer.get("allowed-address", ""),
                    peer.get("client-address", ""),
                    peer.get("client-dns", ""),
                    peer.get("client-endpoint", ""),
                    peer.get("client-listen-port", "")
                )
                self.tree.insert("", "end", iid=tree_id, values=row_values)
                self.peers_data[tree_id] = peer
        except Exception as e:
            messagebox.showerror("Fehler", str(e))

    def add_peer(self):
        use_template = messagebox.askyesno("Vorlage verwenden?", "Möchten Sie eine Vorlage verwenden?")
        if use_template:
            templates = self.template_manager.get_templates()
            if not templates:
                messagebox.showinfo("Keine Vorlagen", "Keine Vorlagen vorhanden.")
                return
            dialog = TemplateSelectionDialog(self, self.template_manager)
            selected_template = dialog.selected_template
            if selected_template:
                PeerEditor(self, self.router_connection, peer=templates[selected_template], callback=self.refresh_peers)
            else:
                messagebox.showwarning("Warnung", "Keine Vorlage ausgewählt.")
        else:
            PeerEditor(self, self.router_connection, callback=self.refresh_peers)

    def get_selected_peer(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warnung", "Bitte wählen Sie einen Peer aus.")
            return None
        peer_id = selection[0]
        return self.peers_data.get(peer_id)

    def edit_peer(self):
        peer = self.get_selected_peer()
        if peer:
            PeerEditor(self, self.router_connection, peer=peer, callback=self.refresh_peers)

    def delete_peer(self):
        peer = self.get_selected_peer()
        if peer:
            if messagebox.askyesno("Bestätigen", "Peer wirklich löschen?"):
                try:
                    # Verwenden Sie "id" statt ".id"
                    self.router_connection.delete_peer(peer.get("id"))
                    self.refresh_peers()
                except Exception as e:
                    messagebox.showerror("Fehler", str(e))

    def manage_templates(self):
        TemplateManagerUI(self, self.template_manager)

if __name__ == "__main__":
    app = WireguardManagerApp()
    app.mainloop()

