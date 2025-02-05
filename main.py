#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import ttk
import json
import os
import sys

# Voraussetzung: Installation der routeros_api-Bibliothek
import routeros_api

# -------------------------------
# ConfigManager: Speichert und lädt Konfigurationsdaten (Login und Fenstergeometrie)
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
                self.config = {}
        else:
            self.config = {}
            
    def save(self):
        try:
            with open(self.filename, "w") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print("Fehler beim Speichern der Konfiguration:", e, file=sys.stderr)
            
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value

# -------------------------------
# LoginDialog: Ein Fenster zur Eingabe der Login-Daten
# -------------------------------
class LoginDialog(tk.Toplevel):
    def __init__(self, master, config):
        super().__init__(master)
        self.title("Login zum Router")
        self.config_data = config
        self.result = None
        self.create_widgets()
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.wait_window(self)
        
    def create_widgets(self):
        # Labels und Eingabefelder
        login_config = self.config_data.get("login", {})
        tk.Label(self, text="Router IP/Hostname:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.host_entry = tk.Entry(self, width=40)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5)
        self.host_entry.insert(0, login_config.get("host", ""))
        
        tk.Label(self, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_entry = tk.Entry(self, width=40)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        self.username_entry.insert(0, login_config.get("username", ""))
        
        tk.Label(self, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_entry = tk.Entry(self, width=40, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        tk.Label(self, text="Port:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.port_entry = tk.Entry(self, width=40)
        self.port_entry.grid(row=3, column=1, padx=5, pady=5)
        self.port_entry.insert(0, login_config.get("port", "8728"))
        
        # Buttons OK und Abbrechen
        button_frame = tk.Frame(self)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        ok_button = tk.Button(button_frame, text="OK", width=10, command=self.on_ok)
        ok_button.pack(side=tk.LEFT, padx=5)
        cancel_button = tk.Button(button_frame, text="Abbrechen", width=10, command=self.on_cancel)
        cancel_button.pack(side=tk.LEFT, padx=5)
        
    def on_ok(self):
        host = self.host_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Fehler", "Ungültiger Port. Bitte eine Zahl eingeben.")
            return
        if not host or not username or not password:
            messagebox.showerror("Fehler", "Bitte alle Felder ausfüllen.")
            return
        self.result = {"host": host, "username": username, "password": password, "port": port}
        self.destroy()
        
    def on_cancel(self):
        self.result = None
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
            pool = routeros_api.RouterOsApiPool(
                self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                plaintext_login=True
            )
            self.api = pool.get_api()
        except Exception as e:
            raise Exception("Fehler beim Verbinden: " + str(e))

    def get_peers(self):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            peers = peers_resource.get()
            return peers
        except Exception as e:
            raise Exception("Fehler beim Abrufen der Peers: " + str(e))

    def add_peer(self, config):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            peers_resource.add(**config)
        except Exception as e:
            raise Exception("Fehler beim Hinzufügen des Peers: " + str(e))

    def update_peer(self, peer_id, config):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            peers_resource.set(id=peer_id, **config)
        except Exception as e:
            raise Exception("Fehler beim Aktualisieren des Peers: " + str(e))

    def delete_peer(self, peer_id):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            peers_resource.remove(id=peer_id)
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
# Dialog zur Auswahl einer Vorlage (bei Anlegen eines neuen Peers)
# -------------------------------
class TemplateSelectionDialog(tk.Toplevel):
    def __init__(self, master, template_manager):
        super().__init__(master)
        self.title("Vorlage auswählen")
        self.template_manager = template_manager
        self.selected_template = None
        self.create_widgets()
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def create_widgets(self):
        self.listbox = tk.Listbox(self)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        for name in self.template_manager.get_templates().keys():
            self.listbox.insert(tk.END, name)
        button_frame = tk.Frame(self)
        button_frame.pack(pady=5)
        ok_button = tk.Button(button_frame, text="OK", command=self.ok)
        ok_button.pack(side=tk.LEFT, padx=5)
        cancel_button = tk.Button(button_frame, text="Abbrechen", command=self.cancel)
        cancel_button.pack(side=tk.LEFT, padx=5)

    def ok(self):
        selection = self.listbox.curselection()
        if selection:
            self.selected_template = self.listbox.get(selection[0])
        self.destroy()

    def cancel(self):
        self.selected_template = None
        self.destroy()

# -------------------------------
# Editor-DIALOG für Peer (Hinzufügen/Bearbeiten) mit erweiterten Feldern
# -------------------------------
class PeerEditor(tk.Toplevel):
    def __init__(self, master, router_connection, peer=None, callback=None):
        super().__init__(master)
        self.router_connection = router_connection
        self.peer = peer  # Falls vorhanden, enthält es die Konfiguration als Dictionary
        self.callback = callback  # Rückruffunktion zum Aktualisieren der Übersicht
        self.title("Peer bearbeiten" if peer else "Peer hinzufügen")
        self.fields = [
            ("comment", "Kommentar"),
            ("name", "Name"),
            ("interface", "Interface"),
            ("public-key", "Public Key"),
            ("private-key", "Private Key"),
            ("allowed-address", "Allowed Address"),
            ("client-address", "Client Address"),
            ("client-dns1", "Client DNS 1"),
            ("client-dns2", "Client DNS 2"),
            ("client-endpoint", "Client Endpoint"),
            ("client-listen-port", "Client Listen Port")
        ]
        self.entries = {}
        self.create_widgets()
        self.grab_set()

    def create_widgets(self):
        for idx, (field_key, field_label) in enumerate(self.fields):
            label = tk.Label(self, text=field_label)
            label.grid(row=idx, column=0, sticky=tk.W, padx=5, pady=3)
            entry = tk.Entry(self, width=50)
            entry.grid(row=idx, column=1, padx=5, pady=3)
            self.entries[field_key] = entry
            if self.peer:
                entry.insert(0, self.peer.get(field_key, ""))
        button_row = len(self.fields)
        save_button = tk.Button(self, text="Speichern", command=self.save)
        save_button.grid(row=button_row, column=0, padx=5, pady=5)
        cancel_button = tk.Button(self, text="Abbrechen", command=self.destroy)
        cancel_button.grid(row=button_row, column=1, padx=5, pady=5)

    def save(self):
        config = {}
        for field_key, _ in self.fields:
            config[field_key] = self.entries[field_key].get()
        try:
            if self.peer:  # Bearbeiten eines existierenden Peers
                peer_id = self.peer.get(".id")
                self.router_connection.update_peer(peer_id, config)
            else:
                self.router_connection.add_peer(config)
            if self.callback:
                self.callback()
            self.destroy()
        except Exception as e:
            messagebox.showerror("Fehler", str(e))

# -------------------------------
# Editor-DIALOG für Vorlagen (Hinzufügen/Bearbeiten) mit erweiterten Feldern
# -------------------------------
class TemplateEditor(tk.Toplevel):
    def __init__(self, master, template_name, template_manager, new_template=True, callback=None):
        super().__init__(master)
        self.template_name = template_name
        self.template_manager = template_manager
        self.new_template = new_template
        self.callback = callback
        self.title("Vorlage bearbeiten" if not new_template else "Vorlage hinzufügen")
        self.fields = [
            ("comment", "Kommentar"),
            ("name", "Name"),
            ("interface", "Interface"),
            ("public-key", "Public Key"),
            ("private-key", "Private Key"),
            ("allowed-address", "Allowed Address"),
            ("client-address", "Client Address"),
            ("client-dns1", "Client DNS 1"),
            ("client-dns2", "Client DNS 2"),
            ("client-endpoint", "Client Endpoint"),
            ("client-listen-port", "Client Listen Port")
        ]
        self.entries = {}
        self.create_widgets()
        self.grab_set()

    def create_widgets(self):
        for idx, (field_key, field_label) in enumerate(self.fields):
            label = tk.Label(self, text=field_label)
            label.grid(row=idx, column=0, sticky=tk.W, padx=5, pady=3)
            entry = tk.Entry(self, width=50)
            entry.grid(row=idx, column=1, padx=5, pady=3)
            self.entries[field_key] = entry
        if not self.new_template:
            config = self.template_manager.get_templates().get(self.template_name, {})
            for field_key, _ in self.fields:
                self.entries[field_key].insert(0, config.get(field_key, ""))
        button_row = len(self.fields)
        save_button = tk.Button(self, text="Speichern", command=self.save)
        save_button.grid(row=button_row, column=0, padx=5, pady=5)
        cancel_button = tk.Button(self, text="Abbrechen", command=self.destroy)
        cancel_button.grid(row=button_row, column=1, padx=5, pady=5)

    def save(self):
        config = {}
        for field_key, _ in self.fields:
            config[field_key] = self.entries[field_key].get()
        if self.new_template:
            self.template_manager.add_template(self.template_name, config)
        else:
            self.template_manager.update_template(self.template_name, config)
        if self.callback:
            self.callback()
        self.destroy()

# -------------------------------
# UI zur Verwaltung von Vorlagen (Liste der Vorlagen)
# -------------------------------
class TemplateManagerUI(tk.Toplevel):
    def __init__(self, master, template_manager):
        super().__init__(master)
        self.template_manager = template_manager
        self.title("Vorlagen verwalten")
        self.create_widgets()
        self.refresh_list()
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
# Hauptanwendung: GUI für die Verwaltung der Wireguard-Peers
# -------------------------------
class WireguardManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.config_manager = ConfigManager()
        # Setze Fenstergeometrie, falls in config vorhanden
        geometry = self.config_manager.get("geometry")
        if geometry:
            self.geometry(geometry)
        self.title("Wireguard Peer Manager")
        self.router_connection = None
        self.template_manager = TemplateManager()
        self.peers_data = {}  # Mapping: peer_id -> vollständiges Peer-Dictionary
        self.create_widgets()
        self.bind_events()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.login_and_connect()

    def login_and_connect(self):
        # Zeige Login-Dialog
        login_dialog = LoginDialog(self, self.config_manager)
        result = login_dialog.result
        if not result:
            self.destroy()
            return
        # Speichere Login-Informationen (ohne Passwort) in der Konfiguration
        self.config_manager.set("login", {
            "host": result["host"],
            "username": result["username"],
            "port": result["port"]
        })
        self.config_manager.save()
        self.router_connection = RouterConnection(
            result["host"], result["username"], result["password"], result["port"]
        )
        try:
            self.router_connection.connect()
            self.refresh_peers()
        except Exception as e:
            messagebox.showerror("Verbindungsfehler", str(e))
            self.destroy()

    def create_widgets(self):
        # Frame für die Tabelle
        table_frame = tk.Frame(self)
        table_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Scrollbar
        vsb = tk.Scrollbar(table_frame, orient="vertical")
        vsb.grid(row=0, column=1, sticky="ns")

        # Treeview als Tabelle
        self.tree = ttk.Treeview(table_frame, columns=(
            "comment", "name", "interface", "public-key", "private-key", "allowed-address",
            "client-address", "client-dns1", "client-dns2", "client-endpoint", "client-listen-port"
        ), show="headings", yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.config(command=self.tree.yview)

        # Spaltenüberschriften und Spaltenkonfiguration
        columns = [
            ("comment", "Kommentar"),
            ("name", "Name"),
            ("interface", "Interface"),
            ("public-key", "Public Key"),
            ("private-key", "Private Key"),
            ("allowed-address", "Allowed Address"),
            ("client-address", "Client Address"),
            ("client-dns1", "Client DNS 1"),
            ("client-dns2", "Client DNS 2"),
            ("client-endpoint", "Client Endpoint"),
            ("client-listen-port", "Client Listen Port")
        ]
        for col_id, col_heading in columns:
            self.tree.heading(col_id, text=col_heading)
            self.tree.column(col_id, width=100, anchor="w")

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # Buttons unterhalb der Tabelle
        button_frame = tk.Frame(self)
        button_frame.grid(row=1, column=0, pady=5, sticky="ew")
        refresh_button = tk.Button(button_frame, text="Aktualisieren", command=self.refresh_peers)
        refresh_button.pack(side=tk.LEFT, padx=5)
        add_button = tk.Button(button_frame, text="Peer hinzufügen", command=self.add_peer)
        add_button.pack(side=tk.LEFT, padx=5)
        edit_button = tk.Button(button_frame, text="Peer bearbeiten", command=self.edit_peer)
        edit_button.pack(side=tk.LEFT, padx=5)
        delete_button = tk.Button(button_frame, text="Peer löschen", command=self.delete_peer)
        delete_button.pack(side=tk.LEFT, padx=5)
        template_button = tk.Button(button_frame, text="Vorlagen verwalten", command=self.manage_templates)
        template_button.pack(side=tk.LEFT, padx=5)

    def bind_events(self):
        # Doppelklick auf einen Peer öffnet den Bearbeitungsdialog
        self.tree.bind("<Double-1>", self.on_double_click)

    def on_double_click(self, event):
        self.edit_peer()

    def refresh_peers(self):
        try:
            peers = self.router_connection.get_peers()
            # Leeren der Tabelle und der internen Zuordnung
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.peers_data = {}
            for peer in peers:
                peer_id = peer.get(".id")
                values = (
                    peer.get("comment", ""),
                    peer.get("name", ""),
                    peer.get("interface", ""),
                    peer.get("public-key", ""),
                    peer.get("private-key", ""),
                    peer.get("allowed-address", ""),
                    peer.get("client-address", ""),
                    peer.get("client-dns1", ""),
                    peer.get("client-dns2", ""),
                    peer.get("client-endpoint", ""),
                    peer.get("client-listen-port", "")
                )
                self.tree.insert("", "end", iid=peer_id, values=values)
                self.peers_data[peer_id] = peer
        except Exception as e:
            messagebox.showerror("Fehler", str(e))

    def get_selected_peer(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warnung", "Bitte wählen Sie einen Peer aus.")
            return None
        peer_id = selection[0]
        return self.peers_data.get(peer_id)

    def add_peer(self):
        templates = self.template_manager.get_templates()
        if templates:
            if messagebox.askyesno("Vorlage verwenden?", "Möchten Sie eine Vorlage verwenden?"):
                dlg = TemplateSelectionDialog(self, self.template_manager)
                self.wait_window(dlg)
                selected_template = dlg.selected_template
                if selected_template:
                    config = templates[selected_template]
                    PeerEditor(self, self.router_connection, peer=config, callback=self.refresh_peers)
                    return
        PeerEditor(self, self.router_connection, callback=self.refresh_peers)

    def edit_peer(self):
        peer = self.get_selected_peer()
        if peer:
            PeerEditor(self, self.router_connection, peer=peer, callback=self.refresh_peers)

    def delete_peer(self):
        peer = self.get_selected_peer()
        if peer:
            if messagebox.askyesno("Bestätigen", "Peer wirklich löschen?"):
                try:
                    self.router_connection.delete_peer(peer.get(".id"))
                    self.refresh_peers()
                except Exception as e:
                    messagebox.showerror("Fehler", str(e))

    def manage_templates(self):
        TemplateManagerUI(self, self.template_manager)

    def on_closing(self):
        # Speichere Fenstergeometrie in der Konfiguration
        self.config_manager.set("geometry", self.geometry())
        self.config_manager.save()
        self.destroy()

if __name__ == "__main__":
    app = WireguardManagerApp()
    app.mainloop()

