#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import os

# Voraussetzung: Installation der routeros_api-Bibliothek
# pip install routeros_api
import routeros_api

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
        self.grab_set()  # Modal

    def create_widgets(self):
        # Definierte Felder: public-key, allowed-address, endpoint, persistent-keepalive
        self.entries = {}
        fields = [
            ("public_key", "Public Key"),
            ("allowed_address", "Allowed Address"),
            ("endpoint", "Endpoint"),
            ("persistent_keepalive", "Persistent Keepalive")
        ]
        row = 0
        for field_key, field_label in fields:
            label = tk.Label(self, text=field_label)
            label.grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
            entry = tk.Entry(self, width=50)
            entry.grid(row=row, column=1, padx=5, pady=5)
            self.entries[field_key] = entry
            row += 1

        # Vorbelegung falls ein bestehender Peer editiert wird
        if self.peer:
            self.entries["public_key"].insert(0, self.peer.get("public-key", ""))
            self.entries["allowed_address"].insert(0, self.peer.get("allowed-address", ""))
            self.entries["endpoint"].insert(0, self.peer.get("endpoint", ""))
            self.entries["persistent_keepalive"].insert(0, self.peer.get("persistent-keepalive", ""))

        save_button = tk.Button(self, text="Speichern", command=self.save)
        save_button.grid(row=row, column=0, padx=5, pady=5)
        cancel_button = tk.Button(self, text="Abbrechen", command=self.destroy)
        cancel_button.grid(row=row, column=1, padx=5, pady=5)

    def save(self):
        # Erstellung des Konfigurations-Dictionaries unter Umbenennung der Felder
        config = {
            "public-key": self.entries["public_key"].get(),
            "allowed-address": self.entries["allowed_address"].get(),
            "endpoint": self.entries["endpoint"].get(),
            "persistent-keepalive": self.entries["persistent_keepalive"].get(),
        }
        try:
            if self.peer:
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
# UI zur Verwaltung von Vorlagen
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
        self.grab_set()

    def create_widgets(self):
        self.entries = {}
        fields = [
            ("public_key", "Public Key"),
            ("allowed_address", "Allowed Address"),
            ("endpoint", "Endpoint"),
            ("persistent_keepalive", "Persistent Keepalive")
        ]
        row = 0
        for field_key, field_label in fields:
            label = tk.Label(self, text=field_label)
            label.grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
            entry = tk.Entry(self, width=50)
            entry.grid(row=row, column=1, padx=5, pady=5)
            self.entries[field_key] = entry
            row += 1

        if not self.new_template:
            config = self.template_manager.get_templates().get(self.template_name, {})
            self.entries["public_key"].insert(0, config.get("public-key", ""))
            self.entries["allowed_address"].insert(0, config.get("allowed-address", ""))
            self.entries["endpoint"].insert(0, config.get("endpoint", ""))
            self.entries["persistent_keepalive"].insert(0, config.get("persistent-keepalive", ""))

        save_button = tk.Button(self, text="Speichern", command=self.save)
        save_button.grid(row=row, column=0, padx=5, pady=5)
        cancel_button = tk.Button(self, text="Abbrechen", command=self.destroy)
        cancel_button.grid(row=row, column=1, padx=5, pady=5)

    def save(self):
        config = {
            "public-key": self.entries["public_key"].get(),
            "allowed-address": self.entries["allowed_address"].get(),
            "endpoint": self.entries["endpoint"].get(),
            "persistent-keepalive": self.entries["persistent_keepalive"].get(),
        }
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
        self.router_connection = None
        self.template_manager = TemplateManager()
        self.create_widgets()
        self.connect_to_router()

    def create_widgets(self):
        # Listbox zur Anzeige der Peers
        self.peer_listbox = tk.Listbox(self, width=80)
        self.peer_listbox.grid(row=0, column=0, columnspan=4, padx=5, pady=5)

        # Aktions-Buttons
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
        # Abfrage der Verbindungsdaten per Dialog
        host = simpledialog.askstring("Router Verbindung", "Router IP/Hostname:")
        if not host:
            self.quit()
            return
        username = simpledialog.askstring("Router Verbindung", "Username:")
        if not username:
            self.quit()
            return
        password = simpledialog.askstring("Router Verbindung", "Password:", show="*")
        if not password:
            self.quit()
            return
        port = simpledialog.askinteger("Router Verbindung", "Port (Standard 8728):", initialvalue=8728)

        self.router_connection = RouterConnection(host, username, password, port)
        try:
            self.router_connection.connect()
            self.refresh_peers()
        except Exception as e:
            messagebox.showerror("Verbindungsfehler", str(e))
            self.quit()

    def refresh_peers(self):
        try:
            peers = self.router_connection.get_peers()
            self.peer_listbox.delete(0, tk.END)
            for peer in peers:
                # Anzeige: interne ID und ein Ausschnitt des Public Keys (wenn vorhanden)
                pubkey = peer.get("public-key", "")
                display_text = f"{peer.get('.id')} - {pubkey[:10] if pubkey else 'Kein Public Key'}"
                self.peer_listbox.insert(tk.END, display_text)
            self.peers_data = peers  # Speicherung der vollständigen Daten für spätere Referenz
        except Exception as e:
            messagebox.showerror("Fehler", str(e))

    def get_selected_peer(self):
        selection = self.peer_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warnung", "Bitte wählen Sie einen Peer aus.")
            return None
        index = selection[0]
        return self.peers_data[index]

    def add_peer(self):
        # Abfrage, ob eine Vorlage verwendet werden soll
        use_template = messagebox.askyesno("Vorlage verwenden?", "Möchten Sie eine Vorlage verwenden?")
        if use_template:
            templates = self.template_manager.get_templates()
            if not templates:
                messagebox.showinfo("Keine Vorlagen", "Keine Vorlagen vorhanden.")
                return
            template_names = list(templates.keys())
            template_name = simpledialog.askstring("Vorlage auswählen",
                                                   f"Verfügbare Vorlagen: {', '.join(template_names)}\nGeben Sie den Namen der Vorlage ein:")
            if template_name in templates:
                # Bei Verwendung einer Vorlage werden die Felder vorab befüllt.
                PeerEditor(self, self.router_connection, peer=templates[template_name], callback=self.refresh_peers)
            else:
                messagebox.showwarning("Warnung", "Vorlage nicht gefunden.")
        else:
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

if __name__ == "__main__":
    app = WireguardManagerApp()
    app.mainloop()

