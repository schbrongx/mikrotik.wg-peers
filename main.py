#!/usr/bin/env python3
import base64
import io
import json
import logging
import os
import sys
import zipfile
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from nacl.public import PrivateKey
import routeros_api

logging.basicConfig(level=logging.ERROR, format='%(asctime)s %(levelname)s: %(message)s')

def generate_keypair():
    """
    Generates a new key pair (private and public key) using PyNaCl.
    """
    priv = PrivateKey.generate()
    priv_key = base64.b64encode(priv.encode()).decode('ascii')
    pub_key = base64.b64encode(priv.public_key.encode()).decode('ascii')
    return priv_key, pub_key

def generate_config_text(peer):
    config_lines = []
    config_lines.append("[Interface]")
    if peer.get("private-key"):
        config_lines.append("PrivateKey = {}".format(peer["private-key"]))
    if peer.get("client-address"):
        config_lines.append("Address = {}".format(peer["client-address"]))
    if peer.get("client-dns"):
        config_lines.append("DNS = {}".format(peer["client-dns"]))
    if peer.get("client-listen-port"):
        config_lines.append("ListenPort = {}".format(peer["client-listen-port"]))
    
    config_lines.append("")
    config_lines.append("[Peer]")
    if peer.get("public-key"):
        config_lines.append("PublicKey = {}".format(peer["public-key"]))
    if peer.get("allowed-address"):
        config_lines.append("AllowedIPs = {}".format(peer["allowed-address"]))
    if peer.get("client-endpoint"):
        config_lines.append("Endpoint = {}".format(peer["client-endpoint"]))
    
    return "\n".join(config_lines)

# -------------------------------------------------------------------
# ConfigManager: Saves and loads configuration data (e.g. login and window geometry)
# -------------------------------------------------------------------
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
                logging.error("Error loading configuration: %s", e)
                self.config = {}
        else:
            self.config = {}
            
    def save(self):
        try:
            with open(self.filename, "w") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error("Error saving configuration: %s", e)
            
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value

# -------------------------------------------------------------------
# LoginDialog: Collects all login data in a single window
# -------------------------------------------------------------------
class LoginDialog(tk.Toplevel):
    def __init__(self, master, config_manager):
        super().__init__(master)
        self.title("Router Login")
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

        self.check_save_password = tk.Checkbutton(self, text="Save password", variable=self.save_password_var)
        self.check_save_password.grid(row=4, column=0, columnspan=2, pady=5)

        button_frame = tk.Frame(self)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        ok_button = tk.Button(button_frame, text="OK", command=self.on_ok)
        ok_button.pack(side="left", padx=5)
        cancel_button = tk.Button(button_frame, text="Cancel", command=self.on_cancel)
        cancel_button.pack(side="left", padx=5)

    def center(self):
        self.update_idletasks()  # Update window dimensions
        master = self.master
        
        # Get position and size of the main window
        master_x = master.winfo_rootx()
        master_y = master.winfo_rooty()
        master_width = master.winfo_width()
        master_height = master.winfo_height()
        
        # Get dimensions of the login window
        dialog_width = self.winfo_width()
        dialog_height = self.winfo_height()
        
        # Calculate new position (centered)
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
            messagebox.showerror("Error", "Invalid port. Please enter a number.")
            return
        if not host or not username or not password:
            messagebox.showerror("Error", "Please fill out all fields.")
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

# -------------------------------------------------------------------
# RouterConnection: Manages the connection to the router
# -------------------------------------------------------------------
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
            logging.debug("Connecting to router '%s' on port %s...", self.host, self.port)
            pool = routeros_api.RouterOsApiPool(
                self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                plaintext_login=True
            )
            self.api = pool.get_api()
            logging.debug("Connection successful.")
        except Exception as e:
            raise Exception("Error connecting: " + str(e))

    def get_peers(self):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            logging.debug("Sending command: /interface/wireguard/peers/print")
            peers = peers_resource.get()
            logging.debug("Received: %s", peers)
            return peers
        except Exception as e:
            raise Exception("Error retrieving peers: " + str(e))

    def add_peer(self, config):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            logging.debug("Sending command to add a peer with configuration: %s", config)
            peers_resource.add(**config)
            logging.debug("Peer added successfully.")
        except Exception as e:
            raise Exception("Error adding peer: " + str(e))

    def update_peer(self, peer_id, config):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            logging.debug("Sending command to update peer with ID '%s' and configuration: %s", peer_id, config)
            peers_resource.set(id=peer_id, **config)
            logging.debug("Peer with ID '%s' updated successfully.", peer_id)
        except Exception as e:
            raise Exception("Error updating peer: " + str(e))

    def delete_peer(self, peer_id):
        try:
            peers_resource = self.api.get_resource('/interface/wireguard/peers')
            logging.debug("Sending command to delete peer with ID '%s'", peer_id)
            peers_resource.remove(id=peer_id)
            logging.debug("Peer with ID '%s' deleted successfully.", peer_id)
        except Exception as e:
            raise Exception("Error deleting peer: " + str(e))

# -------------------------------------------------------------------
# TemplateManager: Manages peer templates
# -------------------------------------------------------------------
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

# -------------------------------------------------------------------
# TemplateSelectionDialog: Dialog for selecting a template
# -------------------------------------------------------------------
class TemplateSelectionDialog(tk.Toplevel):
    def __init__(self, master, template_manager):
        super().__init__(master)
        self.template_manager = template_manager
        self.title("Select Template")
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
        cancel_button = tk.Button(button_frame, text="Cancel", command=self.on_cancel)
        cancel_button.pack(side="left", padx=5)

    def on_ok(self):
        selection = self.listbox.curselection()
        if selection:
            self.selected_template = self.listbox.get(selection[0])
        self.destroy()

    def on_cancel(self):
        self.selected_template = None
        self.destroy()

# -------------------------------------------------------------------
# PeerEditor: Dialog for editing/adding a peer
# -------------------------------------------------------------------
class PeerEditor(tk.Toplevel):
    def __init__(self, master, router_connection, peer=None, callback=None):
        super().__init__(master)
        self.router_connection = router_connection
        self.peer = peer
        self.callback = callback  # Callback after successful update
        self.title("Edit Peer" if peer else "Add Peer")
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

        keygen_button = tk.Button(self, text="Generate key pair", command=self.generate_keys)
        keygen_button.grid(row=row, column=0, columnspan=2, padx=5, pady=5)
        row += 1

        save_button = tk.Button(self, text="Save", command=self.save)
        save_button.grid(row=row, column=0, padx=5, pady=5)
        cancel_button = tk.Button(self, text="Cancel", command=self.destroy)
        cancel_button.grid(row=row, column=1, padx=5, pady=5)

    def generate_keys(self):
        current_pub = self.entries["public-key"].get()
        current_priv = self.entries["private-key"].get()
        if current_pub or current_priv:
            overwrite = messagebox.askyesno("Overwrite?", "A key pair already exists. Do you want to overwrite it?")
            if not overwrite:
                return
        priv_key, pub_key = generate_keypair()
        self.entries["public-key"].delete(0, tk.END)
        self.entries["public-key"].insert(0, pub_key)
        self.entries["private-key"].delete(0, tk.END)
        self.entries["private-key"].insert(0, priv_key)
        logging.debug("New key pair generated: Public Key: %s, Private Key: %s", pub_key, priv_key)

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
            messagebox.showerror("Error", str(e))

# -------------------------------------------------------------------
# TemplateManagerUI: User interface for managing templates
# -------------------------------------------------------------------
class TemplateManagerUI(tk.Toplevel):
    def __init__(self, master, template_manager):
        super().__init__(master)
        self.template_manager = template_manager
        self.title("Manage Templates")
        self.create_widgets()
        self.refresh_list()
        self.bind("<Escape>", lambda event: self.destroy())
        self.grab_set()

    def create_widgets(self):
        self.listbox = tk.Listbox(self, width=50)
        self.listbox.grid(row=0, column=0, columnspan=2, padx=5, pady=5)
        add_button = tk.Button(self, text="Add", command=self.add_template)
        add_button.grid(row=1, column=0, padx=5, pady=5)
        edit_button = tk.Button(self, text="Edit", command=self.edit_template)
        edit_button.grid(row=1, column=1, padx=5, pady=5)
        delete_button = tk.Button(self, text="Delete", command=self.delete_template)
        delete_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def refresh_list(self):
        self.listbox.delete(0, tk.END)
        for name in self.template_manager.get_templates().keys():
            self.listbox.insert(tk.END, name)

    def add_template(self):
        name = simpledialog.askstring("New Template", "Template name:")
        if name:
            TemplateEditor(self, name, self.template_manager, new_template=True, callback=self.refresh_list)

    def edit_template(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a template.")
            return
        name = self.listbox.get(selection[0])
        TemplateEditor(self, name, self.template_manager, new_template=False, callback=self.refresh_list)

    def delete_template(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a template.")
            return
        name = self.listbox.get(selection[0])
        if messagebox.askyesno("Confirm", f"Really delete template '{name}'?"):
            self.template_manager.delete_template(name)
            self.refresh_list()

# -------------------------------------------------------------------
# TemplateEditor: Dialog for editing/adding a template (similar to PeerEditor)
# -------------------------------------------------------------------
class TemplateEditor(tk.Toplevel):
    def __init__(self, master, template_name, template_manager, new_template=True, callback=None):
        super().__init__(master)
        self.template_name = template_name
        self.template_manager = template_manager
        self.new_template = new_template
        self.callback = callback
        self.title("Edit Template" if not new_template else "Add Template")
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

        save_button = tk.Button(self, text="Save", command=self.save)
        save_button.grid(row=row, column=0, padx=5, pady=5)
        cancel_button = tk.Button(self, text="Cancel", command=self.destroy)
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

# -------------------------------------------------------------------
# WireguardManagerApp: Main application for managing Wireguard peers
# -------------------------------------------------------------------
class WireguardManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Wireguard Peer Manager")
        self.config_manager = ConfigManager()  # Initialize ConfigManager
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
        # Treeview configuration with existing columns
        columns = ("id", "comment", "name", "interface", "public-key", "private-key", 
                   "allowed-address", "client-address", "client-dns", "client-endpoint", 
                   "client-listen-port", "download")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        for col in columns:
            if col == "download":
                self.tree.heading(col, text="")
                self.tree.column(col, width=60, anchor="center")
            else:
                self.tree.heading(col, text=col.capitalize())
                self.tree.column(col, width=100, anchor="w")
        
        self.tree.grid(row=0, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=4, sticky="ns")
        self.tree.configure(yscrollcommand=vsb.set)
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        refresh_button = tk.Button(self, text="Refresh", command=self.refresh_peers)
        refresh_button.grid(row=1, column=0, padx=5, pady=5)
        add_button = tk.Button(self, text="Add Peer", command=self.add_peer)
        add_button.grid(row=1, column=1, padx=5, pady=5)
        edit_button = tk.Button(self, text="Edit Peer", command=self.edit_peer)
        edit_button.grid(row=1, column=2, padx=5, pady=5)
        delete_button = tk.Button(self, text="Delete Peer", command=self.delete_peer)
        delete_button.grid(row=1, column=3, padx=5, pady=5)
        template_button = tk.Button(self, text="Manage Templates", command=self.manage_templates)
        template_button.grid(row=2, column=0, columnspan=4, padx=5, pady=5)
        
        # New button for downloading all configurations as ZIP
        download_zip_button = tk.Button(self, text="Download all configs as ZIP", command=self.download_all_configs)
        download_zip_button.grid(row=3, column=0, columnspan=4, padx=5, pady=5)
        
        # Bind click events in the Treeview
        self.tree.bind("<ButtonRelease-1>", self.on_treeview_click)

    def connect_to_router(self):
        # Use the LoginDialog to collect all login data in one window.
        login_dialog = LoginDialog(self, self.config_manager)
        if login_dialog.result is None:
            self.destroy()
            sys.exit(0)
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
            # Save login data (including password if chosen)
            login_data = {"host": host, "username": username, "port": port}
            if result.get("save_password"):
                login_data["password"] = password
            login_data["save_password"] = result.get("save_password")
            self.config_manager.set("login", login_data)
            self.config_manager.save()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
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
                    peer.get("client-listen-port", ""),
                    "⬇"
                )
                self.tree.insert("", "end", iid=tree_id, values=row_values)
                self.peers_data[tree_id] = peer
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_treeview_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region == "cell":
            col = self.tree.identify_column(event.x)
            if col == "#12":
                row_id = self.tree.identify_row(event.y)
                if row_id:
                    peer = self.peers_data.get(row_id)
                    if peer:
                        self.download_config(peer)
    
    def download_config(self, peer):
        # Use generate_config_text function to generate the configuration text.
        config_text = generate_config_text(peer)
        
        # Standard filename based on the peer name
        default_filename = "{}.conf".format(peer.get("name", "wireguard_peer").replace(" ", "_"))
        
        # Open the Save Dialog
        filename = filedialog.asksaveasfilename(
            title="Save Wireguard configuration file",
            defaultextension=".conf",
            initialfile=default_filename,
            filetypes=[("Configuration files", "*.conf"), ("All files", "*.*")]
        )
        
        if not filename:
            return  # User cancelled the dialog
        
        try:
            with open(filename, "w") as f:
                f.write(config_text)
            messagebox.showinfo("Download", f"Configuration file saved as '{filename}'.")
        except Exception as e:
            messagebox.showerror("Error", f"Configuration file could not be created: {e}")

    def download_all_configs(self):
        # In-memory stream for the ZIP archive
        zip_buffer = io.BytesIO()
        
        # Create the ZIP archive in write mode
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            # Iterate over all peers
            for peer_id, peer in self.peers_data.items():
                # Generate configuration text using generate_config_text function
                config_text = generate_config_text(peer)
                # Create a filename based on the peer name (replace spaces with underscores)
                peer_name = peer.get("name", "wireguard_peer").replace(" ", "_")
                filename = f"{peer_name}.conf"
                # Write the configuration file into the ZIP archive
                zip_file.writestr(filename, config_text)
        
        # Reset the buffer pointer to the beginning
        zip_buffer.seek(0)
        
        # Open a Save Dialog for saving the ZIP archive
        default_zipname = "wireguard_configs.zip"
        save_path = filedialog.asksaveasfilename(
            title="Save all Wireguard configuration files as ZIP",
            defaultextension=".zip",
            initialfile=default_zipname,
            filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")]
        )
        
        if not save_path:
            return  # User cancelled the dialog
        
        try:
            # Write the in-memory ZIP content to the file
            with open(save_path, "wb") as f:
                f.write(zip_buffer.read())
            messagebox.showinfo("Download", f"The ZIP file has been saved as '{save_path}'.")
        except Exception as e:
            messagebox.showerror("Error", f"The ZIP file could not be created: {e}")

    def add_peer(self):
        use_template = messagebox.askyesno("Use template?", "Do you want to use a template?")
        if use_template:
            templates = self.template_manager.get_templates()
            if not templates:
                messagebox.showinfo("No Templates", "No templates available.")
                return
            dialog = TemplateSelectionDialog(self, self.template_manager)
            selected_template = dialog.selected_template
            if selected_template:
                PeerEditor(self, self.router_connection, peer=templates[selected_template], callback=self.refresh_peers)
            else:
                messagebox.showwarning("Warning", "No template selected.")
        else:
            PeerEditor(self, self.router_connection, callback=self.refresh_peers)

    def get_selected_peer(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a peer.")
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
            if messagebox.askyesno("Confirm", "Really delete peer?"):
                try:
                    # Use "id" instead of ".id"
                    self.router_connection.delete_peer(peer.get("id"))
                    self.refresh_peers()
                except Exception as e:
                    messagebox.showerror("Error", str(e))

    def manage_templates(self):
        TemplateManagerUI(self, self.template_manager)

if __name__ == "__main__":
    app = WireguardManagerApp()
    app.mainloop()
