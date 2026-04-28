"""
gui_app.py - Modern GUI for Biometric Authentication System
"""

import tkinter as tk
from tkinter import messagebox, ttk
import cv2
from PIL import Image, ImageTk
import threading
import time

import config
import database
import authentication
import enrollment
import utils

class BiometricGUI:
    def __init__(self, window):
        self.window = window
        self.window.title("AeroGuard - Biometric Authentication")
        self.window.geometry("1100x700")
        self.window.configure(bg="#0f172a")  # Deep slate blue/black

        self.style = ttk.Style()
        self.style.theme_use('clam')

        # State
        self.is_scanning = True
        self.auth_active = False # Set to true when we want to actively scan
        self.cap = None
        self.current_frame = None
        
        # Load known encodings for speed
        try:
            self.known_encodings, self.known_ids = authentication.load_known_encodings()
        except:
            self.known_encodings, self.known_ids = [], []

        self._setup_ui()
        self._start_camera()

    def _setup_ui(self):
        # Header
        header = tk.Frame(self.window, bg="#1e293b", height=80)
        header.pack(fill="x")
        
        tk.Label(header, text="AeroGuard Biometrics", font=("Outfit", 26, "bold"), 
                 bg="#1e293b", fg="#38bdf8").pack(pady=20)

        # Main Layout
        main_container = tk.Frame(self.window, bg="#0f172a")
        main_container.pack(fill="both", expand=True, padx=20, pady=20)

        # Left Side: Camera
        self.cam_frame = tk.Frame(main_container, bg="#1e293b", bd=2, relief="solid")
        self.cam_frame.pack(side="left", fill="both", expand=True)

        self.cam_label = tk.Label(self.cam_frame, bg="black")
        self.cam_label.pack(fill="both", expand=True, padx=10, pady=10)

        self.status_bar = tk.Label(self.cam_frame, text="System Ready", font=("Inter", 14),
                                  bg="#0ea5e9", fg="white", height=2)
        self.status_bar.pack(fill="x")

        # Right Side: Controls
        nav_frame = tk.Frame(main_container, bg="#0f172a", width=300)
        nav_frame.pack(side="right", fill="y", padx=(20, 0))

        # Dashboard Stats (Pre-fetch)
        stats = database.get_statistics()
        
        self._create_stat_card(nav_frame, "Total Users", stats['get_total_users'] if 'get_total_users' in stats else stats.get('total_users', 0), "#0ea5e9")
        self._create_stat_card(nav_frame, "Today's Access", stats.get('today_total', 0), "#10b981")

        # Action Buttons
        btn_style = {"font": ("Inter", 12, "bold"), "height": 2, "width": 20, "cursor": "hand2", "bd": 0}
        
        tk.Button(nav_frame, text="START SCAN MODE", bg="#10b981", fg="white", 
                  command=self.toggle_auth, **btn_style).pack(pady=10)

        tk.Button(nav_frame, text="ENROLL NEW USER", bg="#38bdf8", fg="white", 
                  command=self.enrollment_wizard, **btn_style).pack(pady=10)
        
        tk.Button(nav_frame, text="VIEW LOGS", bg="#475569", fg="white", 
                  command=self.view_logs, **btn_style).pack(pady=10)
        
        tk.Button(nav_frame, text="ADMIN DASHBOARD", bg="#475569", fg="white", 
                  command=self.admin_panel, **btn_style).pack(pady=10)

    def _create_stat_card(self, parent, label, value, color):
        card = tk.Frame(parent, bg="#1e293b", padx=20, pady=15, bd=1, relief="solid")
        card.pack(fill="x", pady=10)
        tk.Label(card, text=label, font=("Inter", 10), bg="#1e293b", fg="#94a3b8").pack(anchor="w")
        tk.Label(card, text=str(value), font=("Inter", 24, "bold"), bg="#1e293b", fg=color).pack(anchor="w")

    def _start_camera(self):
        self.cap = cv2.VideoCapture(config.CAMERA_INDEX)
        self.is_scanning = True
        self._update_camera()

    def _update_camera(self):
        if not self.is_scanning: return
        
        ret, frame = self.cap.read()
        if ret:
            # Mirror for natural view
            frame = cv2.flip(frame, 1)
            display_frame = frame.copy()

            if self.auth_active:
                # Actual face recognition test
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                face_locations = []
                if authentication.FACE_RECOGNITION_AVAILABLE:
                    face_locations = authentication.face_recognition.face_locations(rgb)
                    encodings = authentication.face_recognition.face_encodings(rgb, face_locations)
                    
                    for (top, right, bottom, left), face_encoding in zip(face_locations, encodings):
                        name = "Unknown"
                        color = (0, 0, 255) # Red for unknown
                        
                        uid, conf = authentication.match_face(face_encoding, self.known_encodings, self.known_ids)
                        if uid:
                            user = database.get_user(uid)
                            name = user['name'] if user else "Authenticated"
                            color = (0, 255, 0) # Green for known
                            self.status_bar.configure(text=f"WELCOME: {name.upper()}", bg="#10b981")
                        
                        # Draw box on display
                        cv2.rectangle(display_frame, (left, top), (right, bottom), color, 2)
                        cv2.putText(display_frame, f"{name} ({int(conf*100)}%)", (left, top - 10), 
                                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)

            # Convert to PIL for Tkinter
            cv2image = cv2.cvtColor(display_frame, cv2.COLOR_BGR2RGBA)
            img = Image.fromarray(cv2image).resize((700, 500))
            imgtk = ImageTk.PhotoImage(image=img)
            self.cam_label.imgtk = imgtk
            self.cam_label.configure(image=imgtk)

        self.window.after(10, self._update_camera)

    def toggle_auth(self):
        self.auth_active = not self.auth_active
        btn_text = "SCANNING ACTIVE" if self.auth_active else "START SCAN MODE"
        color = "#f43f5e" if self.auth_active else "#10b981"
        self.status_bar.configure(text=btn_text, bg=color)

    def enrollment_wizard(self):
        # We launch the existing enrollment logic but wrapped in GUI feedback
        enrollment.interactive_enroll()
        messagebox.showinfo("Success", "Enrollment completed successfully!")

    def view_logs(self):
        # Import and show logs in a new window or CLI for now
        import access_log
        access_log.display_logs()

    def admin_panel(self):
        import admin
        admin.run_admin_dashboard()

if __name__ == "__main__":
    database.initialize_database()
    root = tk.Tk()
    app = BiometricGUI(root)
    root.mainloop()
