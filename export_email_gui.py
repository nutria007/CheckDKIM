#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
export_email_gui.py - Interfaz gráfica para exportar correos a PDF

GUI en Tkinter para facilitar el uso de export_email.py
Incluye verificación DKIM/ARC/SPF de correos electrónicos
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import subprocess
import threading
from pathlib import Path
from datetime import datetime

# Configurar la codificación de salida para manejar Unicode en Windows
if sys.platform == 'win32':
    import codecs
    if sys.stdout.encoding != 'utf-8':
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'replace')

def safe_str(text):
    """Convierte texto con caracteres Unicode problemáticos a algo seguro para mostrar"""
    if isinstance(text, str):
        return text.replace('✓', '[OK]').replace('✗', '[X]').replace('⚠', '[!]')
    return text


class ExportEmailGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Export Email - Exportador de Correos a PDF con Verificación")
        self.root.geometry("800x700")
        self.root.resizable(True, True)
        
        # Variables
        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.title_text = tk.StringVar(value="Correos Electrónicos")
        self.log_path = tk.StringVar()
        self.separate_pdf = tk.BooleanVar(value=False)
        self.force_export = tk.BooleanVar(value=True)
        self.verbose_mode = tk.BooleanVar(value=True)
        self.no_verify_mode = tk.BooleanVar(value=False)
        self.processing = False
        
        # Verificar que export_email.py existe
        self.export_script = os.path.join(os.path.dirname(__file__), "export_email.py")
        if not os.path.exists(self.export_script):
            messagebox.showerror(
                "Error",
                f"No se encontró export_email.py en {os.path.dirname(__file__)}"
            )
            self.root.quit()
        
        self.setup_ui()
    
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Estilo
        style = ttk.Style()
        style.theme_use('clam')
        
        # Frame principal con padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        row = 0
        
        # Título
        title_label = ttk.Label(
            main_frame,
            text="Exportador de Correos a PDF con Verificación DKIM/ARC/SPF",
            font=('Helvetica', 14, 'bold')
        )
        title_label.grid(row=row, column=0, columnspan=3, pady=(0, 20))
        row += 1
        
        # Sección: Entrada
        ttk.Label(
            main_frame,
            text="Entrada:",
            font=('Helvetica', 10, 'bold')
        ).grid(row=row, column=0, columnspan=3, sticky=tk.W, pady=(10, 5))
        row += 1
        
        # Selección de archivo/carpeta
        ttk.Label(main_frame, text="Archivo o Carpeta:").grid(
            row=row, column=0, sticky=tk.W, pady=5
        )
        ttk.Entry(main_frame, textvariable=self.input_path, width=50).grid(
            row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=5
        )
        ttk.Button(main_frame, text="Examinar...", command=self.browse_input).grid(
            row=row, column=2, pady=5
        )
        row += 1
        
        # Ayuda para entrada
        help_text = ttk.Label(
            main_frame,
            text="Seleccione un archivo .eml o una carpeta con múltiples archivos .eml",
            font=('Helvetica', 8),
            foreground='gray'
        )
        help_text.grid(row=row, column=1, sticky=tk.W, pady=(0, 10))
        row += 1
        
        # Sección: Opciones
        ttk.Label(
            main_frame,
            text="Opciones:",
            font=('Helvetica', 10, 'bold')
        ).grid(row=row, column=0, columnspan=3, sticky=tk.W, pady=(10, 5))
        row += 1
        
        # Título del documento
        ttk.Label(main_frame, text="Título del documento:").grid(
            row=row, column=0, sticky=tk.W, pady=5
        )
        ttk.Entry(main_frame, textvariable=self.title_text, width=50).grid(
            row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=5
        )
        row += 1
        
        # Checkboxes de opciones
        options_frame = ttk.Frame(main_frame)
        options_frame.grid(row=row, column=1, sticky=tk.W, pady=10)
        
        ttk.Checkbutton(
            options_frame,
            text="Generar PDFs separados (uno por correo)",
            variable=self.separate_pdf,
            command=self.toggle_separate_mode
        ).grid(row=0, column=0, sticky=tk.W, pady=2)
        
        ttk.Checkbutton(
            options_frame,
            text="Forzar exportación (incluir correos no verificados)",
            variable=self.force_export
        ).grid(row=1, column=0, sticky=tk.W, pady=2)
        
        ttk.Checkbutton(
            options_frame,
            text="Modo verbose (registro detallado)",
            variable=self.verbose_mode
        ).grid(row=2, column=0, sticky=tk.W, pady=2)

        ttk.Checkbutton(
            options_frame,
            text="Omitir verificación DKIM/ARC (--no-verify)",
            variable=self.no_verify_mode
        ).grid(row=3, column=0, sticky=tk.W, pady=2)
        
        row += 1
        
        # Sección: Salida
        ttk.Label(
            main_frame,
            text="Salida:",
            font=('Helvetica', 10, 'bold')
        ).grid(row=row, column=0, columnspan=3, sticky=tk.W, pady=(10, 5))
        row += 1
        
        # Archivo PDF de salida
        ttk.Label(main_frame, text="Archivo PDF:").grid(
            row=row, column=0, sticky=tk.W, pady=5
        )
        self.output_entry = ttk.Entry(main_frame, textvariable=self.output_path, width=50)
        self.output_entry.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        self.output_button = ttk.Button(
            main_frame,
            text="Examinar...",
            command=self.browse_output
        )
        self.output_button.grid(row=row, column=2, pady=5)
        row += 1
        
        # Ayuda para salida
        self.output_help = ttk.Label(
            main_frame,
            text="Opcional. Si no se especifica, se genera automáticamente",
            font=('Helvetica', 8),
            foreground='gray'
        )
        self.output_help.grid(row=row, column=1, sticky=tk.W, pady=(0, 5))
        row += 1
        
        # Archivo de registro
        ttk.Label(main_frame, text="Archivo de registro:").grid(
            row=row, column=0, sticky=tk.W, pady=5
        )
        ttk.Entry(main_frame, textvariable=self.log_path, width=50).grid(
            row=row, column=1, sticky=(tk.W, tk.E), pady=5, padx=5
        )
        ttk.Button(main_frame, text="Examinar...", command=self.browse_log).grid(
            row=row, column=2, pady=5
        )
        row += 1
        
        # Ayuda para log
        ttk.Label(
            main_frame,
            text="Opcional. Si no se especifica, se genera automáticamente",
            font=('Helvetica', 8),
            foreground='gray'
        ).grid(row=row, column=1, sticky=tk.W, pady=(0, 10))
        row += 1
        
        # Separador
        ttk.Separator(main_frame, orient='horizontal').grid(
            row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10
        )
        row += 1
        
        # Botones de acción
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=row, column=0, columnspan=3, pady=10)
        
        self.export_button = ttk.Button(
            buttons_frame,
            text="Exportar a PDF",
            command=self.start_export,
            width=20
        )
        self.export_button.grid(row=0, column=0, padx=5)
        
        self.cancel_button = ttk.Button(
            buttons_frame,
            text="Cancelar",
            command=self.cancel_export,
            width=15,
            state='disabled'
        )
        self.cancel_button.grid(row=0, column=1, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Limpiar",
            command=self.clear_form,
            width=15
        ).grid(row=0, column=2, padx=5)
        
        row += 1
        
        # Barra de progreso
        self.progress = ttk.Progressbar(
            main_frame,
            mode='indeterminate',
            length=300
        )
        self.progress.grid(row=row, column=0, columnspan=3, pady=10, sticky=(tk.W, tk.E))
        row += 1
        
        # Área de salida/log
        ttk.Label(
            main_frame,
            text="Salida:",
            font=('Helvetica', 10, 'bold')
        ).grid(row=row, column=0, columnspan=3, sticky=tk.W, pady=(10, 5))
        row += 1
        
        # ScrolledText para mostrar salida
        self.output_text = scrolledtext.ScrolledText(
            main_frame,
            height=15,
            width=80,
            wrap=tk.WORD,
            font=('Courier', 9)
        )
        self.output_text.grid(
            row=row, column=0, columnspan=3,
            sticky=(tk.W, tk.E, tk.N, tk.S), pady=5
        )
        main_frame.rowconfigure(row, weight=1)
        row += 1
        
        # Barra de estado
        self.status_bar = ttk.Label(
            main_frame,
            text="Listo",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.grid(row=row, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
    
    def browse_input(self):
        """Abre diálogo para seleccionar archivo o carpeta"""
        # Preguntar si es archivo o carpeta
        choice = messagebox.askquestion(
            "Selección",
            "¿Desea seleccionar una carpeta?\n\n"
            "Sí = Carpeta con múltiples .eml\n"
            "No = Archivo .eml individual"
        )
        
        if choice == 'yes':
            path = filedialog.askdirectory(title="Seleccionar carpeta con archivos .eml")
        else:
            path = filedialog.askopenfilename(
                title="Seleccionar archivo .eml",
                filetypes=[("Email files", "*.eml"), ("All files", "*.*")]
            )
        
        if path:
            self.input_path.set(path)
            self.log_output(f"Entrada seleccionada: {path}\n")
    
    def browse_output(self):
        """Abre diálogo para seleccionar archivo PDF de salida"""
        path = filedialog.asksaveasfilename(
            title="Guardar PDF como",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        
        if path:
            self.output_path.set(path)
    
    def browse_log(self):
        """Abre diálogo para seleccionar archivo de registro"""
        path = filedialog.asksaveasfilename(
            title="Guardar registro como",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if path:
            self.log_path.set(path)
    
    def toggle_separate_mode(self):
        """Maneja el cambio de modo separado"""
        if self.separate_pdf.get():
            # Deshabilitar selección de archivo de salida en modo separado
            self.output_entry.config(state='disabled')
            self.output_button.config(state='disabled')
            self.output_path.set("")
            self.output_help.config(text="Se generará un PDF por cada archivo .eml")
        else:
            # Habilitar selección de archivo de salida
            self.output_entry.config(state='normal')
            self.output_button.config(state='normal')
            self.output_help.config(text="Opcional. Si no se especifica, se genera automáticamente")
    
    def clear_form(self):
        """Limpia el formulario"""
        self.input_path.set("")
        self.output_path.set("")
        self.title_text.set("Correos Electrónicos")
        self.log_path.set("")
        self.separate_pdf.set(False)
        self.force_export.set(False)
        self.verbose_mode.set(False)
        self.no_verify_mode.set(False)
        self.output_text.delete(1.0, tk.END)
        self.status_bar.config(text="Listo")
        self.toggle_separate_mode()
    
    def log_output(self, text):
        """Agrega texto al área de salida"""
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.root.update()
    
    def update_status(self, text):
        """Actualiza la barra de estado"""
        self.status_bar.config(text=text)
        self.root.update()
    
    def validate_input(self):
        """Valida los datos de entrada"""
        if not self.input_path.get():
            messagebox.showerror("Error", "Debe seleccionar un archivo o carpeta de entrada")
            return False
        
        input_path = Path(self.input_path.get())
        if not input_path.exists():
            messagebox.showerror("Error", "La ruta de entrada no existe")
            return False
        
        # Validar que hay archivos .eml
        if input_path.is_file():
            if input_path.suffix.lower() != '.eml':
                messagebox.showerror("Error", "El archivo debe tener extensión .eml")
                return False
        else:
            eml_files = list(input_path.glob("*.eml"))
            if not eml_files:
                messagebox.showerror("Error", "No se encontraron archivos .eml en la carpeta")
                return False
        
        return True
    
    def start_export(self):
        """Inicia el proceso de exportación"""
        if not self.validate_input():
            return
        
        if self.processing:
            messagebox.showwarning("Advertencia", "Ya hay un proceso en ejecución")
            return
        
        # Confirmar si hay muchos archivos
        input_path = Path(self.input_path.get())
        if input_path.is_dir():
            eml_count = len(list(input_path.glob("*.eml")))
            if eml_count > 50:
                if not messagebox.askyesno(
                    "Confirmación",
                    f"Se van a procesar {eml_count} archivos .eml.\n"
                    "Esto puede tomar varios minutos.\n\n"
                    "¿Desea continuar?"
                ):
                    return
        
        # Iniciar en thread separado
        self.processing = True
        self.export_button.config(state='disabled')
        self.cancel_button.config(state='normal')
        self.progress.start()
        self.output_text.delete(1.0, tk.END)
        
        thread = threading.Thread(target=self.run_export)
        thread.daemon = True
        thread.start()
    
    def run_export(self):
        """Ejecuta el script de exportación"""
        try:
            self.update_status("Procesando...")
            self.log_output(f"Iniciando exportación...\n")
            self.log_output(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.log_output("=" * 60 + "\n\n")
            
            # Construir comando
            cmd = [sys.executable, self.export_script, self.input_path.get()]
            
            if self.output_path.get():
                cmd.extend(["-o", self.output_path.get()])
            
            if self.title_text.get():
                cmd.extend(["-t", self.title_text.get()])
            
            if self.log_path.get():
                cmd.extend(["--log", self.log_path.get()])
            
            if self.separate_pdf.get():
                cmd.append("--separate")
            
            if self.force_export.get():
                cmd.append("--force")

            if self.no_verify_mode.get():
                cmd.append("--no-verify")
            
            if self.verbose_mode.get():
                cmd.append("-v")
            
            self.log_output(f"Comando: {' '.join(cmd)}\n\n")
            
            # Ejecutar
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',  # Replace problematic characters
                bufsize=1,
                universal_newlines=True
            )
            
            # Leer salida en tiempo real
            for line in iter(process.stdout.readline, ''):
                if not self.processing:  # Cancelado
                    process.terminate()
                    break
                self.log_output(line)
            
            process.wait()
            
            if process.returncode == 0:
                self.update_status("Exportación completada exitosamente")
                self.log_output("\n" + "=" * 60 + "\n")
                self.log_output("✓ Exportación completada exitosamente\n")
                messagebox.showinfo(
                    "Éxito",
                    "La exportación se completó exitosamente.\n"
                    "Revise el área de salida para más detalles."
                )
            else:
                self.update_status("Error en la exportación")
                self.log_output("\n" + "=" * 60 + "\n")
                self.log_output("✗ Error en la exportación\n")
                messagebox.showerror(
                    "Error",
                    "Hubo un error durante la exportación.\n"
                    "Revise el área de salida para más detalles."
                )
        
        except Exception as e:
            self.update_status("Error")
            self.log_output(f"\n✗ Error: {str(e)}\n")
            messagebox.showerror("Error", f"Error al ejecutar la exportación:\n{str(e)}")
        
        finally:
            self.processing = False
            self.export_button.config(state='normal')
            self.cancel_button.config(state='disabled')
            self.progress.stop()
    
    def cancel_export(self):
        """Cancela el proceso de exportación"""
        if messagebox.askyesno("Cancelar", "¿Desea cancelar el proceso?"):
            self.processing = False
            self.update_status("Cancelado por el usuario")
            self.log_output("\n⚠ Proceso cancelado por el usuario\n")


def main():
    root = tk.Tk()
    app = ExportEmailGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
