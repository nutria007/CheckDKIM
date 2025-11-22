#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
export_email.py - Exportador de correos electrónicos a PDF con verificación DKIM/ARC/SPF

Este script permite exportar correos electrónicos desde archivos .eml a PDF,
verificando su autenticidad usando check_email.py antes de la exportación.
"""

import argparse
import os
import sys
import subprocess
import email
from email import policy
from datetime import datetime
from pathlib import Path
import io

# Configurar la codificación de salida para manejar Unicode en Windows
if sys.platform == 'win32':
    import codecs
    if sys.stdout.encoding != 'utf-8':
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'replace')

def safe_print(*args, **kwargs):
    """Imprime de forma segura, reemplazando caracteres problemáticos si es necesario"""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        # Reemplazar caracteres Unicode problemáticos
        safe_args = []
        for arg in args:
            if isinstance(arg, str):
                arg = arg.replace('✓', '[OK]').replace('✗', '[X]').replace('⚠', '[!]')
            safe_args.append(arg)
        print(*safe_args, **kwargs)

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.pdfgen import canvas
except ImportError:
    print("Error: Se requiere la biblioteca 'reportlab' para generar PDFs.")
    print("Instálela usando: pip install reportlab")
    sys.exit(1)


class EmailVerifier:
    """Clase para verificar correos usando check_email.py"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.check_email_path = os.path.join(os.path.dirname(__file__), "check_email.py")
        
        if not os.path.exists(self.check_email_path):
            raise FileNotFoundError(f"No se encontró check_email.py en {self.check_email_path}")
    
    def verify_email(self, eml_file):
        """
        Verifica un archivo .eml usando check_email.py
        
        Returns:
            tuple: (success: bool, output: str, verification_details: dict)
        """
        try:
            cmd = [sys.executable, self.check_email_path]
            if self.verbose:
                cmd.append("-v")
            cmd.append(str(eml_file))
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'  # Replace problematic characters instead of failing
            )
            
            output = result.stdout
            success = "✓ SUCCESS" in output or "[OK] SUCCESS" in output
            
            # Extraer detalles de la verificación
            details = {
                "success": success,
                "method": None,
                "arc_found": "ARC" in output,
                "dkim_found": "DKIM" in output,
                "output": output
            }
            
            if success:
                if "usando ARC" in output:
                    details["method"] = "ARC"
                elif "usando DKIM" in output:
                    details["method"] = "DKIM"
            
            return success, output, details
            
        except Exception as e:
            return False, f"Error al verificar: {str(e)}", {"success": False, "error": str(e)}


class PDFEmailExporter:
    """Clase para exportar correos a PDF"""
    
    def __init__(self, title="Correos Electrónicos", verbose=False):
        self.title = title
        self.verbose = verbose
        self.verifier = EmailVerifier(verbose)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
    def _setup_custom_styles(self):
        """Configura estilos personalizados para el PDF"""
        # Estilo para el título principal
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=16,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=20,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Estilo para encabezados de correo
        self.styles.add(ParagraphStyle(
            name='EmailHeader',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        ))
        
        # Estilo para contenido de correo
        self.styles.add(ParagraphStyle(
            name='EmailBody',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#000000'),
            spaceAfter=12,
            leading=14
        ))
        
        # Estilo para verificación exitosa
        self.styles.add(ParagraphStyle(
            name='VerificationSuccess',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.green,
            fontName='Helvetica-Bold'
        ))
        
        # Estilo para verificación fallida
        self.styles.add(ParagraphStyle(
            name='VerificationFail',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.red,
            fontName='Helvetica-Bold'
        ))
    
    def _sanitize_text(self, text):
        """Sanitiza texto para evitar problemas con caracteres especiales en PDF"""
        if not text:
            return ""
        # Reemplazar caracteres problemáticos
        replacements = {
            '<': '&lt;',
            '>': '&gt;',
            '&': '&amp;',
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text
    
    def _get_email_body(self, msg):
        """Extrae el cuerpo del correo electrónico"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            body = payload.decode(charset, errors='replace')
                            break
                    except Exception:
                        pass
                        
                elif content_type == "text/html" and not body and "attachment" not in content_disposition:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            html_body = payload.decode(charset, errors='replace')
                            # Simplificar HTML (eliminar tags básicos)
                            import re
                            body = re.sub('<[^<]+?>', '', html_body)
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    body = payload.decode(charset, errors='replace')
            except Exception:
                body = str(msg.get_payload())
        
        return body.strip() if body else "[No se pudo extraer el cuerpo del mensaje]"
    
    def _create_page_template(self, canvas_obj, doc, email_num, total_emails, email_headers):
        """Crea el template de cada página con encabezado y pie"""
        canvas_obj.saveState()
        
        # Encabezado
        canvas_obj.setFont('Helvetica-Bold', 10)
        canvas_obj.drawString(inch, doc.height + doc.topMargin + 0.5*inch, self.title)
        
        canvas_obj.setFont('Helvetica', 8)
        canvas_obj.drawString(inch, doc.height + doc.topMargin + 0.3*inch, 
                            f"Correo {email_num} de {total_emails}")
        
        # Información del correo en el encabezado
        y_pos = doc.height + doc.topMargin + 0.1*inch
        canvas_obj.setFont('Helvetica', 7)
        canvas_obj.drawString(inch, y_pos, 
                            f"De: {email_headers.get('from', 'N/A')[:60]}")
        y_pos -= 0.15*inch
        canvas_obj.drawString(inch, y_pos, 
                            f"Asunto: {email_headers.get('subject', 'N/A')[:60]}")
        y_pos -= 0.15*inch
        canvas_obj.drawString(inch, y_pos, 
                            f"Fecha: {email_headers.get('date', 'N/A')}")
        
        # Pie de página
        canvas_obj.setFont('Helvetica', 8)
        canvas_obj.drawCentredString(doc.width/2 + inch, 0.5*inch, 
                                    f"Página {doc.page} - {self.title}")
        
        canvas_obj.restoreState()
    
    def export_single_email(self, eml_file, output_pdf, force_export=False):
        """
        Exporta un único correo electrónico a PDF
        
        Args:
            eml_file: Ruta al archivo .eml
            output_pdf: Ruta del PDF de salida
            force_export: Si es True, exporta incluso si falla la verificación
        """
        print(f"\nProcesando: {os.path.basename(eml_file)}")
        
        # Verificar el correo
        success, verify_output, details = self.verifier.verify_email(eml_file)
        
        if not success and not force_export:
            safe_print(f"⚠ Verificación fallida. Use --force para exportar de todos modos.")
            return False, details
        
        # Leer el correo
        try:
            with open(eml_file, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
        except Exception as e:
            safe_print(f"✗ Error al leer el archivo: {e}")
            return False, details
        
        # Extraer información del correo
        email_headers = {
            'from': self._sanitize_text(msg.get('From', 'N/A')),
            'to': self._sanitize_text(msg.get('To', 'N/A')),
            'subject': self._sanitize_text(msg.get('Subject', 'N/A')),
            'date': self._sanitize_text(msg.get('Date', 'N/A')),
            'message_id': self._sanitize_text(msg.get('Message-ID', 'N/A'))
        }
        
        body = self._get_email_body(msg)
        
        # Crear PDF
        doc = SimpleDocTemplate(
            output_pdf,
            pagesize=letter,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=1.5*inch,
            bottomMargin=inch
        )
        
        story = []
        
        # Título
        story.append(Paragraph(self.title, self.styles['CustomTitle']))
        story.append(Spacer(1, 0.3*inch))
        
        # Información de verificación
        verify_style = self.styles['VerificationSuccess'] if success else self.styles['VerificationFail']
        verify_text = f"{'✓' if success else '✗'} Verificación DKIM/ARC: {'EXITOSA' if success else 'FALLIDA'}"
        if details.get('method'):
            verify_text += f" (Método: {details['method']})"
        story.append(Paragraph(verify_text, verify_style))
        
        if not success:
            story.append(Paragraph(
                "⚠ ADVERTENCIA: Este correo no pudo ser verificado. La autenticidad no está garantizada.",
                self.styles['VerificationFail']
            ))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Tabla con información del correo
        data = [
            ['De:', email_headers['from']],
            ['Para:', email_headers['to']],
            ['Asunto:', email_headers['subject']],
            ['Fecha:', email_headers['date']],
            ['Message-ID:', email_headers['message_id']]
        ]
        
        table = Table(data, colWidths=[1.2*inch, 5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.grey),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.3*inch))
        
        # Cuerpo del mensaje
        story.append(Paragraph("<b>Cuerpo del mensaje:</b>", self.styles['EmailHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        # Dividir el cuerpo en párrafos
        body_paragraphs = body.split('\n')
        for para in body_paragraphs:
            if para.strip():
                sanitized_para = self._sanitize_text(para)
                story.append(Paragraph(sanitized_para, self.styles['EmailBody']))
        
        # Construir PDF
        def page_template(canvas_obj, doc):
            self._create_page_template(canvas_obj, doc, 1, 1, email_headers)
        
        doc.build(story, onFirstPage=page_template, onLaterPages=page_template)
        
        safe_print(f"✓ PDF generado: {output_pdf}")
        return True, details
    
    def export_batch(self, eml_files, output_pdf, force_export=False):
        """
        Exporta múltiples correos a un único PDF
        
        Args:
            eml_files: Lista de rutas a archivos .eml
            output_pdf: Ruta del PDF de salida
            force_export: Si es True, exporta incluso si falla la verificación
        """
        print(f"\nProcesando {len(eml_files)} correo(s)...")
        
        doc = SimpleDocTemplate(
            output_pdf,
            pagesize=letter,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=1.5*inch,
            bottomMargin=inch
        )
        
        story = []
        results = []
        
        for idx, eml_file in enumerate(eml_files, 1):
            print(f"\n[{idx}/{len(eml_files)}] {os.path.basename(eml_file)}")
            
            # Verificar el correo
            success, verify_output, details = self.verifier.verify_email(eml_file)
            details['filename'] = os.path.basename(eml_file)
            results.append(details)
            
            if not success and not force_export:
                safe_print(f"⚠ Verificación fallida. Omitiendo...")
                continue
            
            # Leer el correo
            try:
                with open(eml_file, 'rb') as f:
                    msg = email.message_from_binary_file(f, policy=policy.default)
            except Exception as e:
                safe_print(f"✗ Error al leer el archivo: {e}")
                details['error'] = str(e)
                continue
            
            # Extraer información
            email_headers = {
                'from': self._sanitize_text(msg.get('From', 'N/A')),
                'to': self._sanitize_text(msg.get('To', 'N/A')),
                'subject': self._sanitize_text(msg.get('Subject', 'N/A')),
                'date': self._sanitize_text(msg.get('Date', 'N/A')),
                'message_id': self._sanitize_text(msg.get('Message-ID', 'N/A'))
            }
            
            details['headers'] = email_headers
            body = self._get_email_body(msg)
            
            # Agregar contenido al PDF
            if idx > 1:
                story.append(PageBreak())
            
            # Número de correo
            story.append(Paragraph(
                f"Correo {idx} de {len(eml_files)}",
                self.styles['CustomTitle']
            ))
            story.append(Spacer(1, 0.2*inch))
            
            # Verificación
            verify_style = self.styles['VerificationSuccess'] if success else self.styles['VerificationFail']
            verify_text = f"{'✓' if success else '✗'} Verificación: {'EXITOSA' if success else 'FALLIDA'}"
            if details.get('method'):
                verify_text += f" ({details['method']})"
            story.append(Paragraph(verify_text, verify_style))
            
            if not success:
                story.append(Paragraph(
                    "⚠ ADVERTENCIA: Verificación fallida",
                    self.styles['VerificationFail']
                ))
            
            story.append(Spacer(1, 0.2*inch))
            
            # Tabla con información
            data = [
                ['De:', email_headers['from']],
                ['Para:', email_headers['to']],
                ['Asunto:', email_headers['subject']],
                ['Fecha:', email_headers['date']],
                ['Message-ID:', email_headers['message_id']]
            ]
            
            table = Table(data, colWidths=[1.2*inch, 5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.grey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            
            story.append(table)
            story.append(Spacer(1, 0.2*inch))
            
            # Cuerpo
            story.append(Paragraph("<b>Cuerpo del mensaje:</b>", self.styles['EmailHeader']))
            story.append(Spacer(1, 0.1*inch))
            
            body_paragraphs = body.split('\n')
            for para in body_paragraphs:
                if para.strip():
                    sanitized_para = self._sanitize_text(para)
                    story.append(Paragraph(sanitized_para, self.styles['EmailBody']))
            
            safe_print(f"✓ Correo agregado al lote")
        
        # Construir PDF
        email_num = [0]  # Usar lista para mutabilidad en closure
        
        def page_template(canvas_obj, doc):
            # Incrementar contador de correo al inicio de cada página
            if doc.page == 1 or story[doc.page - 1].__class__.__name__ == 'PageBreak':
                email_num[0] += 1
            
            headers = results[email_num[0] - 1].get('headers', {}) if email_num[0] <= len(results) else {}
            self._create_page_template(canvas_obj, doc, email_num[0], len(eml_files), headers)
        
        doc.build(story, onFirstPage=page_template, onLaterPages=page_template)
        
        safe_print(f"\n✓ PDF generado: {output_pdf}")
        return results


def save_verification_log(results, output_file, verbose=False):
    """Guarda los resultados de verificación en un archivo de texto"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("REGISTRO DE VERIFICACIÓN DE CORREOS ELECTRÓNICOS\n")
        f.write("=" * 80 + "\n")
        f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total de correos procesados: {len(results)}\n")
        f.write("=" * 80 + "\n\n")
        
        for idx, result in enumerate(results, 1):
            f.write(f"Correo #{idx}: {result.get('filename', 'N/A')}\n")
            f.write("-" * 80 + "\n")
            
            # Encabezados
            headers = result.get('headers', {})
            if headers:
                f.write(f"De: {headers.get('from', 'N/A')}\n")
                f.write(f"Para: {headers.get('to', 'N/A')}\n")
                f.write(f"Asunto: {headers.get('subject', 'N/A')}\n")
                f.write(f"Fecha: {headers.get('date', 'N/A')}\n")
                f.write(f"Message-ID: {headers.get('message_id', 'N/A')}\n")
            
            # Estado de verificación
            f.write(f"\nEstado: {'✓ EXITOSA' if result.get('success') else '✗ FALLIDA'}\n")
            
            if result.get('method'):
                f.write(f"Método: {result['method']}\n")
            
            if result.get('arc_found'):
                f.write("Firma ARC encontrada: Sí\n")
            if result.get('dkim_found'):
                f.write("Firma DKIM encontrada: Sí\n")
            
            if result.get('error'):
                f.write(f"Error: {result['error']}\n")
            
            # Salida completa en modo verbose
            if verbose and result.get('output'):
                f.write("\nSalida detallada de verificación:\n")
                f.write("-" * 40 + "\n")
                f.write(result['output'])
                f.write("\n" + "-" * 40 + "\n")
            
            f.write("\n" + "=" * 80 + "\n\n")


def main():
    parser = argparse.ArgumentParser(
        description="Exporta correos electrónicos (.eml) a PDF con verificación DKIM/ARC/SPF"
    )
    
    parser.add_argument(
        "input",
        help="Archivo .eml o carpeta con archivos .eml"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Archivo PDF de salida (por defecto: emails_export_[timestamp].pdf)"
    )
    
    parser.add_argument(
        "-t", "--title",
        default="Correos Electrónicos",
        help="Título para el encabezado del PDF"
    )
    
    parser.add_argument(
        "--separate",
        action="store_true",
        help="Genera un PDF separado para cada correo"
    )
    
    parser.add_argument(
        "--force",
        action="store_true",
        help="Exporta incluso si la verificación DKIM/ARC falla"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Incluye detalles adicionales en el registro"
    )
    
    parser.add_argument(
        "--log",
        help="Archivo de registro de verificación (por defecto: verification_log_[timestamp].txt)"
    )
    
    args = parser.parse_args()
    
    # Validar entrada
    input_path = Path(args.input)
    if not input_path.exists():
        safe_print(f"✗ Error: La ruta '{args.input}' no existe")
        sys.exit(1)
    
    # Obtener lista de archivos .eml
    if input_path.is_file():
        if input_path.suffix.lower() != '.eml':
            safe_print(f"✗ Error: El archivo debe tener extensión .eml")
            sys.exit(1)
        eml_files = [input_path]
    else:
        eml_files = sorted(input_path.glob("*.eml"))
        if not eml_files:
            safe_print(f"✗ Error: No se encontraron archivos .eml en '{args.input}'")
            sys.exit(1)
    
    print(f"Encontrados {len(eml_files)} archivo(s) .eml")
    
    # Crear exportador
    exporter = PDFEmailExporter(title=args.title, verbose=args.verbose)
    
    # Determinar archivos de salida
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if args.output:
        output_pdf = args.output
    else:
        if args.separate:
            output_pdf = None  # Se generará para cada archivo
        else:
            output_pdf = f"emails_export_{timestamp}.pdf"
    
    log_file = args.log or f"verification_log_{timestamp}.txt"
    
    # Exportar
    results = []
    
    if args.separate:
        # Exportar cada correo a un PDF separado
        for eml_file in eml_files:
            base_name = eml_file.stem
            pdf_name = f"{base_name}_{timestamp}.pdf"
            success, details = exporter.export_single_email(
                eml_file,
                pdf_name,
                force_export=args.force
            )
            details['filename'] = eml_file.name
            results.append(details)
    else:
        # Exportar todos a un único PDF
        results = exporter.export_batch(
            eml_files,
            output_pdf,
            force_export=args.force
        )
    
    # Guardar registro
    save_verification_log(results, log_file, verbose=args.verbose)
    safe_print(f"\n✓ Registro guardado: {log_file}")
    
    # Resumen
    successful = sum(1 for r in results if r.get('success'))
    print(f"\n{'=' * 60}")
    print(f"Resumen:")
    print(f"  Total procesados: {len(results)}")
    print(f"  Verificaciones exitosas: {successful}")
    print(f"  Verificaciones fallidas: {len(results) - successful}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
