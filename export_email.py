#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
export_email.py - Exportador de correos electrónicos a PDF con verificación DKIM/ARC

Este script permite exportar correos electrónicos desde archivos .eml a PDF,
verificando su autenticidad usando check_email.py antes de la exportación.
"""

import argparse
import os
import sys
import subprocess
import email
from email import policy
from email.header import decode_header
from datetime import datetime, timezone, timedelta
from pathlib import Path
import io
import locale

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
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Flowable
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
            
            # Detectar si no hay firmas
            no_signatures = "Ninguna firma encontrada" in output or "No se encontraron cabeceras" in output
            
            # Extraer detalles de la verificación
            details = {
                "success": success,
                "method": None,
                "arc_found": False,
                "dkim_found": False,
                "no_signatures": no_signatures,
                "output": output,
                "failure_causes": []  # Nueva lista para causas de fallo
            }
            
            # Extraer causas específicas de fallo si está en modo verbose
            if not success and self.verbose and not no_signatures:
                # Buscar la sección "Causas específicas detectadas:" (con variaciones de encoding)
                causes_marker = None
                for marker in ["Causas específicas detectadas:", "Causas espec", "Causas detec"]:
                    if marker in output:
                        causes_marker = marker
                        break
                
                if causes_marker:
                    lines = output.split('\n')
                    in_causes_section = False
                    for line in lines:
                        if causes_marker in line:
                            in_causes_section = True
                            continue
                        if in_causes_section:
                            # Las causas empiezan con → (o su representación codificada)
                            stripped = line.strip()
                            if stripped and not stripped.startswith('='):
                                # Buscar el símbolo de flecha en diferentes encodings
                                arrow_chars = ['\u2192', 'â\u2020\u2019', 'Ã\u201cÃ¥æ']  # arrow symbol variants
                                has_arrow = any(arrow in line for arrow in arrow_chars)
                                
                                if has_arrow:
                                    # Extraer el texto después del símbolo
                                    cause = line.strip()
                                    # Remover diferentes variantes del símbolo de flecha
                                    for arrow in arrow_chars:
                                        if arrow in cause:
                                            cause = cause.split(arrow, 1)[-1].strip()
                                            break
                                    if cause:
                                        details["failure_causes"].append(cause)
                                elif stripped and in_causes_section:
                                    # Si no hay flecha pero hay contenido, terminó la sección
                                    break

            
            if not no_signatures:
                # Detectar qué firmas se encontraron basándose en diferentes formatos de salida
                encontradas_line = ""
                arc_headers_found = False
                dkim_headers_found = False
                
                for line in output.split('\n'):
                    # Formato sin verbose: "Encontradas: DKIM" o "Encontradas: ARC, DKIM"
                    if "Encontradas:" in line:
                        encontradas_line = line
                    # Formato verbose: "Cabeceras ARC-Seal encontradas:" o "Cabeceras DKIM-Signature encontradas:"
                    if "Cabeceras ARC" in line and "encontradas:" in line:
                        arc_headers_found = True
                    if "Cabeceras DKIM" in line and "encontradas:" in line:
                        dkim_headers_found = True
                
                # Detectar firmas de cualquiera de los dos formatos
                details["arc_found"] = "ARC" in encontradas_line or arc_headers_found
                details["dkim_found"] = "DKIM" in encontradas_line or dkim_headers_found
            
            if success:
                if "usando ARC" in output:
                    details["method"] = "ARC"
                elif "usando DKIM" in output:
                    details["method"] = "DKIM"
            
            return success, output, details
            
        except Exception as e:
            return False, f"Error al verificar: {str(e)}", {"success": False, "error": str(e)}


class EmailMarker(Flowable):
    """Flowable invisible para marcar el inicio de un email en el story"""
    def __init__(self, email_index, email_data):
        Flowable.__init__(self)
        self.email_index = email_index
        self.email_data = email_data
        self.width = 0
        self.height = 0
    
    def draw(self):
        # No dibuja nada, solo marca la posición
        pass


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
        
        # Estilos para texto citado (niveles 1-3)
        self.styles.add(ParagraphStyle(
            name='QuotedText1',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#000000'),
            leftIndent=20,
            spaceAfter=12,
            leading=14
        ))
        
        self.styles.add(ParagraphStyle(
            name='QuotedText2',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#000000'),
            leftIndent=40,
            spaceAfter=12,
            leading=14
        ))
        
        self.styles.add(ParagraphStyle(
            name='QuotedText3',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#000000'),
            leftIndent=60,
            spaceAfter=12,
            leading=14
        ))
        
        # Estilo para cabeceras citadas (indentadas con texto en negrita)
        self.styles.add(ParagraphStyle(
            name='QuotedHeader',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#000000'),
            leftIndent=20,
            spaceAfter=6,
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
        
        # Estilo para verificación omitida
        self.styles.add(ParagraphStyle(
            name='VerificationSkipped',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.blue,
            fontName='Helvetica-Bold'
        ))
    
    def _sanitize_text(self, text):
        """Sanitiza texto para headers escapando caracteres especiales para ReportLab"""
        if not text:
            return ""
        # Escapar caracteres especiales para XML/HTML en ReportLab
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        return text
    
    def _sanitize_body_text(self, text):
        """Sanitiza texto del cuerpo para evitar problemas con caracteres especiales en PDF"""
        if not text:
            return ""
        # Escapar caracteres especiales para XML/HTML en ReportLab
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        return text
    
    def _detect_quote_level(self, line):
        """Detecta el nivel de citado de una línea y si es una cabecera.
        Retorna: (quote_level, is_header)
        - quote_level: 0 = no citado, 1+ = niveles de citado
        - is_header: True si es una línea de cabecera citada (From:, To:, CC:, etc.)
        """
        import re
        
        stripped = line.lstrip()
        
        # Contar los > al inicio
        quote_count = 0
        for char in stripped:
            if char == '>':
                quote_count += 1
            elif char == ' ':
                continue
            else:
                break
        
        # Patrones de expresión regular para detectar líneas de respuesta/reenvío
        # "El ... escribió:" o "On ... wrote:"
        reply_patterns = [
            r'^El .+ escribi[oó]:',  # El 22/11/2024 escribió:
            r'^On .+ wrote:',         # On Mon, Nov 22, 2024 wrote:
        ]
        
        # Marcadores exactos de cabecera
        quote_markers = [
            'De: ', 'From: ', 'Sent: ', 'Enviado: ', 'Enviado el: ',
            'To: ', 'Para: ', 'CC: ', 'Cc: ', 'Subject: ', 'Asunto: ', 'Fecha: ', 'Date: ',
            '-----Original Message-----', '-----Mensaje original-----',
            '_____', '====='
        ]
        
        # Verificar patrones regex
        is_header = any(re.match(pattern, stripped, re.IGNORECASE) for pattern in reply_patterns)
        
        # Si no coincide con regex, verificar marcadores exactos
        if not is_header:
            is_header = any(stripped.startswith(marker) for marker in quote_markers)
        
        if is_header:
            # Si ya tiene >, mantener ese nivel, sino considerar como nivel 1
            return (max(quote_count, 1), True)
        
        return (quote_count, False)
    
    def _format_quoted_header(self, text):
        """Aplica formato en negrita a las palabras clave en cabeceras citadas.
        Se aplica después de sanitizar el texto."""
        import re
        
        # Palabras clave que deben estar en negrita (ya sanitizadas)
        keywords = [
            r'(De:)', r'(From:)', r'(Para:)', r'(To:)', r'(CC:)', r'(Cc:)',
            r'(Asunto:)', r'(Subject:)', r'(Fecha:)', r'(Date:)',
            r'(Enviado:)', r'(Enviado el:)', r'(Sent:)',
            r'(escribió:)', r'(escribi[oó]:)', r'(wrote:)',
            r'(-----Original Message-----)', r'(-----Mensaje original-----)'
        ]
        
        # Aplicar negrita a cada palabra clave encontrada
        formatted_text = text
        for keyword_pattern in keywords:
            formatted_text = re.sub(keyword_pattern, r'<b>\1</b>', formatted_text, flags=re.IGNORECASE)
        
        return formatted_text
    
    def _clean_email_display(self, email_str):
        """Asegura que la dirección de email siempre esté entre <>.
        Ejemplo: 'John Doe <john@example.com>' -> 'John Doe <john@example.com>'
                 'john@example.com' -> '<john@example.com>'
        """
        if not email_str:
            return ""
        
        # Si ya tiene formato "Name <email>", dejarlo como está
        if '<' in email_str and '>' in email_str:
            return email_str
        
        # Si es solo un email sin <>, agregarlo
        return f"<{email_str}>"
    
    def _decode_header(self, header_value):
        """Decodifica un header de email que puede estar codificado (RFC 2047)"""
        if not header_value:
            return "N/A"
        
        try:
            decoded_parts = []
            for part, encoding in decode_header(header_value):
                if isinstance(part, bytes):
                    # Si tiene encoding, usarlo; sino intentar utf-8, luego latin-1
                    if encoding:
                        try:
                            decoded_parts.append(part.decode(encoding))
                        except:
                            decoded_parts.append(part.decode('utf-8', errors='replace'))
                    else:
                        try:
                            decoded_parts.append(part.decode('utf-8', errors='replace'))
                        except:
                            decoded_parts.append(part.decode('latin-1', errors='replace'))
                else:
                    decoded_parts.append(str(part))
            return ' '.join(decoded_parts)
        except Exception as e:
            # Si falla la decodificación, retornar el valor original
            return str(header_value)
    
    def _format_date_spanish(self, date_string):
        """Convierte fecha de email a formato español con GMT-3"""
        if not date_string or date_string == 'N/A':
            return 'N/A'
        
        try:
            from email.utils import parsedate_to_datetime
            
            # Parsear la fecha del email
            dt = parsedate_to_datetime(date_string)
            
            # Convertir a GMT-3 (Argentina)
            gmt_minus_3 = timezone(timedelta(hours=-3))
            dt_local = dt.astimezone(gmt_minus_3)
            
            # Nombres de meses en español
            meses = [
                'enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio',
                'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre'
            ]
            
            # Formato: "22 de noviembre de 2025, 12:34 GMT-3"
            dia = dt_local.day
            mes = meses[dt_local.month - 1]
            anio = dt_local.year
            hora = dt_local.strftime('%H:%M')
            
            return f"{dia} de {mes} de {anio}, {hora} GMT-3"
            
        except Exception as e:
            # Si falla el parseo, devolver la fecha original
            return date_string
    
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
    
    def _get_attachments_info(self, msg):
        """Extrae información de los archivos adjuntos"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        # Decodificar el nombre del archivo si está codificado
                        filename = self._decode_header(filename)
                        
                        # Obtener el tamaño del contenido
                        try:
                            payload = part.get_payload(decode=True)
                            size = len(payload) if payload else 0
                            # Convertir a formato legible
                            if size < 1024:
                                size_str = f"{size} bytes"
                            elif size < 1024 * 1024:
                                size_str = f"{size / 1024:.1f} KB"
                            else:
                                size_str = f"{size / (1024 * 1024):.1f} MB"
                        except:
                            size_str = "Tamaño desconocido"
                        
                        # Obtener tipo de contenido
                        content_type = part.get_content_type()
                        
                        attachments.append({
                            'filename': filename,
                            'size': size_str,
                            'type': content_type
                        })
        
        return attachments
    
    def _create_page_template(self, canvas_obj, doc, email_num, total_emails, email_headers, email_page_num=1, total_email_pages=1, total_pages=None):
        """Crea el template de cada página con encabezado y pie"""
        canvas_obj.saveState()
        
        # Encabezado - Primera línea con 2 secciones alineadas
        y_header = doc.height + doc.topMargin + 0.5*inch
        canvas_obj.setFont('Helvetica-Bold', 9)
        
        # Título (izquierda)
        canvas_obj.drawString(inch, y_header, self.title)
        
        # Correo N de M (derecha)
        correo_text = f"Correo {email_num} de {total_emails}"
        canvas_obj.drawRightString(doc.width + inch, y_header, correo_text)
        
        # Encabezado - Segunda línea: De (izquierda) y Fecha (derecha)
        y_pos = doc.height + doc.topMargin + 0.3*inch
        canvas_obj.setFont('Helvetica', 7)
        canvas_obj.drawString(inch, y_pos, 
                            f"De: {email_headers.get('from', 'N/A')[:80]}")
        canvas_obj.drawRightString(doc.width + inch, y_pos, 
                            f"Fecha: {email_headers.get('date', 'N/A')}")
        
        # Tercera línea: Para
        y_pos -= 0.15*inch
        canvas_obj.drawString(inch, y_pos, 
                            f"Para: {email_headers.get('to', 'N/A')[:100]}")
        
        # Cuarta línea: Asunto
        y_pos -= 0.15*inch
        canvas_obj.drawString(inch, y_pos, 
                            f"Asunto: {email_headers.get('subject', 'N/A')[:100]}")
        
        # Línea separadora del encabezado
        y_pos -= 0.1*inch
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(inch, y_pos, doc.width + inch, y_pos)
        
        # Pie de página
        canvas_obj.setFont('Helvetica', 8)
        footer_text = f"{self.title} - Página {doc.page}"
        if total_pages:
            footer_text += f" de {total_pages}"
        
        # Línea separadora del pie de página
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(inch, 0.7*inch, doc.width + inch, 0.7*inch)
        
        canvas_obj.drawCentredString(doc.width/2 + inch, 0.5*inch, footer_text)
        
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
        # Headers sin sanitizar para el canvas (page header)
        raw_headers = {
            'from': self._decode_header(msg.get('From', 'N/A')),
            'to': self._decode_header(msg.get('To', 'N/A')),
            'cc': self._decode_header(msg.get('Cc', '')),
            'subject': self._decode_header(msg.get('Subject', 'N/A')),
            'date': self._format_date_spanish(msg.get('Date', 'N/A')),
            'message_id': msg.get('Message-ID', 'N/A')
        }
        
        # Headers sanitizados para Paragraphs (tabla)
        email_headers = {
            'from': self._sanitize_text(raw_headers['from']),
            'to': self._sanitize_text(raw_headers['to']),
            'cc': self._sanitize_text(raw_headers['cc']),
            'subject': self._sanitize_text(raw_headers['subject']),
            'date': self._sanitize_text(raw_headers['date']),
            'message_id': self._sanitize_text(raw_headers['message_id'])
        }
        
        body = self._get_email_body(msg)
        
        story = []
        
        # Título
        story.append(Paragraph(self.title, self.styles['CustomTitle']))
        story.append(Spacer(1, 0.3*inch))
        
        # Información de verificación
        if details.get('no_signatures'):
            verify_style = self.styles['VerificationSkipped']
            verify_text = "⊘ Verificación DKIM/ARC: OMITIDA - No hay firmas para verificar"
        else:
            verify_style = self.styles['VerificationSuccess'] if success else self.styles['VerificationFail']
            verify_text = f"{'✓' if success else '✗'} Verificación DKIM/ARC: {'EXITOSA' if success else 'FALLIDA'}"
            if details.get('method'):
                verify_text += f" (Método: {details['method']})"
        
        story.append(Paragraph(verify_text, verify_style))
        
        if not success and not details.get('no_signatures'):
            # Determinar qué verificaciones fallaron
            failed_methods = []
            if details.get('dkim_found'):
                failed_methods.append('DKIM')
            if details.get('arc_found'):
                failed_methods.append('ARC')
            
            methods_text = ' y '.join(failed_methods) if failed_methods else 'DKIM/ARC'
            warning_text = f"[!] ADVERTENCIA: La verificación {methods_text} falló. La autenticidad no está garantizada."
            
            story.append(Paragraph(
                warning_text,
                self.styles['VerificationFail']
            ))
            
            # Mostrar causas específicas del fallo si están disponibles
            failure_causes = details.get('failure_causes', [])
            if failure_causes:
                story.append(Spacer(1, 0.1*inch))
                story.append(Paragraph(
                    "<b>Causas del fallo detectadas:</b>",
                    self.styles['VerificationFail']
                ))
                for cause in failure_causes:
                    story.append(Paragraph(
                        f"  - {self._sanitize_text(cause)}",
                        self.styles['VerificationFail']
                    ))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Tabla con información del correo
        # Usar Paragraph para permitir word wrapping en celdas largas
        cell_style = ParagraphStyle(
            'TableCell',
            parent=self.styles['Normal'],
            fontSize=9,
            leading=11
        )
        
        data = [
            [Paragraph('<b>De:</b>', self.styles['Normal']), Paragraph(email_headers['from'], cell_style)],
            [Paragraph('<b>Para:</b>', self.styles['Normal']), Paragraph(email_headers['to'], cell_style)],
        ]
        
        # Solo agregar CC si existe
        if email_headers['cc']:
            data.append([Paragraph('<b>CC:</b>', self.styles['Normal']), Paragraph(email_headers['cc'], cell_style)])
        
        data.extend([
            [Paragraph('<b>Asunto:</b>', self.styles['Normal']), Paragraph(email_headers['subject'], cell_style)],
            [Paragraph('<b>Fecha:</b>', self.styles['Normal']), Paragraph(email_headers['date'], cell_style)],
            [Paragraph('<b>Message-ID:</b>', self.styles['Normal']), Paragraph(email_headers['message_id'], cell_style)]
        ])
        
        table = Table(data, colWidths=[1.2*inch, 5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.grey),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.3*inch))
        
        # Cuerpo del mensaje
        story.append(Paragraph("<b>Cuerpo del mensaje:</b>", self.styles['EmailHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        # Dividir el cuerpo en párrafos y detectar niveles de citado
        body_paragraphs = body.split('\n')
        for para in body_paragraphs:
            if para.strip():
                quote_level, is_header = self._detect_quote_level(para)
                
                # Remover los > del inicio para el texto mostrado
                display_text = para.lstrip()
                while display_text.startswith('>'):
                    display_text = display_text[1:].lstrip()
                
                # Sanitizar primero
                sanitized_para = self._sanitize_body_text(display_text)
                
                # Si es cabecera citada, aplicar formato en negrita a palabras clave (después de sanitizar)
                if is_header:
                    sanitized_para = self._format_quoted_header(sanitized_para)
                    style = self.styles['QuotedHeader']
                else:
                    # Seleccionar estilo según el nivel de citado
                    if quote_level == 0:
                        style = self.styles['EmailBody']
                    elif quote_level == 1:
                        style = self.styles['QuotedText1']
                    elif quote_level == 2:
                        style = self.styles['QuotedText2']
                    else:  # 3 o más
                        style = self.styles['QuotedText3']
                
                story.append(Paragraph(sanitized_para, style))
        
        # Archivos adjuntos
        attachments = self._get_attachments_info(msg)
        if attachments:
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph("<b>Archivos adjuntos:</b>", self.styles['EmailHeader']))
            story.append(Spacer(1, 0.1*inch))
            
            # Crear tabla con información de adjuntos
            attach_data = [['Nombre', 'Tamaño']]
            for att in attachments:
                attach_data.append([
                    self._sanitize_body_text(att['filename']),
                    att['size']
                ])
            
            attach_table = Table(attach_data, colWidths=[4.5*inch, 1.7*inch])
            attach_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(attach_table)
        
        # Construir PDF
        doc = SimpleDocTemplate(
            output_pdf,
            pagesize=letter,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=1.5*inch,
            bottomMargin=inch
        )
        
        def page_template(canvas_obj, doc_obj):
            # Para un solo correo, página actual = página del correo
            self._create_page_template(canvas_obj, doc_obj, 1, 1, raw_headers, doc_obj.page, doc_obj.page, None)
        
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
        
        story = []
        results = []
        included_results = []  # Solo los correos que se agregaron al PDF
        
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
            # Headers sin sanitizar para el canvas (page header)
            raw_headers = {
                'from': self._decode_header(msg.get('From', 'N/A')),
                'to': self._decode_header(msg.get('To', 'N/A')),
                'cc': self._decode_header(msg.get('Cc', '')),
                'subject': self._decode_header(msg.get('Subject', 'N/A')),
                'date': self._format_date_spanish(msg.get('Date', 'N/A')),
                'message_id': msg.get('Message-ID', 'N/A')
            }
            
            # Headers sanitizados para Paragraphs (tabla)
            email_headers = {
                'from': self._sanitize_text(raw_headers['from']),
                'to': self._sanitize_text(raw_headers['to']),
                'cc': self._sanitize_text(raw_headers['cc']),
                'subject': self._sanitize_text(raw_headers['subject']),
                'date': self._sanitize_text(raw_headers['date']),
                'message_id': self._sanitize_text(raw_headers['message_id'])
            }
            
            details['headers'] = email_headers
            details['raw_headers'] = raw_headers
            body = self._get_email_body(msg)
            
            # Agregar a la lista de correos incluidos en el PDF
            included_results.append(details)
            
            # Marcar el inicio de este email en el story ANTES del PageBreak
            # para que la primera página del nuevo email tenga el marcador correcto
            if len(included_results) > 1:
                # Agregar el marcador antes del page break
                story.append(EmailMarker(len(included_results) - 1, {'headers': email_headers, 'raw_headers': raw_headers}))
                story.append(PageBreak())
            else:
                # Para el primer email, solo agregamos el marcador
                story.append(EmailMarker(len(included_results) - 1, {'headers': email_headers, 'raw_headers': raw_headers}))
            
            # Número de correo
            story.append(Paragraph(
                f"Correo {len(included_results)} de {len(eml_files)}",
                self.styles['CustomTitle']
            ))
            story.append(Spacer(1, 0.2*inch))
            
            # Verificación
            if details.get('no_signatures'):
                verify_style = self.styles['VerificationSkipped']
                verify_text = "⊘ Verificación: OMITIDA - No hay firmas para verificar"
            else:
                verify_style = self.styles['VerificationSuccess'] if success else self.styles['VerificationFail']
                verify_text = f"{'✓' if success else '✗'} Verificación: {'EXITOSA' if success else 'FALLIDA'}"
                if details.get('method'):
                    verify_text += f" ({details['method']})"
            
            story.append(Paragraph(verify_text, verify_style))
            
            if not success and not details.get('no_signatures'):
                # Determinar qué verificaciones fallaron
                failed_methods = []
                if details.get('dkim_found'):
                    failed_methods.append('DKIM')
                if details.get('arc_found'):
                    failed_methods.append('ARC')
                
                methods_text = ' y '.join(failed_methods) if failed_methods else 'DKIM/ARC'
                warning_text = f"⚠ ADVERTENCIA: Verificación {methods_text} fallida"
                
                story.append(Paragraph(
                    warning_text,
                    self.styles['VerificationFail']
                ))
                
                # Mostrar causas específicas del fallo si están disponibles
                failure_causes = details.get('failure_causes', [])
                if failure_causes:
                    story.append(Spacer(1, 0.1*inch))
                    story.append(Paragraph(
                        "<b>Causas del fallo detectadas:</b>",
                        self.styles['VerificationFail']
                    ))
                    for cause in failure_causes:
                        story.append(Paragraph(
                            f"  - {self._sanitize_text(cause)}",
                            self.styles['VerificationFail']
                        ))
            
            story.append(Spacer(1, 0.2*inch))
            
            # Tabla con información
            # Usar Paragraph para permitir word wrapping en celdas largas
            cell_style = ParagraphStyle(
                'TableCell',
                parent=self.styles['Normal'],
                fontSize=9,
                leading=11
            )
            
            data = [
                [Paragraph('<b>De:</b>', self.styles['Normal']), Paragraph(email_headers['from'], cell_style)],
                [Paragraph('<b>Para:</b>', self.styles['Normal']), Paragraph(email_headers['to'], cell_style)],
            ]
            
            # Solo agregar CC si existe
            if email_headers['cc']:
                data.append([Paragraph('<b>CC:</b>', self.styles['Normal']), Paragraph(email_headers['cc'], cell_style)])
            
            data.extend([
                [Paragraph('<b>Asunto:</b>', self.styles['Normal']), Paragraph(email_headers['subject'], cell_style)],
                [Paragraph('<b>Fecha:</b>', self.styles['Normal']), Paragraph(email_headers['date'], cell_style)],
                [Paragraph('<b>Message-ID:</b>', self.styles['Normal']), Paragraph(email_headers['message_id'], cell_style)]
            ])
            
            table = Table(data, colWidths=[1.2*inch, 5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.grey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
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
                    quote_level, is_header = self._detect_quote_level(para)
                    
                    # Remover los > del inicio para el texto mostrado
                    display_text = para.lstrip()
                    while display_text.startswith('>'):
                        display_text = display_text[1:].lstrip()
                    
                    # Sanitizar primero
                    sanitized_para = self._sanitize_body_text(display_text)
                    
                    # Si es cabecera citada, aplicar formato en negrita a palabras clave (después de sanitizar)
                    if is_header:
                        sanitized_para = self._format_quoted_header(sanitized_para)
                        style = self.styles['QuotedHeader']
                    else:
                        # Seleccionar estilo según el nivel de citado
                        if quote_level == 0:
                            style = self.styles['EmailBody']
                        elif quote_level == 1:
                            style = self.styles['QuotedText1']
                        elif quote_level == 2:
                            style = self.styles['QuotedText2']
                        else:  # 3 o más
                            style = self.styles['QuotedText3']
                    
                    story.append(Paragraph(sanitized_para, style))
            
            # Archivos adjuntos
            attachments = self._get_attachments_info(msg)
            if attachments:
                story.append(Spacer(1, 0.2*inch))
                story.append(Paragraph("<b>Archivos adjuntos:</b>", self.styles['EmailHeader']))
                story.append(Spacer(1, 0.1*inch))
                
                # Crear tabla con información de adjuntos
                attach_data = [['Nombre', 'Tamaño']]
                for att in attachments:
                    attach_data.append([
                        self._sanitize_body_text(att['filename']),
                        att['size']
                    ])
                
                attach_table = Table(attach_data, colWidths=[4.5*inch, 1.7*inch])
                attach_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
                ]))
                story.append(attach_table)
            
            safe_print(f"✓ Correo agregado al lote")
        
        if not included_results:
            safe_print("\n✗ No se agregaron correos al lote")
            return []
        
        # Marcar cada correo con un atributo especial para rastrear cambios
        # Agregar marcadores especiales al story
        email_markers = []
        for i, item in enumerate(story):
            if item.__class__.__name__ == 'PageBreak':
                email_markers.append(i)
        
        # Crear el documento PDF
        doc = SimpleDocTemplate(
            output_pdf,
            pagesize=letter,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=1.5*inch,
            bottomMargin=inch
        )
        
        # Rastrear en qué correo estamos usando una estrategia más directa
        # Guardamos el índice del email actual que se actualiza cuando procesamos EmailMarker
        current_email = [0]  # Usamos lista para que sea mutable en el closure
        
        # Hook personalizado para EmailMarker
        original_EmailMarker_draw = EmailMarker.draw
        def tracked_draw(self):
            current_email[0] = self.email_index
            return original_EmailMarker_draw(self)
        
        # Parchear temporalmente el método draw
        EmailMarker.draw = tracked_draw
        
        def page_template(canvas_obj, doc_obj):
            # Usar el índice del email actual
            email_idx = min(current_email[0], len(included_results) - 1)
            
            if email_idx < len(included_results):
                headers = included_results[email_idx].get('headers', {})
                raw_headers = included_results[email_idx].get('raw_headers', headers)
                
                self._create_page_template(canvas_obj, doc_obj, email_idx + 1, len(included_results), 
                                         raw_headers, 1, 1, None)
        
        try:
            doc.build(story, onFirstPage=page_template, onLaterPages=page_template)
        finally:
            # Restaurar el método original
            EmailMarker.draw = original_EmailMarker_draw
        
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
            if result.get('no_signatures'):
                f.write(f"\nEstado: ⊘ OMITIDA - No hay firmas para verificar\n")
            else:
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


def get_email_date(eml_file):
    """Extrae la fecha de un archivo .eml para ordenamiento"""
    try:
        with open(eml_file, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        date_str = msg.get('Date')
        if date_str:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str)
    except:
        pass
    # Si falla, usar la fecha de modificación del archivo
    return datetime.fromtimestamp(eml_file.stat().st_mtime, tz=timezone.utc)


def main():
    parser = argparse.ArgumentParser(
        description="Exporta correos electrónicos (.eml) a PDF con verificación DKIM/ARC"
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
        eml_files = list(input_path.glob("*.eml"))
        if not eml_files:
            safe_print(f"✗ Error: No se encontraron archivos .eml en '{args.input}'")
            sys.exit(1)
        # Ordenar por fecha del email (más antiguos primero)
        eml_files = sorted(eml_files, key=get_email_date)
    
    print(f"Encontrados {len(eml_files)} archivo(s) .eml")
    
    # Crear exportador
    exporter = PDFEmailExporter(title=args.title, verbose=args.verbose)
    
    # Determinar archivos de salida
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Determinar directorio base (mismo que el input)
    if input_path.is_file():
        base_dir = input_path.parent
    else:
        base_dir = input_path
    
    if args.output:
        output_pdf = args.output
    else:
        if args.separate:
            output_pdf = None  # Se generará para cada archivo
        else:
            output_pdf = base_dir / f"emails_export_{timestamp}.pdf"
    
    log_file = args.log or str(base_dir / f"verification_log_{timestamp}.txt")
    
    # Exportar
    results = []
    
    if args.separate:
        # Exportar cada correo a un PDF separado
        for eml_file in eml_files:
            base_name = eml_file.stem
            pdf_path = base_dir / f"{base_name}_{timestamp}.pdf"
            success, details = exporter.export_single_email(
                eml_file,
                str(pdf_path),
                force_export=args.force
            )
            details['filename'] = eml_file.name
            results.append(details)
    else:
        # Exportar todos a un único PDF
        results = exporter.export_batch(
            eml_files,
            str(output_pdf),
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
