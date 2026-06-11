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
import re
import html as html_lib
from email import policy
from email.header import decode_header
from datetime import datetime, timezone, timedelta
from pathlib import Path
import io
import locale
import base64
import tempfile

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

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

try:
    from pypdf import PdfReader, PdfWriter
except ImportError:
    PdfReader = None
    PdfWriter = None


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
    
    def __init__(self, title="Correos Electrónicos", verbose=False, verify_emails=True):
        self.title = title
        self.verbose = verbose
        self.verify_emails = verify_emails
        self.verifier = EmailVerifier(verbose) if verify_emails else None
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

    def _html_to_text(self, html_content):
        """Convierte HTML a texto legible para el PDF."""
        if not html_content:
            return ""

        text = html_content
        # Eliminar bloques ocultos comunes en preheaders de emails masivos.
        text = re.sub(
            r'(?is)<([a-z0-9]+)[^>]*style=["\'][^"\']*(display\s*:\s*none|mso-hide\s*:\s*all|max-height\s*:\s*0)[^"\']*["\'][^>]*>.*?</\1>',
            ' ',
            text
        )
        # Quitar bloques que no aportan contenido visible.
        text = re.sub(r'(?is)<(script|style|head|title)[^>]*>.*?</\1>', ' ', text)
        # Preservar saltos de línea para etiquetas de bloque frecuentes.
        text = re.sub(r'(?i)<br\s*/?>', '\n', text)
        text = re.sub(r'(?i)</(p|div|tr|li|h1|h2|h3|h4|h5|h6)>', '\n', text)
        # Quitar etiquetas restantes.
        text = re.sub(r'(?s)<[^>]+>', ' ', text)
        # Convertir entidades HTML (&nbsp;, &amp;, etc.).
        text = html_lib.unescape(text)
        # Eliminar caracteres invisibles frecuentes en plantillas de email.
        text = re.sub(r'[\u200B-\u200F\u2060\uFEFF]', '', text)
        text = text.replace('\xa0', ' ')
        # Normalizar espacios y saltos.
        text = text.replace('\r\n', '\n').replace('\r', '\n')
        text = re.sub(r'[\t\f\v]+', ' ', text)
        text = re.sub(r'\n\s*\n\s*\n+', '\n\n', text)
        text = re.sub(r'[ ]{2,}', ' ', text)

        return text.strip()

    def _html_to_reportlab_markup(self, html_content):
        """Convierte HTML a markup simple compatible con ReportLab Paragraph."""
        if not html_content:
            return ""

        text = html_content

        # Eliminar bloques no visibles o no relevantes.
        text = re.sub(
            r'(?is)<([a-z0-9]+)[^>]*style=["\'][^"\']*(display\s*:\s*none|mso-hide\s*:\s*all|max-height\s*:\s*0)[^"\']*["\'][^>]*>.*?</\1>',
            ' ',
            text
        )
        text = re.sub(r'(?is)<!--.*?-->', ' ', text)
        text = re.sub(r'(?is)<(script|style|head|title)[^>]*>.*?</\1>', ' ', text)

        # Enlaces: mantener texto visible + URL para preservar información.
        def _link_replacer(match):
            url = html_lib.unescape(match.group(1) or '').strip()
            label = match.group(2) or ''
            label = re.sub(r'(?is)<[^>]+>', ' ', label)
            label = html_lib.unescape(label)
            label = re.sub(r'\s+', ' ', label).strip()
            if not label:
                label = url
            if url and url != label:
                return f"<u>{label}</u> ({url})"
            return f"<u>{label}</u>"

        text = re.sub(
            r'(?is)<a\b[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
            _link_replacer,
            text
        )

        # Normalizar etiquetas de formato compatibles.
        text = re.sub(r'(?is)<\s*strong\b[^>]*>', '<b>', text)
        text = re.sub(r'(?is)</\s*strong\s*>', '</b>', text)
        text = re.sub(r'(?is)<\s*em\b[^>]*>', '<i>', text)
        text = re.sub(r'(?is)</\s*em\s*>', '</i>', text)
        text = re.sub(r'(?is)<\s*b\b[^>]*>', '<b>', text)
        text = re.sub(r'(?is)</\s*b\s*>', '</b>', text)
        text = re.sub(r'(?is)<\s*i\b[^>]*>', '<i>', text)
        text = re.sub(r'(?is)</\s*i\s*>', '</i>', text)
        text = re.sub(r'(?is)<\s*u\b[^>]*>', '<u>', text)
        text = re.sub(r'(?is)</\s*u\s*>', '</u>', text)

        # Estructura de bloques.
        text = re.sub(r'(?is)<\s*br\b[^>]*>', '<br/>', text)
        text = re.sub(r'(?is)</\s*(p|div|tr|h1|h2|h3|h4|h5|h6)\s*>', '<br/><br/>', text)
        text = re.sub(r'(?is)<\s*li\b[^>]*>', '• ', text)
        text = re.sub(r'(?is)</\s*li\s*>', '<br/>', text)

        # Proteger etiquetas soportadas antes de eliminar el resto.
        placeholders = {}

        def _protect(match):
            token = f"__RL_TAG_{len(placeholders)}__"
            placeholders[token] = match.group(0)
            return token

        text = re.sub(r'(?is)</?(b|i|u)>|<br\s*/?>', _protect, text)

        # Remover etiquetas no soportadas conservando el texto.
        text = re.sub(r'(?is)<[^>]+>', ' ', text)

        # Decodificar entidades y normalizar espacios.
        text = html_lib.unescape(text)
        text = re.sub(r'[\u200B-\u200F\u2060\uFEFF]', '', text)
        text = text.replace('\xa0', ' ')
        text = text.replace('\r\n', '\n').replace('\r', '\n')
        text = re.sub(r'[\t\f\v]+', ' ', text)
        text = re.sub(r'\n\s*\n\s*\n+', '\n\n', text)
        text = re.sub(r' {2,}', ' ', text)

        # Escapar texto para ReportLab y restaurar etiquetas válidas.
        text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        for token, tag in placeholders.items():
            normalized_tag = tag
            if re.match(r'(?is)<br\s*/?>', tag):
                normalized_tag = '<br/>'
            else:
                normalized_tag = tag.lower()
            text = text.replace(token, normalized_tag)

        return text.strip()
    
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
        """Extrae el cuerpo del correo electrónico.

        Returns:
            tuple: (body: str, is_html: bool)
        """
        body = ""
        is_html = False
        
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
                            is_html = False
                            break
                    except Exception:
                        pass
                        
                elif content_type == "text/html" and not body and "attachment" not in content_disposition:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            html_body = payload.decode(charset, errors='replace')
                            body = self._html_to_reportlab_markup(html_body)
                            is_html = True
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    raw_body = payload.decode(charset, errors='replace')
                    if msg.get_content_type() == "text/html":
                        body = self._html_to_reportlab_markup(raw_body)
                        is_html = True
                    else:
                        body = raw_body
                        is_html = False
            except Exception:
                body = str(msg.get_payload())
                is_html = False
        
        body = body.strip() if body else "[No se pudo extraer el cuerpo del mensaje]"
        return body, is_html
    
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

    def _replace_cid_sources(self, html_body, cid_map):
        """Reemplaza referencias cid: por data URLs embebidas."""
        if not html_body or not cid_map:
            return html_body

        def _cid_replacer(match):
            quote = match.group(1)
            cid_value = match.group(2).strip().strip('<>')
            replacement = cid_map.get(cid_value)
            if replacement:
                return f"={quote}{replacement}{quote}"
            return match.group(0)

        return re.sub(r'=(["\'])cid:([^"\']+)\1', _cid_replacer, html_body, flags=re.IGNORECASE)

    def _extract_html_body_fragment(self, html_body):
        """Extrae solo el contenido de <body> si existe para evitar nesting HTML completo."""
        if not html_body:
            return html_body

        match = re.search(r'(?is)<body\b[^>]*>(.*?)</body>', html_body)
        if match:
            return match.group(1)
        return html_body

    def _extract_email_content(self, msg):
        """Extrae html/texto y adjuntos de un mensaje para renderizado en navegador."""
        html_body = None
        text_body = None
        cid_map = {}

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", "")).lower()
                payload = part.get_payload(decode=True)

                if payload is None:
                    continue

                charset = part.get_content_charset() or 'utf-8'

                if content_type == "text/html" and "attachment" not in content_disposition and html_body is None:
                    html_body = payload.decode(charset, errors='replace')
                elif content_type == "text/plain" and "attachment" not in content_disposition and text_body is None:
                    text_body = payload.decode(charset, errors='replace')

                content_id = (part.get("Content-ID") or "").strip().strip("<>")
                if content_id and content_type.startswith("image/"):
                    b64_data = base64.b64encode(payload).decode('ascii')
                    cid_map[content_id] = f"data:{content_type};base64,{b64_data}"
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                decoded = payload.decode(charset, errors='replace')
                if msg.get_content_type() == "text/html":
                    html_body = decoded
                else:
                    text_body = decoded

        if html_body:
            html_body = self._replace_cid_sources(html_body, cid_map)
            html_body = self._extract_html_body_fragment(html_body)

        return {
            "html": html_body,
            "text": text_body
        }

    def _build_email_section_html(self, raw_headers, details, success, body_html, body_text, attachments, email_num, total_emails):
        """Construye una sección HTML imprimible para un correo."""
        from_text = html_lib.escape(raw_headers.get('from', 'N/A'))
        to_text = html_lib.escape(raw_headers.get('to', 'N/A'))
        cc_text = html_lib.escape(raw_headers.get('cc', ''))
        subject_text = html_lib.escape(raw_headers.get('subject', 'N/A'))
        date_text = html_lib.escape(raw_headers.get('date', 'N/A'))
        message_id_text = html_lib.escape(raw_headers.get('message_id', 'N/A'))

        verification_html = ""
        if not details.get('verification_skipped'):
            if details.get('no_signatures'):
                verification_html = '<div class="verify verify-skip">Verificacion DKIM/ARC: omitida (sin firmas)</div>'
            else:
                verify_class = "verify-ok" if success else "verify-fail"
                verify_text = "EXITOSA" if success else "FALLIDA"
                method_text = f" ({html_lib.escape(details.get('method'))})" if details.get('method') else ""
                verification_html = f'<div class="verify {verify_class}">Verificacion DKIM/ARC: {verify_text}{method_text}</div>'

            if not success and not details.get('no_signatures'):
                causes = details.get('failure_causes', [])
                warning_html = '<div class="verify verify-fail">Advertencia: autenticidad no garantizada.</div>'
                if causes:
                    cause_items = ''.join([f'<li>{html_lib.escape(c)}</li>' for c in causes])
                    warning_html += f'<ul class="verify-causes">{cause_items}</ul>'
                verification_html += warning_html

        body_content_html = ""
        if body_html:
            body_content_html = body_html
        elif body_text:
            body_content_html = f"<pre>{html_lib.escape(body_text)}</pre>"
        else:
            body_content_html = "<p>[No se pudo extraer el cuerpo del mensaje]</p>"

        cc_row = ""
        if cc_text:
            cc_row = f"<tr><th>CC</th><td>{cc_text}</td></tr>"

        attachments_html = ""
        if attachments:
            rows = []
            for att in attachments:
                rows.append(
                    f"<tr><td>{html_lib.escape(att['filename'])}</td><td>{html_lib.escape(att['size'])}</td><td>{html_lib.escape(att.get('type', ''))}</td></tr>"
                )
            attachments_html = (
                "<h3>Archivos adjuntos</h3>"
                "<table class='attachments'><thead><tr><th>Nombre</th><th>Tamano</th><th>Tipo</th></tr></thead>"
                f"<tbody>{''.join(rows)}</tbody></table>"
            )

        return f"""
        <section class=\"email-section\">
          <div class=\"email-title\">Correo {email_num} de {total_emails}</div>
          {verification_html}
          <table class=\"meta\">
            <tr><th>De</th><td>{from_text}</td></tr>
            <tr><th>Para</th><td>{to_text}</td></tr>
            {cc_row}
            <tr><th>Asunto</th><td>{subject_text}</td></tr>
            <tr><th>Fecha</th><td>{date_text}</td></tr>
            <tr><th>Message-ID</th><td>{message_id_text}</td></tr>
          </table>
          <h3>Cuerpo del mensaje</h3>
          <div class=\"email-body\">{body_content_html}</div>
          {attachments_html}
        </section>
        """

    def _render_sections_to_pdf(self, sections_html, output_pdf, header_context=None):
        """Renderiza secciones HTML a PDF usando Playwright."""
        if sync_playwright is None:
            raise RuntimeError(
                "Playwright no esta instalado. Instale con: pip install playwright y luego ejecute: playwright install chromium"
            )

        header_context = header_context or {}
        escaped_title = html_lib.escape(self.title)
        escaped_from = html_lib.escape(header_context.get('from', 'N/A'))
        escaped_to = html_lib.escape(header_context.get('to', 'N/A'))
        escaped_subject = html_lib.escape(header_context.get('subject', 'N/A'))
        escaped_date = html_lib.escape(header_context.get('date', 'N/A'))
        escaped_email_label = html_lib.escape(header_context.get('email_label', ''))

        document_html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: Arial, Helvetica, sans-serif; font-size: 12px; color: #111; margin: 0; }}
    .email-section {{ page-break-after: always; padding: 0; margin: 0; }}
    .email-section:last-child {{ page-break-after: auto; }}
    .email-title {{ font-size: 17px; font-weight: 700; margin: 0 0 8px 0; }}
    .verify {{ margin: 0 0 8px 0; padding: 6px 8px; border-radius: 4px; font-weight: 700; }}
    .verify-ok {{ background: #edf7ed; color: #1f6f43; border: 1px solid #b7dfc2; }}
    .verify-fail {{ background: #fdecec; color: #a12622; border: 1px solid #f1bdbb; }}
    .verify-skip {{ background: #eef4ff; color: #1d4f91; border: 1px solid #bfd2f0; }}
    .verify-causes {{ margin: 6px 0 8px 18px; }}
    table {{ width: 100%; }}
    .meta, .attachments {{ border-collapse: collapse; margin-bottom: 10px; table-layout: fixed; }}
    .meta th, .meta td, .attachments th, .attachments td {{ border: 1px solid #d9d9d9; padding: 5px 7px; vertical-align: top; word-wrap: break-word; }}
    .meta th {{ width: 18%; background: #f1f1f1; text-align: left; }}
    .attachments th {{ background: #f1f1f1; text-align: left; }}
    h3 {{ margin: 8px 0 5px 0; font-size: 13px; }}
    .email-body {{ border: 1px solid #e1e1e1; padding: 8px; overflow-wrap: anywhere; }}
    .email-body pre {{ white-space: pre-wrap; margin: 0; font-family: Consolas, monospace; }}
    .email-body p {{ margin: 0 0 8px 0; }}
    .email-body table {{ margin-bottom: 8px; border-collapse: separate; }}
    .email-body th, .email-body td {{ border: none; padding: initial; }}
    .attachments th, .attachments td {{ font-size: 11px; }}
    img {{ max-width: 100% !important; height: auto !important; }}
  </style>
</head>
<body>
{sections_html}
</body>
</html>
"""

        with sync_playwright() as p:
            browser = p.chromium.launch()
            try:
                page = browser.new_page()
                page.set_content(document_html, wait_until="networkidle")

                header_template = f"""
                                <div style="font-family: Arial, Helvetica, sans-serif; width:100%; padding:0 14px 6px 14px; font-size:9px; color:#111;">
                                    <div style="display:flex; justify-content:space-between; align-items:flex-end; margin-bottom:4px;">
                                        <div style="font-weight:700; font-size:10px;">{escaped_title}</div>
                                        <div style="font-weight:700;">{escaped_email_label}</div>
                                    </div>
                                    <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
                                        <div>De: {escaped_from}</div>
                                        <div>Fecha: {escaped_date}</div>
                                    </div>
                                    <div style="margin-bottom:2px;">Para: {escaped_to}</div>
                                    <div>Asunto: {escaped_subject}</div>
                                    <div style="margin-top:5px; border-top:1px solid #777;"></div>
                </div>
                """

                footer_template = """
                                <div style="font-family: Arial, Helvetica, sans-serif; font-size:9px; width:100%; padding:0 14px; color:#111; text-align:center;">
                                    <div style="border-top:1px solid #777; margin-bottom:4px;"></div>
                                    <span>""" + escaped_title + """ - Página <span class=\"pageNumber\"></span></span>
                </div>
                """

                page.pdf(
                    path=output_pdf,
                    format="A4",
                    print_background=True,
                    display_header_footer=True,
                    header_template=header_template,
                    footer_template=footer_template,
                    margin={"top": "110px", "bottom": "48px", "left": "24px", "right": "24px"}
                )
            finally:
                browser.close()

    def _merge_pdf_files(self, input_pdf_paths, output_pdf):
        """Une múltiples PDFs en un único archivo de salida."""
        if not input_pdf_paths:
            raise RuntimeError("No hay PDFs para combinar.")

        if len(input_pdf_paths) == 1:
            with open(input_pdf_paths[0], 'rb') as src, open(output_pdf, 'wb') as dst:
                dst.write(src.read())
            return

        if PdfReader is None or PdfWriter is None:
            raise RuntimeError(
                "Se requiere pypdf para combinar múltiples PDFs. Instale con: pip install pypdf"
            )

        writer = PdfWriter()
        for pdf_path in input_pdf_paths:
            reader = PdfReader(pdf_path)
            for page in reader.pages:
                writer.add_page(page)

        with open(output_pdf, 'wb') as out_f:
            writer.write(out_f)
    
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
        
        # Verificar el correo (si está habilitado)
        if self.verify_emails:
            success, verify_output, details = self.verifier.verify_email(eml_file)
        else:
            success = True
            verify_output = ""
            details = {
                "success": True,
                "method": None,
                "arc_found": False,
                "dkim_found": False,
                "no_signatures": False,
                "output": "",
                "failure_causes": [],
                "verification_skipped": True
            }
        
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

        raw_headers = {
            'from': self._decode_header(msg.get('From', 'N/A')),
            'to': self._decode_header(msg.get('To', 'N/A')),
            'cc': self._decode_header(msg.get('Cc', '')),
            'subject': self._decode_header(msg.get('Subject', 'N/A')),
            'date': self._format_date_spanish(msg.get('Date', 'N/A')),
            'message_id': msg.get('Message-ID', 'N/A')
        }

        details['headers'] = {
            'from': self._sanitize_text(raw_headers['from']),
            'to': self._sanitize_text(raw_headers['to']),
            'cc': self._sanitize_text(raw_headers['cc']),
            'subject': self._sanitize_text(raw_headers['subject']),
            'date': self._sanitize_text(raw_headers['date']),
            'message_id': self._sanitize_text(raw_headers['message_id'])
        }

        content = self._extract_email_content(msg)
        attachments = self._get_attachments_info(msg)
        section_html = self._build_email_section_html(
            raw_headers,
            details,
            success,
            content.get('html'),
            content.get('text'),
            attachments,
            1,
            1
        )

        try:
            self._render_sections_to_pdf(
                section_html,
                output_pdf,
                header_context={
                    "from": raw_headers.get("from", "N/A"),
                    "to": raw_headers.get("to", "N/A"),
                    "subject": raw_headers.get("subject", "N/A"),
                    "date": raw_headers.get("date", "N/A"),
                    "email_label": "Correo 1 de 1",
                }
            )
        except Exception as e:
            safe_print(f"✗ Error al generar PDF con Playwright: {e}")
            return False, details
        
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
        
        section_entries = []
        results = []
        included_results = []
        
        for idx, eml_file in enumerate(eml_files, 1):
            print(f"\n[{idx}/{len(eml_files)}] {os.path.basename(eml_file)}")
            
            # Verificar el correo (si está habilitado)
            if self.verify_emails:
                success, verify_output, details = self.verifier.verify_email(eml_file)
            else:
                success = True
                verify_output = ""
                details = {
                    "success": True,
                    "method": None,
                    "arc_found": False,
                    "dkim_found": False,
                    "no_signatures": False,
                    "output": "",
                    "failure_causes": [],
                    "verification_skipped": True
                }
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
            content = self._extract_email_content(msg)
            attachments = self._get_attachments_info(msg)
            
            # Agregar a la lista de correos incluidos en el PDF
            included_results.append(details)
            section_html = self._build_email_section_html(
                raw_headers,
                details,
                success,
                content.get('html'),
                content.get('text'),
                attachments,
                len(included_results),
                len(eml_files)
            )
            section_entries.append({
                "html": section_html,
                "raw_headers": raw_headers,
                "email_index": len(included_results),
            })
            
            safe_print(f"✓ Correo agregado al lote")
        
        if not included_results:
            safe_print("\n✗ No se agregaron correos al lote")
            return []
        
        try:
            temp_pdf_paths = []
            with tempfile.TemporaryDirectory(prefix="export_email_") as tmp_dir:
                for entry in section_entries:
                    temp_pdf_path = os.path.join(tmp_dir, f"email_{entry['email_index']:04d}.pdf")
                    header_ref = entry.get("raw_headers", {})
                    self._render_sections_to_pdf(
                        entry["html"],
                        temp_pdf_path,
                        header_context={
                            "from": header_ref.get("from", "N/A"),
                            "to": header_ref.get("to", "N/A"),
                            "subject": header_ref.get("subject", "N/A"),
                            "date": header_ref.get("date", "N/A"),
                            "email_label": f"Correo {entry['email_index']} de {len(included_results)}",
                        }
                    )
                    temp_pdf_paths.append(temp_pdf_path)

                self._merge_pdf_files(temp_pdf_paths, output_pdf)
        except Exception as e:
            safe_print(f"✗ Error al generar PDF con Playwright: {e}")
            return []
        
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
            if result.get('verification_skipped'):
                f.write(f"\nEstado: ⊘ OMITIDA por parámetro --no-verify\n")
            elif result.get('no_signatures'):
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
        "--no-verify",
        action="store_true",
        help="Omite la verificación DKIM/ARC y exporta directamente"
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
    exporter = PDFEmailExporter(
        title=args.title,
        verbose=args.verbose,
        verify_emails=not args.no_verify
    )
    
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
