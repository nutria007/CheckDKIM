#!/usr/bin/env python3
"""
Analyze verification log files to gather statistics on DKIM/ARC failures.
"""

import os
import re
import email
from email import policy
from collections import defaultdict, Counter
from datetime import datetime

def analyze_log_file(filepath):
    """Parse a single log file and extract relevant information."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    # Split into individual email entries by the separator line
    entries = re.split(r'-{50,}', content)
    
    results = []
    for entry in entries:
        if not entry.strip() or 'REGISTRO DE VERIFICACIÓN' in entry:
            continue
        
        data = {
            'dkim_status': None,
            'arc_status': None,
            'dkim_found': False,
            'arc_found': False,
            'failure_causes': [],
            'from_domain': None,
            'to_domain': None,
            'filename': None,
            'verification_status': None,
            'verification_method': None,
            'date': None,
            'has_attachments': False,
            'attachment_count': 0
        }
        
        # Extract email filename (Correo #N: filename)
        filename_match = re.search(r'Correo #\d+: (.+\.eml)', entry)
        if filename_match:
            data['filename'] = filename_match.group(1)
        
        # Extract From domain
        from_match = re.search(r'De: .+?<.+?@([^\s>]+)>', entry)
        if not from_match:
            from_match = re.search(r'From: .+?<.+?@([^\s>]+)>', entry)
        if from_match:
            data['from_domain'] = from_match.group(1)
        
        # Extract To domain
        to_match = re.search(r'Para: .+?<.+?@([^\s>]+)>', entry)
        if not to_match:
            to_match = re.search(r'To: .+?<.+?@([^\s>]+)>', entry)
        if to_match:
            data['to_domain'] = to_match.group(1)
        
        # Extract date
        date_match = re.search(r'Fecha: (.+?)\n', entry)
        if date_match:
            data['date'] = date_match.group(1).strip()
        
        # Check for attachments
        # Look for attachment indicators in the detailed output
        if 'Content-Disposition: attachment' in entry:
            data['has_attachments'] = True
            # Try to count attachments
            attachment_matches = re.findall(r'Content-Disposition: attachment', entry)
            data['attachment_count'] = len(attachment_matches)
        elif re.search(r'Archivos adjuntos?:', entry):
            data['has_attachments'] = True
            # Try to extract count
            attach_count_match = re.search(r'Archivos? adjuntos?: (\d+)', entry)
            if attach_count_match:
                data['attachment_count'] = int(attach_count_match.group(1))
        
        # Try to extract file path to check the .eml file directly
        filepath_match = re.search(r'Archivo: (.+\.eml)', entry)
        if filepath_match and not data['has_attachments']:
            eml_path = filepath_match.group(1).strip()
            if os.path.exists(eml_path):
                try:
                    with open(eml_path, 'rb') as f:
                        msg = email.message_from_binary_file(f, policy=policy.default)
                        attachment_count = 0
                        for part in msg.walk():
                            if part.get_content_disposition() == 'attachment':
                                attachment_count += 1
                        if attachment_count > 0:
                            data['has_attachments'] = True
                            data['attachment_count'] = attachment_count
                except Exception:
                    pass  # If we can't read the file, leave attachments as unknown
        
        # Check overall verification status (Estado:)
        status_match = re.search(r'Estado: (?:✓|✗|⊘)\s*(\w+)', entry)
        if status_match:
            data['verification_status'] = status_match.group(1).lower()
        
        # Extract verification method (Método:)
        method_match = re.search(r'Método: (\w+)', entry)
        if method_match:
            data['verification_method'] = method_match.group(1).upper()
        
        # Check for DKIM signature presence
        if 'Firma DKIM encontrada: Sí' in entry:
            data['dkim_found'] = True
        
        # Check for ARC signature presence
        if 'Firma ARC encontrada: Sí' in entry:
            data['arc_found'] = True
        
        # Determine DKIM/ARC status from detailed output
        # Look for specific result patterns
        if 'DKIM verification failed' in entry or 'signature verification failed' in entry:
            data['dkim_status'] = 'fallida'
        elif 'El correo ha sido verificado exitosamente usando DKIM' in entry:
            data['dkim_status'] = 'exitosa'
        
        if 'ARC verification failed' in entry or 'broken chain' in entry:
            data['arc_status'] = 'fallida'
        elif 'El correo ha sido verificado exitosamente usando ARC' in entry:
            data['arc_status'] = 'exitosa'
        
        # If method is specified and status is exitosa, set that specific status
        if data['verification_method'] == 'DKIM' and data['verification_status'] == 'exitosa':
            data['dkim_status'] = 'exitosa'
        elif data['verification_method'] == 'ARC' and data['verification_status'] == 'exitosa':
            data['arc_status'] = 'exitosa'
        
        # If both signatures found and status is FALLIDA, both failed
        if data['verification_status'] == 'fallida':
            if data['dkim_found']:
                data['dkim_status'] = 'fallida'
            if data['arc_found']:
                data['arc_status'] = 'fallida'
        
        # Extract failure causes
        causes_section = re.search(r'Causas del fallo:(.+?)(?:\n\n|\nSalida detallada|\Z)', entry, re.DOTALL)
        if causes_section:
            # Look for bullet points or specific error messages
            causes = re.findall(r'[•\-→]\s*(.+)', causes_section.group(1))
            data['failure_causes'] = [c.strip() for c in causes if c.strip()]
        
        # Also check for specific error patterns in the detailed output
        if not data['failure_causes']:
            error_patterns = [
                (r'body hash mismatch', 'Body hash mismatch'),
                (r'signature verification failed', 'Signature verification failed'),
                (r'signature is expired', 'Firma expirada'),
                (r'broken chain', 'Cadena ARC rota'),
                (r'DNS query timeout', 'DNS timeout'),
                (r'DKIM public key', 'Problema con clave pública DKIM'),
            ]
            for pattern, description in error_patterns:
                if re.search(pattern, entry, re.IGNORECASE):
                    data['failure_causes'].append(description)
        
        if data['filename']:  # Only add if we found an email entry
            results.append(data)
    
    return results

def generate_statistics(all_results):
    """Generate comprehensive statistics from all log results."""
    stats = {
        'total_emails': len(all_results),
        'dkim_present': 0,
        'arc_present': 0,
        'both_present': 0,
        'neither_present': 0,
        'dkim_pass': 0,
        'dkim_fail': 0,
        'arc_pass': 0,
        'arc_fail': 0,
        'failure_causes': Counter(),
        'domains': Counter(),
        'to_domains': Counter(),
        'failure_by_domain': defaultdict(lambda: {'count': 0, 'causes': Counter()}),
        'failure_by_to_domain': defaultdict(lambda: {'count': 0, 'dkim_fail': 0, 'arc_fail': 0}),
        'dkim_only_fail': 0,
        'arc_only_fail': 0,
        'both_fail': 0,
        'arc_fail_implies_dkim_fail': 0,
        'arc_fail_total': 0,
        'failure_dates': [],
        'correlation_data': [],
        'emails_with_attachments': 0,
        'emails_without_attachments': 0,
        'fail_with_attachments': 0,
        'fail_without_attachments': 0,
        'pass_with_attachments': 0,
        'pass_without_attachments': 0,
    }
    
    for result in all_results:
        # Count signature presence
        if result['dkim_found'] and result['arc_found']:
            stats['both_present'] += 1
        elif result['dkim_found']:
            stats['dkim_present'] += 1
        elif result['arc_found']:
            stats['arc_present'] += 1
        else:
            stats['neither_present'] += 1
        
        # Count DKIM results
        if result['dkim_status'] == 'exitosa':
            stats['dkim_pass'] += 1
        elif result['dkim_status'] == 'fallida':
            stats['dkim_fail'] += 1
        
        # Count ARC results
        if result['arc_status'] == 'exitosa':
            stats['arc_pass'] += 1
        elif result['arc_status'] == 'fallida':
            stats['arc_fail'] += 1
        
        # Track failures by type
        dkim_failed = result['dkim_status'] == 'fallida'
        arc_failed = result['arc_status'] == 'fallida'
        
        if dkim_failed and arc_failed:
            stats['both_fail'] += 1
        elif dkim_failed:
            stats['dkim_only_fail'] += 1
        elif arc_failed:
            stats['arc_only_fail'] += 1
        
        # Collect failure causes
        for cause in result['failure_causes']:
            stats['failure_causes'][cause] += 1
            
            # Associate causes with domains
            if result['from_domain']:
                stats['failure_by_domain'][result['from_domain']]['count'] += 1
                stats['failure_by_domain'][result['from_domain']]['causes'][cause] += 1
        
        # Count domains
        if result['from_domain']:
            stats['domains'][result['from_domain']] += 1
        
        if result['to_domain']:
            stats['to_domains'][result['to_domain']] += 1
            
            # Track failures by recipient domain
            if dkim_failed or arc_failed:
                stats['failure_by_to_domain'][result['to_domain']]['count'] += 1
                if dkim_failed:
                    stats['failure_by_to_domain'][result['to_domain']]['dkim_fail'] += 1
                if arc_failed:
                    stats['failure_by_to_domain'][result['to_domain']]['arc_fail'] += 1
        
        # Track correlation: when ARC fails, does DKIM also fail?
        if arc_failed:
            stats['arc_fail_total'] += 1
            if dkim_failed:
                stats['arc_fail_implies_dkim_fail'] += 1
        
        # Store correlation data for detailed analysis
        if dkim_failed or arc_failed:
            stats['correlation_data'].append({
                'filename': result['filename'],
                'date': result['date'],
                'from_domain': result['from_domain'],
                'to_domain': result['to_domain'],
                'dkim_failed': dkim_failed,
                'arc_failed': arc_failed,
                'causes': result['failure_causes'],
                'has_attachments': result['has_attachments'],
                'attachment_count': result['attachment_count']
            })
            stats['failure_dates'].append(result['date'])
        
        # Track attachment statistics
        has_any_failure = dkim_failed or arc_failed
        has_any_success = (result['dkim_status'] == 'exitosa' or result['arc_status'] == 'exitosa')
        
        if result['has_attachments']:
            stats['emails_with_attachments'] += 1
            if has_any_failure:
                stats['fail_with_attachments'] += 1
            if has_any_success:
                stats['pass_with_attachments'] += 1
        else:
            stats['emails_without_attachments'] += 1
            if has_any_failure:
                stats['fail_without_attachments'] += 1
            if has_any_success:
                stats['pass_without_attachments'] += 1
    
    return stats

def write_markdown_report(stats, output_file):
    """Write statistics to a markdown file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Análisis de Logs de Verificación DKIM/ARC\n\n")
        f.write(f"**Fecha del análisis:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Overview
        f.write("## Resumen General\n\n")
        f.write(f"- **Total de correos analizados:** {stats['total_emails']}\n")
        f.write(f"- **Correos con firma DKIM solamente:** {stats['dkim_present']}\n")
        f.write(f"- **Correos con firma ARC solamente:** {stats['arc_present']}\n")
        f.write(f"- **Correos con ambas firmas (DKIM + ARC):** {stats['both_present']}\n")
        f.write(f"- **Correos sin firmas:** {stats['neither_present']}\n\n")
        
        # DKIM Results
        f.write("## Resultados de Verificación DKIM\n\n")
        total_dkim = stats['dkim_pass'] + stats['dkim_fail']
        if total_dkim > 0:
            f.write(f"- **Verificaciones exitosas:** {stats['dkim_pass']} ({stats['dkim_pass']*100/total_dkim:.1f}%)\n")
            f.write(f"- **Verificaciones fallidas:** {stats['dkim_fail']} ({stats['dkim_fail']*100/total_dkim:.1f}%)\n")
        else:
            f.write("- No se encontraron verificaciones DKIM\n")
        f.write("\n")
        
        # ARC Results
        f.write("## Resultados de Verificación ARC\n\n")
        total_arc = stats['arc_pass'] + stats['arc_fail']
        if total_arc > 0:
            f.write(f"- **Verificaciones exitosas:** {stats['arc_pass']} ({stats['arc_pass']*100/total_arc:.1f}%)\n")
            f.write(f"- **Verificaciones fallidas:** {stats['arc_fail']} ({stats['arc_fail']*100/total_arc:.1f}%)\n")
        else:
            f.write("- No se encontraron verificaciones ARC\n")
        f.write("\n")
        
        # Failure breakdown
        f.write("## Distribución de Fallos\n\n")
        total_failures = stats['dkim_only_fail'] + stats['arc_only_fail'] + stats['both_fail']
        if total_failures > 0:
            f.write(f"- **Solo DKIM falló:** {stats['dkim_only_fail']} ({stats['dkim_only_fail']*100/total_failures:.1f}%)\n")
            f.write(f"- **Solo ARC falló:** {stats['arc_only_fail']} ({stats['arc_only_fail']*100/total_failures:.1f}%)\n")
            f.write(f"- **Ambos fallaron:** {stats['both_fail']} ({stats['both_fail']*100/total_failures:.1f}%)\n\n")
        else:
            f.write("- No se registraron fallos\n\n")
        
        # Top failure causes
        if stats['failure_causes']:
            f.write("## Causas de Fallo Más Comunes\n\n")
            f.write("| # | Causa | Ocurrencias |\n")
            f.write("|---|-------|-------------|\n")
            for i, (cause, count) in enumerate(stats['failure_causes'].most_common(), 1):
                f.write(f"| {i} | {cause} | {count} |\n")
            f.write("\n")
        
        # Domains analysis
        if stats['domains']:
            f.write("## Análisis por Dominio\n\n")
            f.write("### Dominios con más correos\n\n")
            f.write("| Dominio | Total Correos |\n")
            f.write("|---------|---------------|\n")
            for domain, count in stats['domains'].most_common(10):
                f.write(f"| {domain} | {count} |\n")
            f.write("\n")
        
        # Failures by domain
        if stats['failure_by_domain']:
            f.write("### Dominios con Fallos\n\n")
            
            # Sort domains by failure count
            sorted_domains = sorted(
                stats['failure_by_domain'].items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )
            
            for domain, data in sorted_domains[:10]:  # Top 10
                f.write(f"#### {domain}\n\n")
                f.write(f"- **Total de fallos:** {data['count']}\n")
                f.write("- **Causas:**\n")
                for cause, count in data['causes'].most_common():
                    f.write(f"  - {cause}: {count}\n")
                f.write("\n")
        
        # Insights
        f.write("## Análisis e Interpretación\n\n")
        
        if total_dkim > 0:
            fail_rate = stats['dkim_fail'] * 100 / total_dkim
            if fail_rate > 50:
                f.write("### ⚠️ Alta tasa de fallos DKIM\n\n")
                f.write(f"La tasa de fallos DKIM es de {fail_rate:.1f}%, lo cual es preocupante. ")
                f.write("Esto sugiere problemas sistemáticos:\n\n")
            elif fail_rate > 20:
                f.write("### ⚠️ Tasa moderada de fallos DKIM\n\n")
                f.write(f"La tasa de fallos DKIM es de {fail_rate:.1f}%. ")
                f.write("Algunos posibles problemas:\n\n")
            else:
                f.write("### ✓ Tasa baja de fallos DKIM\n\n")
                f.write(f"La tasa de fallos DKIM es de solo {fail_rate:.1f}%, lo cual es aceptable.\n\n")
        
        # Attachment analysis
        f.write("### Análisis de Archivos Adjuntos\n\n")
        total_with_attachments = stats['emails_with_attachments']
        total_without_attachments = stats['emails_without_attachments']
        
        if total_with_attachments > 0 or total_without_attachments > 0:
            f.write(f"- **Correos con archivos adjuntos:** {total_with_attachments} ({total_with_attachments*100/(total_with_attachments+total_without_attachments):.1f}%)\n")
            f.write(f"- **Correos sin archivos adjuntos:** {total_without_attachments} ({total_without_attachments*100/(total_with_attachments+total_without_attachments):.1f}%)\n\n")
            
            # Failure rates by attachment presence
            if total_with_attachments > 0:
                fail_rate_with = (stats['fail_with_attachments'] / total_with_attachments) * 100
                f.write(f"**Tasa de fallo en correos CON adjuntos:** {stats['fail_with_attachments']}/{total_with_attachments} ({fail_rate_with:.1f}%)\n\n")
            
            if total_without_attachments > 0:
                fail_rate_without = (stats['fail_without_attachments'] / total_without_attachments) * 100
                f.write(f"**Tasa de fallo en correos SIN adjuntos:** {stats['fail_without_attachments']}/{total_without_attachments} ({fail_rate_without:.1f}%)\n\n")
            
            # Interpretation
            if total_with_attachments > 0 and total_without_attachments > 0:
                if fail_rate_with > fail_rate_without * 1.5:
                    f.write("⚠️ **Los correos con adjuntos tienen una tasa de fallo significativamente mayor.** ")
                    f.write("Esto sugiere que los archivos adjuntos pueden estar relacionados con las modificaciones del mensaje.\n\n")
                elif fail_rate_without > fail_rate_with * 1.5:
                    f.write("⚠️ **Los correos sin adjuntos tienen una tasa de fallo mayor.** ")
                    f.write("Los adjuntos no parecen ser un factor determinante en los fallos.\n\n")
                else:
                    f.write("Los archivos adjuntos no parecen tener un impacto significativo en la tasa de fallos.\n\n")
        
        # Correlation analysis
        f.write("### Correlación entre fallos DKIM y ARC\n\n")
        if stats['arc_fail_total'] > 0:
            correlation_pct = (stats['arc_fail_implies_dkim_fail'] / stats['arc_fail_total']) * 100
            f.write(f"**Hallazgo importante:** De {stats['arc_fail_total']} fallos de ARC detectados, ")
            f.write(f"**{stats['arc_fail_implies_dkim_fail']} ({correlation_pct:.1f}%) también tuvieron fallo DKIM**.\n\n")
            
            if correlation_pct > 90:
                f.write("⚠️ **Esto indica una correlación muy alta**: Cuando ARC falla, DKIM casi siempre falla también. ")
                f.write("Esto sugiere que las modificaciones del mensaje afectan ambas verificaciones.\n\n")
            elif correlation_pct > 70:
                f.write("⚠️ **Correlación significativa**: La mayoría de los fallos ARC también presentan fallos DKIM.\n\n")
            else:
                f.write("Los fallos de ARC y DKIM son relativamente independientes.\n\n")
        else:
            f.write("No se detectaron fallos de ARC para analizar correlación.\n\n")
        
        # Analyze common causes
        if stats['failure_causes']:
            top_cause = stats['failure_causes'].most_common(1)[0]
            f.write(f"### Causa principal de fallos\n\n")
            f.write(f"La causa más frecuente es: **{top_cause[0]}** ({top_cause[1]} ocurrencias)\n\n")
            
            # Provide interpretation based on top cause
            if 'body hash' in top_cause[0].lower():
                f.write("**Interpretación:** Los fallos de body hash indican que el contenido del mensaje fue modificado después de ser firmado. ")
                f.write("Esto puede ocurrir por:\n")
                f.write("- Reenvíos que modifican el cuerpo\n")
                f.write("- Software antivirus que inserta disclaimers\n")
                f.write("- Clientes de correo que reformatean mensajes\n")
                f.write("- Modificaciones en servidores intermediarios\n\n")
            
            elif 'signature' in top_cause[0].lower() and 'verif' in top_cause[0].lower():
                f.write("**Interpretación:** Problemas con la verificación de firma sugieren:\n")
                f.write("- Claves públicas DNS incorrectas o no disponibles\n")
                f.write("- Firmas malformadas o corruptas\n")
                f.write("- Problemas de formato en los headers\n\n")
            
            elif 'expired' in top_cause[0].lower() or 'vencida' in top_cause[0].lower():
                f.write("**Interpretación:** Firmas vencidas indican:\n")
                f.write("- Los correos se verifican mucho tiempo después de ser enviados\n")
                f.write("- El remitente configuró un tiempo de expiración muy corto\n")
                f.write("- Retrasos en la entrega de correos\n\n")
        
        # Analysis by recipient domain
        if stats['failure_by_to_domain']:
            f.write("## Análisis por Dominio Receptor\n\n")
            f.write("### Dominios receptores con más fallos\n\n")
            f.write("| Dominio Receptor | Total Fallos | Fallos DKIM | Fallos ARC |\n")
            f.write("|------------------|--------------|-------------|------------|\n")
            
            sorted_to_domains = sorted(
                stats['failure_by_to_domain'].items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )
            
            for domain, data in sorted_to_domains[:10]:
                f.write(f"| {domain} | {data['count']} | {data['dkim_fail']} | {data['arc_fail']} |\n")
            f.write("\n")
        
        # Temporal analysis
        if stats['failure_dates']:
            f.write("## Análisis Temporal de Fallos\n\n")
            f.write(f"**Total de fallos registrados:** {len(stats['failure_dates'])}\n\n")
            
            # Try to parse and group dates
            date_patterns = defaultdict(int)
            for date_str in stats['failure_dates']:
                if date_str:
                    # Try to extract month/year
                    month_match = re.search(r'(enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre)\s+de\s+(\d{4})', date_str, re.IGNORECASE)
                    if month_match:
                        period = f"{month_match.group(1).capitalize()} {month_match.group(2)}"
                        date_patterns[period] += 1
            
            if date_patterns:
                f.write("### Distribución de fallos por período\n\n")
                f.write("| Período | Cantidad de Fallos |\n")
                f.write("|---------|--------------------|\n")
                for period in sorted(date_patterns.keys()):
                    f.write(f"| {period} | {date_patterns[period]} |\n")
                f.write("\n")
        
        # Detailed correlation table
        if stats['correlation_data']:
            f.write("## Tabla Detallada de Correlación DKIM/ARC\n\n")
            f.write("Primeros 20 casos de fallo para análisis detallado:\n\n")
            f.write("| # | Fecha | De (Dominio) | Para (Dominio) | DKIM | ARC | Adjuntos |\n")
            f.write("|---|-------|--------------|----------------|------|-----|----------|\n")
            
            for i, item in enumerate(stats['correlation_data'][:20], 1):
                dkim_status = "❌ FALLO" if item['dkim_failed'] else "✓ OK"
                arc_status = "❌ FALLO" if item['arc_failed'] else "✓ OK"
                attachment_info = f"Sí ({item['attachment_count']})" if item['has_attachments'] else "No"
                date_short = item['date'][:20] if item['date'] else 'N/A'
                f.write(f"| {i} | {date_short} | {item['from_domain'] or 'N/A'} | {item['to_domain'] or 'N/A'} | {dkim_status} | {arc_status} | {attachment_info} |\n")
            
            if len(stats['correlation_data']) > 20:
                f.write(f"\n*... y {len(stats['correlation_data']) - 20} casos adicionales*\n")
            f.write("\n")
        
        # Recommendations
        f.write("## Recomendaciones\n\n")
        
        if stats['dkim_fail'] > stats['dkim_pass']:
            f.write("1. **Prioridad Alta:** Investigar la causa principal de fallos identificada arriba\n")
            f.write("2. Verificar la configuración DNS de los dominios con más fallos\n")
            f.write("3. Revisar si hay patrones temporales en los fallos\n")
            f.write("4. Considerar si los correos están siendo modificados en tránsito\n")
        else:
            f.write("1. La tasa de verificación es generalmente buena\n")
            f.write("2. Los fallos detectados parecen ser casos específicos\n")
            f.write("3. Revisar los dominios con fallos consistentes\n")
        
        f.write("\n---\n\n")
        f.write("*Reporte generado automáticamente por analyze_logs.py*\n")

def main():
    log_dir = r"d:\Documents\franco\Pericias\Salud Nova c. OS Aceiteros\logs"
    output_file = r"d:\Documents\franco\Pericias\Salud Nova c. OS Aceiteros\logs\stats.md"
    
    print(f"Analizando logs en: {log_dir}")
    
    # Get all log files
    log_files = [f for f in os.listdir(log_dir) if f.startswith('verification_log_') and f.endswith('.txt')]
    
    if not log_files:
        print("No se encontraron archivos de log.")
        return
    
    print(f"Encontrados {len(log_files)} archivos de log")
    
    # Analyze all logs
    all_results = []
    for log_file in log_files:
        filepath = os.path.join(log_dir, log_file)
        print(f"  Procesando {log_file}...")
        try:
            results = analyze_log_file(filepath)
            all_results.extend(results)
            print(f"    → {len(results)} correos encontrados")
        except Exception as e:
            print(f"    ✗ Error: {e}")
    
    print(f"\nTotal de correos analizados: {len(all_results)}")
    
    # Generate statistics
    print("Generando estadísticas...")
    stats = generate_statistics(all_results)
    
    # Write report
    print(f"Escribiendo reporte en: {output_file}")
    write_markdown_report(stats, output_file)
    
    print("\n✓ Análisis completado")
    print(f"\nResumen:")
    print(f"  - Total correos: {stats['total_emails']}")
    print(f"  - DKIM exitoso: {stats['dkim_pass']}, fallido: {stats['dkim_fail']}")
    print(f"  - ARC exitoso: {stats['arc_pass']}, fallido: {stats['arc_fail']}")
    if stats['failure_causes']:
        top_cause = stats['failure_causes'].most_common(1)[0]
        print(f"  - Causa principal: {top_cause[0]} ({top_cause[1]}x)")

if __name__ == '__main__':
    main()
