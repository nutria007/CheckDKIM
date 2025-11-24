#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import email
import sys
import dkim
import os
import re
from datetime import datetime

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




def verify_arc(msg_bytes, verbose=False):
    """
    Verifica la firma ARC de un mensaje.
    
    En modo verbose, captura información detallada del proceso de verificación
    utilizando el logger interno de dkim.arc_verify(), incluyendo:
    - Parámetros de las firmas ARC parseados
    - Validación de la cadena ARC
    - Errores específicos con tipos de excepción detallados
    """
    safe_print("=" * 60)
    safe_print("VERIFICACIÓN ARC")
    safe_print("=" * 60)
    
    try:
        # Parse del mensaje para análisis detallado
        msg = email.message_from_bytes(msg_bytes)
        
        # Mostrar información sobre cabeceras ARC
        arc_seals = msg.get_all('ARC-Seal') or []
        arc_signatures = msg.get_all('ARC-Message-Signature') or []
        arc_auth_results = msg.get_all('ARC-Authentication-Results') or []
        
        if verbose:
            safe_print(f"Cabeceras ARC-Seal encontradas: {len(arc_seals)}")
            for i, seal in enumerate(arc_seals, 1):
                safe_print(f"  ARC-Seal #{i}: {seal[:100]}{'...' if len(seal) > 100 else ''}")
                
            safe_print(f"Cabeceras ARC-Message-Signature encontradas: {len(arc_signatures)}")
            for i, sig in enumerate(arc_signatures, 1):
                safe_print(f"  ARC-Message-Signature #{i}: {sig[:100]}{'...' if len(sig) > 100 else ''}")
                
            safe_print(f"Cabeceras ARC-Authentication-Results encontradas: {len(arc_auth_results)}")
            for i, auth in enumerate(arc_auth_results, 1):
                safe_print(f"  ARC-Authentication-Results #{i}: {auth[:100]}{'...' if len(auth) > 100 else ''}")
        else:
            safe_print(f"Cabeceras encontradas: {len(arc_seals)} ARC-Seal, {len(arc_signatures)} ARC-Signature, {len(arc_auth_results)} ARC-Auth-Results")
        
        # Intentar verificar ARC de manera simple
        if verbose:
            safe_print("\nIntentando verificación automática de ARC...")
        
        # Configurar logger para capturar información detallada en modo verbose
        arc_logger = None
        log_stream = None
        if verbose:
            import logging
            import io
            
            # Crear un logger específico para ARC
            arc_logger = logging.getLogger('arc_verify')
            arc_logger.setLevel(logging.DEBUG)
            arc_logger.handlers = []  # Limpiar handlers previos
            
            # Crear un handler que capture los logs en memoria
            log_stream = io.StringIO()
            handler = logging.StreamHandler(log_stream)
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            arc_logger.addHandler(handler)
        
        # Método 1: Intentar con arc_verify directamente del módulo dkim
        try:
            result = dkim.arc_verify(msg_bytes, logger=arc_logger if verbose else None)
            
            # arc_verify devuelve una tupla de 3 elementos:
            # (CV Result, lista de diccionarios de resultados, razón del resultado)
            if verbose:
                safe_print("Resultado de dkim.arc_verify:")
            
            if isinstance(result, tuple) and len(result) == 3:
                cv_result, result_dicts, result_reason = result
                
                if verbose:
                    safe_print(f"  CV Result: {cv_result}")
                    safe_print(f"  Razón: {result_reason}")
                    safe_print(f"  Número de resultados: {len(result_dicts) if result_dicts else 0}")
                    
                    if result_dicts:
                        safe_print("  Detalles de resultados:")
                        import json
                        for i, result_dict in enumerate(result_dicts):
                            safe_print(f"    Resultado #{i+1}:")
                            safe_print(json.dumps(result_dict, indent=6, default=str))
                
                # Evaluar el resultado basado en CV Result
                # Importar las constantes de dkim si están disponibles
                try:
                    from dkim import CV_Pass, CV_Fail, CV_None
                    if cv_result == CV_Pass:
                        safe_print("✓ Verificación ARC exitosa (CV_Pass).")
                        return True
                    elif cv_result == CV_Fail:
                        safe_print("✗ Verificación ARC falló (CV_Fail).")
                        
                        # Mostrar logs capturados solo cuando falla y está en modo verbose
                        if verbose and arc_logger:
                            log_output = log_stream.getvalue()
                            if log_output.strip():
                                safe_print("\n  Información detallada de dkim.arc_verify():")
                                
                                # Analizar mensajes de error específicos del logger
                                error_analysis = []
                                for line in log_output.strip().split('\n'):
                                    safe_print(f"    {line}")
                                    
                                    # Detectar errores específicos
                                    if 'body hash mismatch' in line.lower():
                                        error_analysis.append("    → El cuerpo del mensaje fue modificado después de la firma")
                                    elif 'x= value is past' in line.lower():
                                        error_analysis.append("    → La firma ha expirado (parámetro x=)")
                                    elif 'could not parse rsa public key' in line.lower():
                                        error_analysis.append("    → La clave pública DKIM no tiene el formato correcto")
                                    elif "'dkim-signature' valid: false" in line.lower() or "b'dkim-signature' valid: false" in line.lower():
                                        error_analysis.append("    → La firma DKIM no tiene el formato correcto")
                                    elif "'arc-" in line.lower() and "valid: false" in line.lower():
                                        error_analysis.append("    → La firma ARC no tiene el formato correcto")
                                    elif 'signature verification failed' in line.lower() or 'valid: false' in line.lower():
                                        error_analysis.append("    → La verificación criptográfica de la firma falló")
                                    elif 'dns' in line.lower() and ('timeout' in line.lower() or 'error' in line.lower()):
                                        error_analysis.append("    → Error al consultar el DNS para obtener la clave pública")
                                    elif 'key' in line.lower() and 'not found' in line.lower():
                                        error_analysis.append("    → La clave pública no se encuentra en el DNS")
                                    elif 'chain' in line.lower() and ('broken' in line.lower() or 'invalid' in line.lower()):
                                        error_analysis.append("    → La cadena ARC está rota o es inválida")
                                
                                # Mostrar análisis de errores detectados
                                if error_analysis:
                                    safe_print("\n  Causas específicas detectadas:")
                                    for analysis in error_analysis:
                                        safe_print(analysis)
                        
                        return False
                    elif cv_result == CV_None:
                        safe_print("⚠ Verificación ARC no concluyente (CV_None).")
                        
                        # Mostrar logs capturados solo cuando falla y está en modo verbose
                        if verbose and arc_logger:
                            log_output = log_stream.getvalue()
                            if log_output.strip():
                                safe_print("\n  Información detallada de dkim.arc_verify():")
                                
                                # Analizar mensajes de error específicos del logger
                                error_analysis = []
                                for line in log_output.strip().split('\n'):
                                    safe_print(f"    {line}")
                                    
                                    # Detectar errores específicos
                                    if 'no arc' in line.lower() or 'missing arc' in line.lower():
                                        error_analysis.append("    → No hay suficientes cabeceras ARC para validar")
                                
                                # Mostrar análisis de errores detectados
                                if error_analysis:
                                    safe_print("\n  Causas específicas detectadas:")
                                    for analysis in error_analysis:
                                        safe_print(analysis)
                        
                        return False
                    else:
                        safe_print(f"? Resultado ARC desconocido: {cv_result}")
                        
                        # Mostrar logs capturados
                        if verbose and arc_logger:
                            log_output = log_stream.getvalue()
                            if log_output.strip():
                                safe_print("\n  Información detallada de dkim.arc_verify():")
                                for line in log_output.strip().split('\n'):
                                    safe_print(f"    {line}")
                        
                        return False
                except ImportError:
                    # Si no se pueden importar las constantes, usar comparación de strings
                    cv_str = str(cv_result).lower()
                    if 'pass' in cv_str:
                        safe_print("✓ Verificación ARC exitosa.")
                        return True
                    elif 'fail' in cv_str:
                        safe_print("✗ Verificación ARC falló.")
                        
                        # Mostrar logs capturados solo cuando falla y está en modo verbose
                        if verbose and arc_logger:
                            log_output = log_stream.getvalue()
                            if log_output.strip():
                                safe_print("\n  Información detallada de dkim.arc_verify():")
                                for line in log_output.strip().split('\n'):
                                    safe_print(f"    {line}")
                        
                        return False
                    elif 'none' in cv_str:
                        safe_print("⚠ Verificación ARC no concluyente.")
                        
                        # Mostrar logs capturados solo cuando falla y está en modo verbose
                        if verbose and arc_logger:
                            log_output = log_stream.getvalue()
                            if log_output.strip():
                                safe_print("\n  Información detallada de dkim.arc_verify():")
                                for line in log_output.strip().split('\n'):
                                    safe_print(f"    {line}")
                        
                        return False
                    else:
                        safe_print(f"? Resultado ARC desconocido: {cv_result}")
                        
                        # Mostrar logs capturados
                        if verbose and arc_logger:
                            log_output = log_stream.getvalue()
                            if log_output.strip():
                                safe_print("\n  Información detallada de dkim.arc_verify():")
                                for line in log_output.strip().split('\n'):
                                    safe_print(f"    {line}")
                        
                        return False
            else:
                if verbose:
                    safe_print(f"  Formato inesperado: {type(result)} = {result}")
                
                # Mostrar logs capturados
                if verbose and arc_logger:
                    log_output = log_stream.getvalue()
                    if log_output.strip():
                        safe_print("\n  Información detallada de dkim.arc_verify():")
                        for line in log_output.strip().split('\n'):
                            safe_print(f"    {line}")
                
                # Fallback: evaluar como booleano
                if result:
                    safe_print("✓ Verificación ARC exitosa.")
                    return True
                else:
                    safe_print("✗ La verificación ARC falló.")
                    return False
        except AttributeError as e:
            safe_print(f"dkim.arc_verify no disponible: {e}")
            
        # Método 2: Verificar manualmente las cabeceras ARC
        if verbose:
            safe_print("\nVerificación manual de cabeceras ARC...")
        if arc_seals and arc_signatures and arc_auth_results:
            if verbose:
                safe_print("✓ Se encontraron todas las cabeceras ARC necesarias.")
                safe_print("⚠ Nota: Verificación criptográfica completa de ARC requiere implementación específica.")
                safe_print("  Para verificación completa, se necesita validar:")
                safe_print("  - Firma criptográfica de cada ARC-Seal")
                safe_print("  - Integridad de la cadena ARC")
                safe_print("  - Validez de las claves públicas")
            return False  # No podemos hacer verificación criptográfica completa
        else:
            if verbose:
                safe_print("✗ No se encontraron todas las cabeceras ARC necesarias.")
            return False
            
    except Exception as e:
        safe_print(f"✗ Error en la verificación ARC: {e}", file=sys.stderr)
        return False

def verify_dkim(msg_bytes, verbose=False):
    """
    Verifica la firma DKIM de un mensaje.
    
    En modo verbose, captura información detallada del proceso de verificación
    utilizando el logger interno de dkim.verify(), incluyendo:
    - Parámetros de la firma parseados
    - Validación del hash del cuerpo (bh)
    - Consultas DNS para claves públicas
    - Errores específicos con tipos de excepción detallados
    """
    safe_print("=" * 60)
    safe_print("VERIFICACIÓN DKIM")
    safe_print("=" * 60)
    
    try:
        # Parse del mensaje para análisis detallado
        msg = email.message_from_bytes(msg_bytes)
        
        # Mostrar información sobre cabeceras DKIM
        dkim_signatures = msg.get_all('DKIM-Signature') or []
        
        if verbose:
            safe_print(f"Cabeceras DKIM-Signature encontradas: {len(dkim_signatures)}")
            
            for i, signature in enumerate(dkim_signatures, 1):
                safe_print(f"\nDKIM-Signature #{i}:")
                safe_print(f"  Cabecera completa: {signature[:200]}{'...' if len(signature) > 200 else ''}")
                
                # Parsear los parámetros de la firma DKIM
                sig_params = {}
                for param in signature.split(';'):
                    param = param.strip()
                    if '=' in param:
                        key, value = param.split('=', 1)
                        sig_params[key.strip()] = value.strip()
                
                safe_print("  Parámetros de la firma:")
                for key, value in sig_params.items():
                    if key in ['v', 'a', 'd', 's', 'c', 'h', 't']:
                        safe_print(f"    {key}: {value}")
                    elif key == 'b':
                        safe_print(f"    {key}: {value[:50]}{'...' if len(value) > 50 else ''} (firma)")
                    elif key == 'bh':
                        safe_print(f"    {key}: {value[:50]}{'...' if len(value) > 50 else ''} (hash del cuerpo)")
            
            safe_print("\nIntentando verificación DKIM...")
        else:
            safe_print(f"Cabeceras encontradas: {len(dkim_signatures)} DKIM-Signature")
        
        # Configurar logger para capturar información detallada en modo verbose
        dkim_logger = None
        if verbose:
            import logging
            import io
            
            # Crear un logger específico para DKIM
            dkim_logger = logging.getLogger('dkim_verify')
            dkim_logger.setLevel(logging.DEBUG)
            dkim_logger.handlers = []  # Limpiar handlers previos
            
            # Crear un handler que capture los logs en memoria
            log_stream = io.StringIO()
            handler = logging.StreamHandler(log_stream)
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            dkim_logger.addHandler(handler)
        
        # Realizar verificación DKIM con logger si está en modo verbose
        result = dkim.verify(msg_bytes, logger=dkim_logger if verbose else None)
        
        if result:
            safe_print("✓ Verificación DKIM exitosa.")
            if verbose:
                safe_print("  La firma DKIM es válida y el mensaje no ha sido alterado.")
            return True
        else:
            safe_print("✗ La firma DKIM no es válida.")
            if verbose:
                safe_print("  Posibles causas:")
                safe_print("  - El mensaje ha sido modificado después de la firma")
                safe_print("  - La clave pública no se puede obtener del DNS")
                safe_print("  - La firma está malformada")
                safe_print("  - El selector o dominio son incorrectos")
                 # Intentar obtener más detalles del fallo
                safe_print("\n  Análisis detallado del fallo:")
            
            # Mostrar logs capturados solo cuando falla y está en modo verbose
            if verbose and dkim_logger:
                log_output = log_stream.getvalue()
                if log_output.strip():
                    safe_print("\n  Información detallada de dkim.verify():")
                    
                    # Analizar mensajes de error específicos del logger
                    error_analysis = []
                    for line in log_output.strip().split('\n'):
                        safe_print(f"    {line}")
                        
                        # Detectar errores específicos
                        if 'body hash mismatch' in line.lower():
                            error_analysis.append("    → El cuerpo del mensaje fue modificado después de la firma")
                        elif 'x= value is past' in line.lower():
                            error_analysis.append("    → La firma ha expirado (parámetro x=)")
                        elif 'could not parse rsa public key' in line.lower():
                            error_analysis.append("    → La clave pública DKIM no tiene el formato correcto")
                        elif "'dkim-signature' valid: false" in line.lower() or "b'dkim-signature' valid: false" in line.lower():
                            error_analysis.append("    → La firma DKIM no tiene el formato correcto")
                        elif 'signature verification failed' in line.lower():
                            error_analysis.append("    → La verificación criptográfica de la firma falló")
                        elif 'dns' in line.lower() and ('timeout' in line.lower() or 'error' in line.lower()):
                            error_analysis.append("    → Error al consultar el DNS para obtener la clave pública")
                        elif 'key' in line.lower() and 'not found' in line.lower():
                            error_analysis.append("    → La clave pública no se encuentra en el DNS")
                    
                    # Mostrar análisis de errores detectados
                    if error_analysis:
                        safe_print("\n  Causas específicas detectadas:")
                        for analysis in error_analysis:
                            safe_print(analysis)
            
            
            return False
            
    except dkim.KeyFormatError as e:
        safe_print(f"✗ Error de formato de clave DKIM: {e}", file=sys.stderr)
        if verbose:
            safe_print("  La clave pública DKIM tiene un formato inválido.")
        return False
    except dkim.MessageFormatError as e:
        safe_print(f"✗ Error de formato del mensaje: {e}", file=sys.stderr)
        if verbose:
            safe_print("  El mensaje no tiene el formato RFC822 esperado.")
        return False
    except dkim.ParameterError as e:
        safe_print(f"✗ Error en parámetros DKIM: {e}", file=sys.stderr)
        if verbose:
            safe_print("  Los parámetros de la firma DKIM son inválidos.")
        return False
    except dkim.DnsTimeoutError as e:
        safe_print(f"✗ Timeout en consulta DNS: {e}", file=sys.stderr)
        if verbose:
            safe_print("  No se pudo obtener la clave pública del DNS (timeout).")
        return False
    except dkim.ValidationError as e:
        safe_print(f"✗ Error de validación DKIM: {e}", file=sys.stderr)
        if verbose:
            safe_print("  Error al validar la firma DKIM.")
        return False
    except dkim.DKIMException as e:
        safe_print(f"✗ Excepción DKIM: {e}", file=sys.stderr)
        if verbose:
            safe_print("  Error específico de la biblioteca DKIM.")
        return False
    except Exception as e:
        safe_print(f"✗ Error general en la verificación DKIM: {e}", file=sys.stderr)
        return False



def main():
    """
    Función principal para verificar las firmas de un email desde un archivo.
    Busca y verifica primero la firma ARC. Si no existe, busca y verifica la firma DKIM.
    """
    parser = argparse.ArgumentParser(
        description="Verifica las firmas DKIM y ARC de un correo electrónico desde un archivo."
    )
    parser.add_argument(
        "email_file", help="Ruta al archivo que contiene el correo electrónico."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Muestra información detallada del proceso de verificación"
    )
    args = parser.parse_args()

    # Preparar archivo de salida en el mismo directorio que el archivo de entrada
    input_dir = os.path.dirname(os.path.abspath(args.email_file))
    input_filename = os.path.basename(args.email_file)
    input_name_without_ext = os.path.splitext(input_filename)[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"{input_name_without_ext}_verification_{timestamp}.txt"
    output_path = os.path.join(input_dir, output_filename)
    
    # Clase para duplicar la salida a consola y archivo
    class TeeOutput:
        def __init__(self, *files):
            self.files = files
        def write(self, obj):
            for f in self.files:
                f.write(obj)
                f.flush()
        def flush(self):
            for f in self.files:
                f.flush()
    
    # Abrir archivo de salida y redirigir stdout
    try:
        output_file = open(output_path, 'w', encoding='utf-8')
        original_stdout = sys.stdout
        sys.stdout = TeeOutput(sys.stdout, output_file)
    except Exception as e:
        safe_print(f"⚠ No se pudo crear el archivo de salida: {e}")
        output_file = None
        original_stdout = None

    safe_print("=" * 80)
    safe_print("VERIFICADOR DE AUTENTICACIÓN DE EMAIL (DKIM/ARC)")
    safe_print("=" * 80)
    safe_print(f"Archivo: {args.email_file}")
    if args.verbose:
        safe_print(f"Salida: {output_path}")
        safe_print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        safe_print(f"Modo: Verbose (detallado)")
    else:
        safe_print(f"Modo: Simple (use -v para detalles)")
    
    try:
        with open(args.email_file, 'rb') as f:
            msg_bytes = f.read()
        if args.verbose:
            safe_print(f"Tamaño del archivo: {len(msg_bytes)} bytes")
    except FileNotFoundError:
        safe_print(f"✗ Error: El archivo '{args.email_file}' no fue encontrado.", file=sys.stderr)
        if output_file:
            output_file.close()
            sys.stdout = original_stdout
        sys.exit(1)
    except Exception as e:
        safe_print(f"✗ Error al leer el archivo: {e}", file=sys.stderr)
        if output_file:
            output_file.close()
            sys.stdout = original_stdout
        sys.exit(1)

    # Análisis inicial del mensaje
    if args.verbose:
        safe_print("\n" + "=" * 60)
        safe_print("ANÁLISIS INICIAL DEL MENSAJE")
        safe_print("=" * 60)
    
    msg = email.message_from_bytes(msg_bytes)
    
    # Información básica del mensaje
    safe_print(f"\nFrom: {msg.get('From', 'No especificado')}")
    safe_print(f"To: {msg.get('To', 'No especificado')}")
    safe_print(f"Subject: {msg.get('Subject', 'No especificado')}")
    safe_print(f"Date: {msg.get('Date', 'No especificado')}")
    safe_print(f"Message-ID: {msg.get('Message-ID', 'No especificado')}")
    
    # Verificar presencia de cabeceras de autenticación
    has_arc_seal = 'ARC-Seal' in msg
    has_dkim_signature = 'DKIM-Signature' in msg
    
    safe_print(f"\nCabeceras de autenticación:")
    if args.verbose:
        safe_print(f"  ARC-Seal: {'✓ Sí' if has_arc_seal else '✗ No'}")
        safe_print(f"  DKIM-Signature: {'✓ Sí' if has_dkim_signature else '✗ No'}")
        
        # Mostrar otras cabeceras de autenticación relevantes
        auth_headers = ['Authentication-Results', 'Received-SPF', 'DMARC-Filter']
        for header in auth_headers:
            if header in msg:
                values = msg.get_all(header)
                safe_print(f"  {header}: ✓ Sí ({len(values)} encontrada(s))")
                for i, value in enumerate(values, 1):
                    safe_print(f"    #{i}: {value[:100]}{'...' if len(value) > 100 else ''}")
            else:
                safe_print(f"  {header}: ✗ No")
    else:
        signatures = []
        if has_arc_seal:
            signatures.append("ARC")
        if has_dkim_signature:
            signatures.append("DKIM")
        if signatures:
            safe_print(f"  Encontradas: {', '.join(signatures)}")
        else:
            safe_print(f"  Ninguna firma encontrada")

    verified = False
    verification_method = ""
    
    # Proceso de verificación
    if has_arc_seal:
        if args.verbose:
            safe_print(f"\n{'='*20} INICIANDO VERIFICACIÓN ARC {'='*20}")
        else:
            safe_print(f"\nVerificando ARC...")
        if verify_arc(msg_bytes, args.verbose):
            verified = True
            verification_method = "ARC"
        else:
            if args.verbose:
                safe_print("\n⚠ La verificación ARC falló. Intentando con DKIM si existe...")
    
    if not verified and has_dkim_signature:
        if args.verbose:
            if has_arc_seal:
                safe_print(f"\n{'='*20} INICIANDO VERIFICACIÓN DKIM (FALLBACK) {'='*20}")
            else:
                safe_print(f"\n{'='*20} INICIANDO VERIFICACIÓN DKIM {'='*20}")
        else:
            safe_print(f"\nVerificando DKIM...")
        if verify_dkim(msg_bytes, args.verbose):
            verified = True
            verification_method = "DKIM"
    
    if not has_arc_seal and not has_dkim_signature:
        if args.verbose:
            safe_print(f"\n{'='*20} SIN FIRMAS ENCONTRADAS {'='*20}")
        safe_print("✗ No se encontraron cabeceras 'ARC-Seal' ni 'DKIM-Signature' en el correo.")
        if args.verbose:
            safe_print("  El mensaje no tiene firmas digitales para verificar.")

    # Resultado final
    if args.verbose:
        safe_print("\n" + "=" * 80)
        safe_print("RESULTADO FINAL")
        safe_print("=" * 80)
    else:
        safe_print("\n" + "=" * 60)
    
    if verified:
        safe_print(f"✓ SUCCESS: El correo ha sido verificado exitosamente usando {verification_method}.")
        if args.verbose:
            safe_print(f"  El mensaje es auténtico y no ha sido alterado.")
    else:
        safe_print("✗ FAIL: No se pudo verificar el correo.")
        if args.verbose:
            if has_arc_seal or has_dkim_signature:
                safe_print("  El mensaje tiene firmas pero no pudieron ser validadas.")
                safe_print("  Posibles causas:")
                safe_print("  - Las firmas están corruptas o malformadas")
                safe_print("  - No se pueden obtener las claves públicas del DNS")
                safe_print("  - El mensaje ha sido modificado después de ser firmado")
                safe_print("  - Problemas de conectividad con los servidores DNS")
            else:
                safe_print("  El mensaje no contiene firmas digitales para verificar.")
    
    if args.verbose:
        safe_print("=" * 80)
    else:
        safe_print("=" * 60)
    
    # Cerrar archivo de salida y restaurar stdout
    if output_file:
        sys.stdout = original_stdout
        output_file.close()
        if args.verbose:
            safe_print(f"\n✓ Resultados guardados en: {output_path}")
        else:
            safe_print(f"\nResultados guardados en: {output_filename}")


if __name__ == "__main__":
    main()
