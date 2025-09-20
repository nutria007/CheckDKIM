
import argparse
import email
import sys
import dkim


def verify_arc(msg_bytes):
    """Verifica la firma ARC de un mensaje."""
    print("=" * 60)
    print("VERIFICACIÓN ARC")
    print("=" * 60)
    
    try:
        # Parse del mensaje para análisis detallado
        msg = email.message_from_bytes(msg_bytes)
        
        # Mostrar información sobre cabeceras ARC
        arc_seals = msg.get_all('ARC-Seal') or []
        arc_signatures = msg.get_all('ARC-Message-Signature') or []
        arc_auth_results = msg.get_all('ARC-Authentication-Results') or []
        
        print(f"Cabeceras ARC-Seal encontradas: {len(arc_seals)}")
        for i, seal in enumerate(arc_seals, 1):
            print(f"  ARC-Seal #{i}: {seal[:100]}{'...' if len(seal) > 100 else ''}")
            
        print(f"Cabeceras ARC-Message-Signature encontradas: {len(arc_signatures)}")
        for i, sig in enumerate(arc_signatures, 1):
            print(f"  ARC-Message-Signature #{i}: {sig[:100]}{'...' if len(sig) > 100 else ''}")
            
        print(f"Cabeceras ARC-Authentication-Results encontradas: {len(arc_auth_results)}")
        for i, auth in enumerate(arc_auth_results, 1):
            print(f"  ARC-Authentication-Results #{i}: {auth[:100]}{'...' if len(auth) > 100 else ''}")
        
        # Intentar verificar ARC de manera simple
        print("\nIntentando verificación automática de ARC...")
        
        # Método 1: Intentar con arc_verify directamente del módulo dkim
        try:
            result = dkim.arc_verify(msg_bytes)
            
            # arc_verify devuelve una tupla de 3 elementos:
            # (CV Result, lista de diccionarios de resultados, razón del resultado)
            print("Resultado de dkim.arc_verify:")
            
            if isinstance(result, tuple) and len(result) == 3:
                cv_result, result_dicts, result_reason = result
                
                print(f"  CV Result: {cv_result}")
                print(f"  Razón: {result_reason}")
                print(f"  Número de resultados: {len(result_dicts) if result_dicts else 0}")
                
                if result_dicts:
                    print("  Detalles de resultados:")
                    import json
                    for i, result_dict in enumerate(result_dicts):
                        print(f"    Resultado #{i+1}:")
                        print(json.dumps(result_dict, indent=6, default=str))
                
                # Evaluar el resultado basado en CV Result
                # Importar las constantes de dkim si están disponibles
                try:
                    from dkim import CV_Pass, CV_Fail, CV_None
                    if cv_result == CV_Pass:
                        print("✓ Verificación ARC exitosa (CV_Pass).")
                        return True
                    elif cv_result == CV_Fail:
                        print("✗ Verificación ARC falló (CV_Fail).")
                        return False
                    elif cv_result == CV_None:
                        print("⚠ Verificación ARC no concluyente (CV_None).")
                        return False
                    else:
                        print(f"? Resultado ARC desconocido: {cv_result}")
                        return False
                except ImportError:
                    # Si no se pueden importar las constantes, usar comparación de strings
                    cv_str = str(cv_result).lower()
                    if 'pass' in cv_str:
                        print("✓ Verificación ARC exitosa.")
                        return True
                    elif 'fail' in cv_str:
                        print("✗ Verificación ARC falló.")
                        return False
                    elif 'none' in cv_str:
                        print("⚠ Verificación ARC no concluyente.")
                        return False
                    else:
                        print(f"? Resultado ARC desconocido: {cv_result}")
                        return False
            else:
                print(f"  Formato inesperado: {type(result)} = {result}")
                # Fallback: evaluar como booleano
                if result:
                    print("✓ Verificación ARC exitosa.")
                    return True
                else:
                    print("✗ La verificación ARC falló.")
                    return False
        except AttributeError as e:
            print(f"dkim.arc_verify no disponible: {e}")
            
        # Método 2: Verificar manualmente las cabeceras ARC
        print("\nVerificación manual de cabeceras ARC...")
        if arc_seals and arc_signatures and arc_auth_results:
            print("✓ Se encontraron todas las cabeceras ARC necesarias.")
            print("⚠ Nota: Verificación criptográfica completa de ARC requiere implementación específica.")
            print("  Para verificación completa, se necesita validar:")
            print("  - Firma criptográfica de cada ARC-Seal")
            print("  - Integridad de la cadena ARC")
            print("  - Validez de las claves públicas")
            return False  # No podemos hacer verificación criptográfica completa
        else:
            print("✗ No se encontraron todas las cabeceras ARC necesarias.")
            return False
            
    except Exception as e:
        print(f"✗ Error en la verificación ARC: {e}", file=sys.stderr)
        return False

def verify_dkim(msg_bytes):
    """Verifica la firma DKIM de un mensaje."""
    print("=" * 60)
    print("VERIFICACIÓN DKIM")
    print("=" * 60)
    
    try:
        # Parse del mensaje para análisis detallado
        msg = email.message_from_bytes(msg_bytes)
        
        # Mostrar información sobre cabeceras DKIM
        dkim_signatures = msg.get_all('DKIM-Signature') or []
        print(f"Cabeceras DKIM-Signature encontradas: {len(dkim_signatures)}")
        
        for i, signature in enumerate(dkim_signatures, 1):
            print(f"\nDKIM-Signature #{i}:")
            print(f"  Cabecera completa: {signature[:200]}{'...' if len(signature) > 200 else ''}")
            
            # Parsear los parámetros de la firma DKIM
            sig_params = {}
            for param in signature.split(';'):
                param = param.strip()
                if '=' in param:
                    key, value = param.split('=', 1)
                    sig_params[key.strip()] = value.strip()
            
            print("  Parámetros de la firma:")
            for key, value in sig_params.items():
                if key in ['v', 'a', 'd', 's', 'c', 'h', 't']:
                    print(f"    {key}: {value}")
                elif key == 'b':
                    print(f"    {key}: {value[:50]}{'...' if len(value) > 50 else ''} (firma)")
                elif key == 'bh':
                    print(f"    {key}: {value[:50]}{'...' if len(value) > 50 else ''} (hash del cuerpo)")
        
        print("\nIntentando verificación DKIM...")
        
        # Realizar verificación DKIM
        result = dkim.verify(msg_bytes)
        
        if result:
            print("✓ Verificación DKIM exitosa.")
            print("  La firma DKIM es válida y el mensaje no ha sido alterado.")
            return True
        else:
            print("✗ La firma DKIM no es válida.")
            print("  Posibles causas:")
            print("  - El mensaje ha sido modificado después de la firma")
            print("  - La clave pública no se puede obtener del DNS")
            print("  - La firma está malformada")
            print("  - El selector o dominio son incorrectos")
            return False
            
    except dkim.DKIMException as e:
        print(f"✗ Excepción DKIM: {e}", file=sys.stderr)
        print("  Error específico de la biblioteca DKIM.")
        return False
    except Exception as e:
        print(f"✗ Error general en la verificación DKIM: {e}", file=sys.stderr)
        return False

def main():
    """
    Función principal para verificar las firmas de un email desde un archivo.
    Busca y verifica primero la firma ARC. Si no existe, busca y verifica la firma DKIM.
    """
    parser = argparse.ArgumentParser(
        description="Verifica la firma ARC o DKIM de un correo electrónico desde un archivo."
    )
    parser.add_argument(
        "email_file", help="Ruta al archivo que contiene el correo electrónico."
    )
    args = parser.parse_args()

    print("=" * 80)
    print("VERIFICADOR DE FIRMAS DKIM/ARC")
    print("=" * 80)
    print(f"Archivo: {args.email_file}")
    
    try:
        with open(args.email_file, 'rb') as f:
            msg_bytes = f.read()
        print(f"Tamaño del archivo: {len(msg_bytes)} bytes")
    except FileNotFoundError:
        print(f"✗ Error: El archivo '{args.email_file}' no fue encontrado.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error al leer el archivo: {e}", file=sys.stderr)
        sys.exit(1)

    # Análisis inicial del mensaje
    print("\n" + "=" * 60)
    print("ANÁLISIS INICIAL DEL MENSAJE")
    print("=" * 60)
    
    msg = email.message_from_bytes(msg_bytes)
    
    # Información básica del mensaje
    print(f"From: {msg.get('From', 'No especificado')}")
    print(f"To: {msg.get('To', 'No especificado')}")
    print(f"Subject: {msg.get('Subject', 'No especificado')}")
    print(f"Date: {msg.get('Date', 'No especificado')}")
    print(f"Message-ID: {msg.get('Message-ID', 'No especificado')}")
    
    # Verificar presencia de cabeceras de autenticación
    has_arc_seal = 'ARC-Seal' in msg
    has_dkim_signature = 'DKIM-Signature' in msg
    
    print(f"\nCabeceras de autenticación encontradas:")
    print(f"  ARC-Seal: {'✓ Sí' if has_arc_seal else '✗ No'}")
    print(f"  DKIM-Signature: {'✓ Sí' if has_dkim_signature else '✗ No'}")
    
    # Mostrar otras cabeceras de autenticación relevantes
    auth_headers = ['Authentication-Results', 'Received-SPF', 'DMARC-Filter']
    for header in auth_headers:
        if header in msg:
            values = msg.get_all(header)
            print(f"  {header}: ✓ Sí ({len(values)} encontrada(s))")
            for i, value in enumerate(values, 1):
                print(f"    #{i}: {value[:100]}{'...' if len(value) > 100 else ''}")
        else:
            print(f"  {header}: ✗ No")

    verified = False
    verification_method = ""
    
    # Proceso de verificación
    if has_arc_seal:
        print(f"\n{'='*20} INICIANDO VERIFICACIÓN ARC {'='*20}")
        if verify_arc(msg_bytes):
            verified = True
            verification_method = "ARC"
        else:
            print("\n⚠ La verificación ARC falló. Intentando con DKIM si existe...")
    
    if not verified and has_dkim_signature:
        if has_arc_seal:
            print(f"\n{'='*20} INICIANDO VERIFICACIÓN DKIM (FALLBACK) {'='*20}")
        else:
            print(f"\n{'='*20} INICIANDO VERIFICACIÓN DKIM {'='*20}")
        if verify_dkim(msg_bytes):
            verified = True
            verification_method = "DKIM"
    elif not has_arc_seal and not has_dkim_signature:
        print(f"\n{'='*20} SIN FIRMAS ENCONTRADAS {'='*20}")
        print("✗ No se encontraron cabeceras 'ARC-Seal' ni 'DKIM-Signature' en el correo.")
        print("  El mensaje no tiene firmas digitales para verificar.")

    # Resultado final
    print("\n" + "=" * 80)
    print("RESULTADO FINAL")
    print("=" * 80)
    
    if verified:
        print(f"✓ SUCCESS: El correo ha sido verificado exitosamente usando {verification_method}.")
        print(f"  El mensaje es auténtico y no ha sido alterado.")
    else:
        print("✗ FAIL: No se pudo verificar el correo.")
        if has_arc_seal or has_dkim_signature:
            print("  El mensaje tiene firmas pero no pudieron ser validadas.")
            print("  Posibles causas:")
            print("  - Las firmas están corruptas o malformadas")
            print("  - No se pueden obtener las claves públicas del DNS")
            print("  - El mensaje ha sido modificado después de ser firmado")
            print("  - Problemas de conectividad con los servidores DNS")
        else:
            print("  El mensaje no contiene firmas digitales para verificar.")
    
    print("=" * 80)


if __name__ == "__main__":
    main()
