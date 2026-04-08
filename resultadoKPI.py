import os
import json
import pandas as pd
import re
from consultaALaApi import buscarInformacionPorAPI
from datetime import datetime, date
import db_manager

# Variables
patronIpOrigen = r"srcIp:\s*([^\|]+)\|"
asset_column = 'Asset'
info_column = 'Detail info'
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCORING_PATH = os.path.join(_BASE_DIR, 'scoring.json')


def cargar_scoring():
    try:
        with open(SCORING_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"No se encontró el archivo de configuración: {SCORING_PATH}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Error al leer {SCORING_PATH}: {e}")


def calcular_score(weekly_intentos, abuse_score, last_seen_str, config):
    score = 0

    # Factor 1: Actividad reciente (mayor peso)
    for threshold in sorted(config['actividad_reciente'], key=lambda x: x['min'], reverse=True):
        if weekly_intentos >= threshold['min']:
            score += threshold['points']
            break

    # Factor 2: Reportes AbuseIPDB (segundo peso)
    for threshold in sorted(config['abuse_reports'], key=lambda x: x['min'], reverse=True):
        if abuse_score >= threshold['min']:
            score += threshold['points']
            break

    # Factor 3: Recencia — menos días desde last_seen = más puntos
    days_ago = (date.today() - date.fromisoformat(last_seen_str)).days
    for threshold in sorted(config['recencia_dias'], key=lambda x: x['max_days']):
        if days_ago <= threshold['max_days']:
            score += threshold['points']
            break

    return score


def generar_top10(weekly_map, config):
    active_ips = db_manager.get_active_ips(config['max_days'])

    scored = []
    for row in active_ips:
        ip = row['ip']
        weekly_intentos = weekly_map.get(ip, 0)
        score = calcular_score(weekly_intentos, row['abuse_score'], row['last_seen'], config)
        scored.append({
            'IP': ip,
            'Score': score,
            'Total Intentos Histórico': row['total_intentos'],
            'Reportes AbuseIPDB': row['abuse_score'],
            'Confianza AbuseIPDB (%)': row['confidence_score'],
            'Último Visto': row['last_seen'],
            'Primer Visto': row['first_seen'],
        })

    scored.sort(key=lambda x: x['Score'], reverse=True)
    top10 = scored[:10]

    if top10:
        df_top10 = pd.DataFrame(top10)
        top10_path = os.path.join(_BASE_DIR, 'top10_ips.csv')
        df_top10.to_csv(top10_path, index=False)
        print(f"Top 10 generado: {top10_path}")

    return top10


def calcular_Indicador(csv_path):
    # Inicializar DB
    db_manager.init_db()

    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Error al leer el archivo CSV: {e}")
        return None, False

    # Paso 1: recolectar todas las IPs únicas con sus repeticiones
    ips_encontradas = {}

    for index, row in df.iterrows():
        try:
            if pd.isna(row[asset_column]) or pd.isna(row[info_column]):
                continue

            asset = row[asset_column].strip()
            info = row[info_column]

            ip_origen_match = re.search(patronIpOrigen, info)
            if not ip_origen_match:
                continue

            ip = ip_origen_match.group(1).strip()

            if ip in ips_encontradas:
                ips_encontradas[ip]['repeticiones'] += 1
            else:
                ips_encontradas[ip] = {'asset': asset, 'repeticiones': 1}

        except Exception as e:
            print(f"Error en la fila {index}: {e}")
            continue

    if not ips_encontradas:
        print("No se encontraron IPs en el archivo.")
        return None, False

    print(f"IPs únicas encontradas: {len(ips_encontradas)}. Consultando API...")

    # Paso 2: ordenar por repeticiones descendente (más frecuentes primero)
    ips_ordenadas = sorted(ips_encontradas.items(), key=lambda x: x[1]['repeticiones'], reverse=True)

    # Paso 3: consultar la API y construir el reporte semanal
    resultados = []
    api_agotada = False

    for ip, datos in ips_ordenadas:
        reportes, primer_reporte, confidence, agotada = buscarInformacionPorAPI(ip)

        if agotada:
            api_agotada = True
            print("API de AbuseIPDB agotada. Se interrumpe la consulta.")
            break

        if reportes > 0:
            resultados.append({
                "Maquina Virtual": datos['asset'],
                "IP": ip,
                "Repeticiones en CSV": datos['repeticiones'],
                "Número de Reportes AbuseIPDB": reportes,
                "Primer Reporte": primer_reporte,
            })
            # Persistir en la DB (solo IPs con reportes de abuso)
            db_manager.upsert_ip(ip, datos['repeticiones'], reportes, confidence)

    if not resultados and not api_agotada:
        print("Ninguna IP tiene reportes de abuso.")
        return None, False

    # Paso 4: generar CSV semanal (sin datos históricos)
    if resultados:
        df_resultado = pd.DataFrame(resultados)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('reportes_CSV', exist_ok=True)
        output_file = os.path.join('reportes_CSV', f"eventosIPS_{timestamp}.csv")
        df_resultado.to_csv(output_file, index=False)
        print(f"Archivo semanal generado: {output_file}")

    # Paso 5: generar Top 10 desde la DB
    try:
        scoring_config = cargar_scoring()
        weekly_map = {ip: datos['repeticiones'] for ip, datos in ips_ordenadas}
        generar_top10(weekly_map, scoring_config)
    except Exception as e:
        print(f"Error al generar el Top 10: {e}")

    return resultados, api_agotada
