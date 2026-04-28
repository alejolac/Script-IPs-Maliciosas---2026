import os
import json
import pandas as pd
import re
from consultaALaApi import buscarInformacionPorAPI
from datetime import datetime, date
import db_manager

patronIpOrigen = r"srcIp:\s*([^\|]+)\|"
asset_column   = 'Asset'
info_column    = 'Detail info'
detected_col   = 'Detected'
level_col      = 'Event risk level'
_BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
SCORING_PATH   = os.path.join(_BASE_DIR, 'scoring.json')

LEVEL_MAP = {'high': 'high', 'medium': 'mid', 'mid': 'mid', 'low': 'low'}


def _parse_date(val):
    try:
        return str(val)[:10]
    except Exception:
        return date.today().isoformat()


def _normalize_category(val):
    return LEVEL_MAP.get(str(val).strip().lower(), 'high')


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

    for threshold in sorted(config['actividad_reciente'], key=lambda x: x['min'], reverse=True):
        if weekly_intentos >= threshold['min']:
            score += threshold['points']
            break

    for threshold in sorted(config['abuse_reports'], key=lambda x: x['min'], reverse=True):
        if abuse_score >= threshold['min']:
            score += threshold['points']
            break

    days_ago = (date.today() - date.fromisoformat(last_seen_str)).days
    for threshold in sorted(config['recencia_dias'], key=lambda x: x['max_days']):
        if days_ago <= threshold['max_days']:
            score += threshold['points']
            break

    return score


def generar_top10(weekly_map, config, category):
    active_ips = db_manager.get_active_ips(config['max_days'], category)

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

    top10_path = os.path.join(_BASE_DIR, f'top10_ips_{category}.csv')
    if top10:
        pd.DataFrame(top10).to_csv(top10_path, index=False)
        print(f"Top 10 [{category}] generado: {top10_path}")

    return top10


def generar_top10_global(config):
    multipliers = config.get('category_multipliers', {'high': 1.2, 'mid': 1.0, 'low': 0.85})
    ip_data = {}

    for cat in db_manager.CATEGORIES:
        path = os.path.join(_BASE_DIR, f'top10_ips_{cat}.csv')
        if not os.path.exists(path):
            continue
        try:
            df = pd.read_csv(path)
        except Exception:
            continue

        multiplier = multipliers.get(cat, 1.0)
        for _, row in df.iterrows():
            ip = row['IP']
            weighted = row['Score'] * multiplier

            if ip not in ip_data:
                ip_data[ip] = {
                    'IP': ip,
                    'Score Global': weighted,
                    'Categorías': [cat],
                    'Total Intentos Histórico': row['Total Intentos Histórico'],
                    'Reportes AbuseIPDB': row['Reportes AbuseIPDB'],
                    'Confianza AbuseIPDB (%)': row['Confianza AbuseIPDB (%)'],
                    'Último Visto': row['Último Visto'],
                    'Primer Visto': row['Primer Visto'],
                }
            else:
                ip_data[ip]['Score Global'] += weighted
                ip_data[ip]['Categorías'].append(cat)
                if row['Último Visto'] > ip_data[ip]['Último Visto']:
                    ip_data[ip]['Último Visto'] = row['Último Visto']
                if row['Primer Visto'] < ip_data[ip]['Primer Visto']:
                    ip_data[ip]['Primer Visto'] = row['Primer Visto']
                ip_data[ip]['Total Intentos Histórico'] = max(
                    ip_data[ip]['Total Intentos Histórico'], row['Total Intentos Histórico']
                )
                ip_data[ip]['Reportes AbuseIPDB'] = max(
                    ip_data[ip]['Reportes AbuseIPDB'], row['Reportes AbuseIPDB']
                )

    if not ip_data:
        return []

    cat_order = {'high': 0, 'mid': 1, 'low': 2}
    for data in ip_data.values():
        data['Categorías'] = '/'.join(
            c.capitalize() for c in sorted(data['Categorías'], key=lambda c: cat_order.get(c, 9))
        )
        data['Score Global'] = round(data['Score Global'])

    top10 = sorted(ip_data.values(), key=lambda x: x['Score Global'], reverse=True)[:10]

    if top10:
        top10_path = os.path.join(_BASE_DIR, 'top10_ips_global.csv')
        pd.DataFrame(top10).to_csv(top10_path, index=False)
        print(f"Top 10 global generado: {top10_path}")

    return top10


def calcular_Indicador(csv_path):
    db_manager.init_db()

    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Error al leer el archivo CSV: {e}")
        return None, False

    # Paso 1: recolectar IPs únicas con categoría, fechas y repeticiones por categoría
    ips_encontradas = {}

    for index, row in df.iterrows():
        try:
            if pd.isna(row[asset_column]) or pd.isna(row[info_column]):
                continue

            asset    = row[asset_column].strip()
            info     = row[info_column]
            detected = _parse_date(row.get(detected_col, date.today().isoformat()))
            category = _normalize_category(row.get(level_col, 'high'))

            ip_match = re.search(patronIpOrigen, info)
            if not ip_match:
                continue

            ip = ip_match.group(1).strip()

            if ip not in ips_encontradas:
                ips_encontradas[ip] = {
                    'asset': asset,
                    'total_repeticiones': 1,
                    'cat_repeticiones': {category: 1},
                    'categories': {category},
                    'max_detected': detected,
                }
            else:
                ips_encontradas[ip]['total_repeticiones'] += 1
                ips_encontradas[ip]['cat_repeticiones'][category] = \
                    ips_encontradas[ip]['cat_repeticiones'].get(category, 0) + 1
                ips_encontradas[ip]['categories'].add(category)
                if detected > ips_encontradas[ip]['max_detected']:
                    ips_encontradas[ip]['max_detected'] = detected

        except Exception as e:
            print(f"Error en la fila {index}: {e}")
            continue

    if not ips_encontradas:
        print("No se encontraron IPs en el archivo.")
        return None, False

    print(f"IPs únicas encontradas: {len(ips_encontradas)}. Consultando API...")

    # Paso 2: ordenar por repeticiones totales descendente
    ips_ordenadas = sorted(
        ips_encontradas.items(),
        key=lambda x: x[1]['total_repeticiones'],
        reverse=True
    )

    # Paso 3: consultar la API y construir resultados
    resultados = []
    api_agotada = False
    affected_categories = set()

    for ip, datos in ips_ordenadas:
        reportes, primer_reporte, confidence, agotada = buscarInformacionPorAPI(ip)

        if agotada:
            api_agotada = True
            print("API de AbuseIPDB agotada. Se interrumpe la consulta.")
            break

        if reportes > 0:
            cat_order = {'high': 0, 'mid': 1, 'low': 2}
            cats_str = '/'.join(
                c.capitalize() for c in sorted(datos['categories'], key=lambda c: cat_order.get(c, 9))
            )
            resultados.append({
                "Maquina Virtual": datos['asset'],
                "IP": ip,
                "Categoría": cats_str,
                "Repeticiones en CSV": datos['total_repeticiones'],
                "Número de Reportes AbuseIPDB": reportes,
                "Primer Reporte": primer_reporte,
            })
            for cat in datos['categories']:
                cat_reps = datos['cat_repeticiones'].get(cat, 0)
                db_manager.upsert_ip(ip, cat_reps, reportes, confidence, cat, datos['max_detected'])
                affected_categories.add(cat)

    if not resultados and not api_agotada:
        print("Ninguna IP tiene reportes de abuso.")
        return None, False

    # Paso 4: generar CSV semanal
    if resultados:
        df_resultado = pd.DataFrame(resultados)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('reportes_CSV', exist_ok=True)
        cats_label = '_'.join(sorted(affected_categories))
        output_file = os.path.join('reportes_CSV', f"eventosIPS_{cats_label}_{timestamp}.csv")
        df_resultado.to_csv(output_file, index=False)
        print(f"Archivo semanal generado: {output_file}")

    # Paso 5: generar Top 10 por cada categoría afectada y el global
    try:
        scoring_config = cargar_scoring()
        for cat in affected_categories:
            weekly_map = {
                ip: datos['cat_repeticiones'].get(cat, 0)
                for ip, datos in ips_ordenadas
            }
            generar_top10(weekly_map, scoring_config, cat)
        generar_top10_global(scoring_config)
    except Exception as e:
        print(f"Error al generar el Top 10: {e}")

    return resultados, api_agotada
