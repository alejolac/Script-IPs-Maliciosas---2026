import requests
import logging
import os
from dotenv import load_dotenv

load_dotenv()

# Configuración del logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Definición del endpoint de la API y la clave
url = 'https://api.abuseipdb.com/api/v2/check'
api_key = os.getenv('ABUSEIPDB_API_KEY')

if not api_key:
    raise ValueError("No se encontró ABUSEIPDB_API_KEY en el archivo .env")

headers = {
    'Accept': 'application/json',
    'Key': api_key
}

def buscarInformacionPorAPI(ip):
    """
    Consulta la API de AbuseIPDB para obtener información sobre una IP.
    
    Args:
        ip (str): Dirección IP a consultar.
    
    Returns:
        tuple: Número de reportes y fecha del primer reporte.
    """
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '365',
        'verbose': '1'
    }

    # Valores predeterminados en caso de fallo
    cantidadDeReportes = 0
    primerReporte = "Sin información"
    confidenceScore = 0
    apiAgotada = False

    try:
        logging.info(f"Consultando información para la IP: {ip}")
        response = requests.get(url, headers=headers, params=querystring, timeout=10)

        if response.status_code == 200:
            data = response.json().get('data', {})

            cantidadDeReportes = data.get('totalReports', 0)
            confidenceScore = data.get('abuseConfidenceScore', 0)
            reports = data.get('reports', [])

            if reports:
                # Ordenar los reportes por fecha (ascendente)
                reports_sorted = sorted(reports, key=lambda x: x['reportedAt'])
                primerReporte = reports_sorted[0]['reportedAt'][:10]
        elif response.status_code == 429:
            logging.warning("Límite de llamadas a la API de AbuseIPDB agotado (429).")
            apiAgotada = True
        else:
            logging.warning(f"Error en la respuesta de la API: {response.status_code} - {response.text}")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error de red al consultar la API: {e}")
    except Exception as e:
        logging.error(f"Error inesperado al procesar la información de la API: {e}")

    return cantidadDeReportes, primerReporte, confidenceScore, apiAgotada
