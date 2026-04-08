from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
import json
import pandas as pd
from dotenv import load_dotenv
from resultadoKPI import calcular_Indicador
import db_manager

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-dev-key')
app.config['UPLOAD_FOLDER'] = 'archivos_CSV/'
app.config['ALLOWED_EXTENSIONS'] = {'csv'}

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LAST_RESULTADO = os.path.join(_BASE_DIR, 'reportes_CSV', 'last_resultado.json')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No se encontró ningún archivo en la solicitud.')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No seleccionaste ningún archivo.')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            try:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                resultados, api_agotada = calcular_Indicador(filepath)

                if resultados or api_agotada:
                    # PRG: guardar resultado y redirigir a GET para evitar re-procesado con F5
                    os.makedirs(os.path.dirname(_LAST_RESULTADO), exist_ok=True)
                    with open(_LAST_RESULTADO, 'w', encoding='utf-8') as f:
                        json.dump({'resultados': resultados or [], 'api_agotada': api_agotada}, f)
                    flash('Archivo procesado correctamente.')
                    return redirect(url_for('ver_resultados'))
                else:
                    flash('No se pudo procesar el archivo. Revisa el contenido.')
            except Exception as e:
                flash(f'Ocurrió un error al procesar el archivo: {e}')
                return redirect(request.url)
        else:
            flash('El archivo debe tener una extensión .csv válida.')
            return redirect(request.url)

    return render_template('cargaCSV.html')


@app.route('/resultados')
def ver_resultados():
    resultados = []
    api_agotada = False
    if os.path.exists(_LAST_RESULTADO):
        try:
            with open(_LAST_RESULTADO, encoding='utf-8') as f:
                data = json.load(f)
            resultados = data.get('resultados', [])
            api_agotada = data.get('api_agotada', False)
        except Exception:
            pass
    return render_template('index.html', resultados=resultados, api_agotada=api_agotada)


@app.route('/top10')
def ver_top10():
    top10_path = os.path.join(_BASE_DIR, 'top10_ips.csv')
    resultados = []
    if os.path.exists(top10_path):
        try:
            df = pd.read_csv(top10_path)
            resultados = df.to_dict(orient='records')
        except Exception as e:
            flash(f'Error al leer el Top 10: {e}')
    return render_template('top10.html', resultados=resultados)


@app.route('/buscar')
def buscar_ip():
    ip_query = request.args.get('ip', '').strip()
    resultado = None
    if ip_query:
        resultado = db_manager.get_ip(ip_query)
    return render_template('buscar.html', ip_query=ip_query, resultado=resultado)


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('reportes_CSV', exist_ok=True)
    app.run(debug=True)
