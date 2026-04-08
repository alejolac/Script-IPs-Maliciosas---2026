"""
Recrea la base de datos desde db_backup.sql.
Ejecutar después de hacer git pull en otro equipo.

    python import_db.py

ATENCIÓN: reemplaza completamente la DB local con la del backup.
"""
import sqlite3
import os

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_BASE_DIR, 'ips_maliciosas.db')
BACKUP_PATH = os.path.join(_BASE_DIR, 'db_backup.sql')


def importar():
    if not os.path.exists(BACKUP_PATH):
        print(f"No se encontró {BACKUP_PATH}. Hacé git pull primero.")
        return

    with open(BACKUP_PATH, 'r', encoding='utf-8') as f:
        sql = f.read()

    # Eliminar DB existente y recrear desde el backup
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(sql)

    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute("SELECT COUNT(*) FROM ips").fetchone()[0]

    print(f"Importación completa: {total} registros cargados en {DB_PATH}")


if __name__ == '__main__':
    importar()
