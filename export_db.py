"""
Exporta la base de datos a db_backup.sql (texto plano, commitable a git).
Ejecutar antes de hacer git commit + push.

    python export_db.py
"""
import sqlite3
import os

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_BASE_DIR, 'ips_maliciosas.db')
BACKUP_PATH = os.path.join(_BASE_DIR, 'db_backup.sql')


def export():
    if not os.path.exists(DB_PATH):
        print("No existe la base de datos. Nada que exportar.")
        return

    with sqlite3.connect(DB_PATH) as conn:
        lines = list(conn.iterdump())

    with open(BACKUP_PATH, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    total = sum(1 for l in lines if l.startswith('INSERT'))
    print(f"Exportacion completa: {total} registros -> {BACKUP_PATH}")


if __name__ == '__main__':
    export()
