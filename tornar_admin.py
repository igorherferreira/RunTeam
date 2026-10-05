"""Transforma um usuário em administrador.  Uso:  python tornar_admin.py seu@email.com"""
import sys

from sqlalchemy import func, select

from models import SessionLocal, Usuario, preparar_banco

if len(sys.argv) != 2:
    sys.exit("Uso: python tornar_admin.py seu@email.com")
preparar_banco()
email = sys.argv[1].strip().lower()
with SessionLocal() as db:
    u = db.scalar(select(Usuario).where(func.lower(Usuario.email) == email))
    if not u:
        sys.exit(f"Nenhum usuário com o e-mail {email}. Crie a conta no app primeiro.")
    u.is_admin = True
    db.commit()
    print(f"{u.nome} agora é administrador.")
