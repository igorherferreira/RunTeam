import os
from datetime import date, datetime

from sqlalchemy import ForeignKey, String, create_engine, false, inspect, text, true
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

# Em produção: DATABASE_URL=postgresql://user:senha@host/db?sslmode=require (Neon)
# Sem a variável, usa o SQLite local.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./atletas.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300)
SessionLocal = sessionmaker(bind=engine, autoflush=False)


class Base(DeclarativeBase):
    pass


class Usuario(Base):
    __tablename__ = "usuarios"
    id: Mapped[int] = mapped_column(primary_key=True)
    nome: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    senha_hash: Mapped[str]
    cidade: Mapped[str] = mapped_column(String(80), index=True)
    esporte: Mapped[str] = mapped_column(String(40), default="corrida")
    foto_perfil: Mapped[str | None]
    is_admin: Mapped[bool] = mapped_column(default=False, server_default=false())
    ativo: Mapped[bool] = mapped_column(default=True, server_default=true())


class Corrida(Base):
    __tablename__ = "corridas"
    id: Mapped[int] = mapped_column(primary_key=True)
    usuario_id: Mapped[int] = mapped_column(ForeignKey("usuarios.id"), index=True)
    distancia_km: Mapped[float] = mapped_column(index=True)
    tempo_seg: Mapped[int]
    data: Mapped[date] = mapped_column(default=date.today)
    legenda: Mapped[str | None]
    comprovante_url: Mapped[str | None]
    trajeto: Mapped[str | None]  # JSON resumido: [[lat,lng],...]
    origem: Mapped[str] = mapped_column(String(10), default="manual", server_default="manual")
    criado_em: Mapped[datetime] = mapped_column(default=datetime.now)
    fotos: Mapped[list["Foto"]] = relationship(lazy="selectin")


class Foto(Base):
    __tablename__ = "fotos"
    id: Mapped[int] = mapped_column(primary_key=True)
    corrida_id: Mapped[int] = mapped_column(ForeignKey("corridas.id"), index=True)
    url: Mapped[str]


class Curtida(Base):
    __tablename__ = "curtidas"
    usuario_id: Mapped[int] = mapped_column(ForeignKey("usuarios.id"), primary_key=True)
    corrida_id: Mapped[int] = mapped_column(ForeignKey("corridas.id"), primary_key=True)


class Turma(Base):
    __tablename__ = "turmas"
    id: Mapped[int] = mapped_column(primary_key=True)
    criador_id: Mapped[int] = mapped_column(ForeignKey("usuarios.id"))
    cidade: Mapped[str] = mapped_column(String(80), index=True)
    local: Mapped[str] = mapped_column(String(150))
    horario: Mapped[datetime]
    nivel: Mapped[str] = mapped_column(String(20))
    vagas: Mapped[int]


class TurmaMembro(Base):
    __tablename__ = "turma_membros"
    turma_id: Mapped[int] = mapped_column(ForeignKey("turmas.id"), primary_key=True)
    usuario_id: Mapped[int] = mapped_column(ForeignKey("usuarios.id"), primary_key=True)


class Campeonato(Base):
    __tablename__ = "campeonatos"
    id: Mapped[int] = mapped_column(primary_key=True)
    divulgador_id: Mapped[int] = mapped_column(ForeignKey("usuarios.id"))
    nome: Mapped[str] = mapped_column(String(150))
    cidade: Mapped[str] = mapped_column(String(80), index=True)
    data: Mapped[date]
    link: Mapped[str | None]


class Anuncio(Base):
    __tablename__ = "anuncios"
    id: Mapped[int] = mapped_column(primary_key=True)
    anunciante: Mapped[str] = mapped_column(String(100))
    titulo: Mapped[str] = mapped_column(String(120))
    texto: Mapped[str | None] = mapped_column(String(300))
    imagem_url: Mapped[str | None]
    link: Mapped[str]
    cidade: Mapped[str | None] = mapped_column(String(80), index=True)  # vazio = todas as cidades
    inicio: Mapped[date | None]
    fim: Mapped[date | None]
    ativo: Mapped[bool] = mapped_column(default=True)
    impressoes: Mapped[int] = mapped_column(default=0)
    cliques: Mapped[int] = mapped_column(default=0)
    criado_em: Mapped[datetime] = mapped_column(default=datetime.now)


def preparar_banco():
    """Cria tabelas novas e adiciona colunas novas em bancos já existentes."""
    Base.metadata.create_all(engine)
    colunas = {c["name"] for c in inspect(engine).get_columns("usuarios")}
    with engine.begin() as con:
        if "is_admin" not in colunas:
            con.execute(text("ALTER TABLE usuarios ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE"))
        if "ativo" not in colunas:
            con.execute(text("ALTER TABLE usuarios ADD COLUMN ativo BOOLEAN NOT NULL DEFAULT TRUE"))
        corridas = {c["name"] for c in inspect(con).get_columns("corridas")}
        if "trajeto" not in corridas:
            con.execute(text("ALTER TABLE corridas ADD COLUMN trajeto VARCHAR"))
        if "origem" not in corridas:
            con.execute(text("ALTER TABLE corridas ADD COLUMN origem VARCHAR(10) NOT NULL DEFAULT 'manual'"))