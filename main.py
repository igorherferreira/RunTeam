import json
import math
import os
import uuid
from datetime import date, datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, EmailStr, Field, computed_field
from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.orm import Session

from models import (Anuncio, Base, Campeonato, Corrida, Curtida, CurtidaPublicacao, Desafio,
                    DesafioParticipante, Foto, Publicacao, SessionLocal, Seguidor, Turma, TurmaMembro,
                    Usuario, engine, preparar_banco)

SECRET_KEY = os.getenv("SECRET_KEY", "troque-esta-chave-em-producao")
TOLERANCIA_PROVA = 1.03  # 10,2 km conta como prova de 10 km; 10,5 km não
VEL_MAX_KMH = 30  # acima disso não é corrida a pé (carro, bicicleta, GPS falso)
TIPOS_IMAGEM = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()  # este e-mail vira administrador
preparar_banco()
if ADMIN_EMAIL:
    with SessionLocal() as _db:
        _u = _db.scalar(select(Usuario).where(func.lower(Usuario.email) == ADMIN_EMAIL))
        if _u and not _u.is_admin:
            _u.is_admin = True
            _db.commit()
os.makedirs("uploads", exist_ok=True)

app = FastAPI(title="Atletas API")
# O app Android abre de https://localhost e conversa com este servidor. Outras origens: CORS_ORIGINS="https://a.com,https://b.com"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost", "http://localhost", "capacitor://localhost"]
    + [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()],
    allow_methods=["*"], allow_headers=["*"],
)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def usuario_atual(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> Usuario:
    try:
        uid = int(jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(401, "Token inválido ou expirado")
    usuario = db.get(Usuario, uid)
    if not usuario:
        raise HTTPException(401, "Usuário não encontrado")
    if not usuario.ativo:
        raise HTTPException(403, "Conta suspensa")
    return usuario


oauth2_opt = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def usuario_opcional(token: str | None = Depends(oauth2_opt),
                     db: Session = Depends(get_db)) -> Usuario | None:
    if not token:
        return None
    try:
        return usuario_atual(token, db)
    except HTTPException:
        return None


def so_admin(u: Usuario = Depends(usuario_atual)) -> Usuario:
    if not u.is_admin:
        raise HTTPException(403, "Acesso restrito a administradores")
    return u


MAX_IMAGEM = 5 * 1024 * 1024  # 5 MB


def salvar_imagem(arquivo: UploadFile) -> str:
    ext = TIPOS_IMAGEM.get(arquivo.content_type)
    if not ext:
        raise HTTPException(415, "Envie uma imagem JPG, PNG ou WEBP")
    conteudo = arquivo.file.read(MAX_IMAGEM + 1)
    if len(conteudo) > MAX_IMAGEM:
        raise HTTPException(413, "A imagem deve ter até 5 MB")
    nome = f"{uuid.uuid4().hex}{ext}"
    with open(os.path.join("uploads", nome), "wb") as f:
        f.write(conteudo)
    return f"/uploads/{nome}"


# ---------- Schemas ----------
class CadastroIn(BaseModel):
    nome: str = Field(min_length=2, max_length=100)
    email: EmailStr
    senha: str = Field(min_length=6)
    cidade: str
    esporte: str = "corrida"


class CorridaIn(BaseModel):
    distancia_km: float = Field(gt=0, le=300)
    tempo_seg: int = Field(gt=0)
    data: date | None = None
    legenda: str | None = None
    comprovante_url: str | None = None
    trajeto: list[list[float]] | None = Field(None, max_length=15000)  # [lat, lng(, 1 = novo trecho)]


class CorridaOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    usuario_id: int
    distancia_km: float
    tempo_seg: int
    data: date
    legenda: str | None
    origem: str

    @computed_field
    @property
    def pace_seg_km(self) -> int:
        return round(self.tempo_seg / self.distancia_km)


class TurmaIn(BaseModel):
    local: str
    horario: datetime
    nivel: str = Field(pattern="^(iniciante|intermediario|avancado)$")
    vagas: int = Field(gt=1, le=200)
    esporte: str = Field("corrida", pattern="^(corrida|futebol|academia)$")


class CampeonatoIn(BaseModel):
    nome: str
    cidade: str
    data: date
    link: str | None = None
    esporte: str = Field("corrida", pattern="^(corrida|futebol|academia)$")


# ---------- Auth ----------
@app.post("/auth/cadastro", status_code=201)
def cadastro(dados: CadastroIn, db: Session = Depends(get_db)):
    if db.scalar(select(Usuario).where(Usuario.email == dados.email)):
        raise HTTPException(409, "E-mail já cadastrado")
    senha_hash = bcrypt.hashpw(dados.senha.encode(), bcrypt.gensalt()).decode()
    u = Usuario(nome=dados.nome, email=dados.email, senha_hash=senha_hash,
                cidade=dados.cidade, esporte=dados.esporte,
                is_admin=bool(ADMIN_EMAIL) and dados.email.lower() == ADMIN_EMAIL)
    db.add(u)
    db.commit()
    return {"id": u.id, "nome": u.nome}


@app.post("/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    u = db.scalar(select(Usuario).where(Usuario.email == form.username))
    if not u or not bcrypt.checkpw(form.password.encode(), u.senha_hash.encode()):
        raise HTTPException(401, "E-mail ou senha incorretos")
    if not u.ativo:
        raise HTTPException(403, "Conta suspensa")
    exp = datetime.now(timezone.utc) + timedelta(days=7)
    token = jwt.encode({"sub": str(u.id), "exp": exp}, SECRET_KEY, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer"}


# ---------- Perfil ----------
@app.get("/usuarios/me")
def meu_perfil(u: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    seguindo_ids = db.scalars(select(Seguidor.seguido_id).where(Seguidor.seguidor_id == u.id)).all()
    return {**perfil(u.id, db), "is_admin": u.is_admin, "seguindo_ids": list(seguindo_ids)}


@app.get("/usuarios/{usuario_id}")
def perfil(usuario_id: int, db: Session = Depends(get_db)):
    u = db.get(Usuario, usuario_id)
    if not u:
        raise HTTPException(404, "Atleta não encontrado")
    total, km = db.execute(
        select(func.count(Corrida.id), func.coalesce(func.sum(Corrida.distancia_km), 0))
        .where(Corrida.usuario_id == u.id)).one()
    fotos = db.scalars(select(Foto.url).join(Corrida).where(Corrida.usuario_id == u.id)
                       .order_by(Foto.id.desc()).limit(30)).all()
    return {"id": u.id, "nome": u.nome, "cidade": u.cidade, "esporte": u.esporte,
            "foto_perfil": u.foto_perfil, "total_corridas": total,
            "km_total": round(km, 1), "fotos": fotos, **estatisticas(db, u.id)}


@app.post("/usuarios/me/foto")
def foto_de_perfil(arquivo: UploadFile = File(...), u: Usuario = Depends(usuario_atual),
                   db: Session = Depends(get_db)):
    u.foto_perfil = salvar_imagem(arquivo)
    db.commit()
    return {"url": u.foto_perfil}


# ---------- GPS ----------
def _hav_km(a, b) -> float:
    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 12742.0176 * math.asin(math.sqrt(h))


def validar_trajeto(bruto):
    pts = []
    for p in bruto:
        if len(p) < 2 or not (-90 <= p[0] <= 90 and -180 <= p[1] <= 180):
            raise HTTPException(422, "Trajeto inválido")
        pts.append((p[0], p[1], len(p) > 2 and p[2] == 1))  # 3º valor 1 = novo trecho (após pausa)
    return pts


def calc_distancia_km(pts) -> float:
    return sum(_hav_km(pts[i], pts[i + 1]) for i in range(len(pts) - 1) if not pts[i + 1][2])


def resumir_trajeto(pts, n=150):
    if len(pts) > n:
        passo = (len(pts) - 1) / (n - 1)
        manter = {round(i * passo) for i in range(n)} | {i for i, p in enumerate(pts) if p[2]}
        pts = [pts[i] for i in sorted(manter)]
    return [[round(p[0], 5), round(p[1], 5), 1] if p[2] else [round(p[0], 5), round(p[1], 5)]
            for p in pts]


# ---------- Corridas ----------
@app.post("/corridas", response_model=CorridaOut, status_code=201)
def registrar_corrida(dados: CorridaIn, u: Usuario = Depends(usuario_atual),
                      db: Session = Depends(get_db)):
    distancia, origem, trajeto = dados.distancia_km, "manual", None
    if dados.trajeto:  # corrida gravada por GPS: a distância é recalculada aqui no servidor
        pts = validar_trajeto(dados.trajeto)
        distancia = round(calc_distancia_km(pts), 2)
        if distancia < 0.1:
            raise HTTPException(422, "Trajeto muito curto para registrar")
        if distancia / (dados.tempo_seg / 3600) > VEL_MAX_KMH:
            raise HTTPException(422, "Velocidade média incompatível com uma corrida a pé")
        origem, trajeto = "gps", json.dumps(resumir_trajeto(pts), separators=(",", ":"))
    corrida = Corrida(usuario_id=u.id, distancia_km=distancia, origem=origem, trajeto=trajeto,
                      tempo_seg=dados.tempo_seg, data=dados.data or date.today(),
                      legenda=dados.legenda, comprovante_url=dados.comprovante_url)
    db.add(corrida)
    db.commit()
    return corrida


@app.post("/corridas/{corrida_id}/fotos", status_code=201)
def enviar_foto(corrida_id: int, arquivo: UploadFile = File(...),
                u: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    corrida = db.get(Corrida, corrida_id)
    if not corrida or corrida.usuario_id != u.id:
        raise HTTPException(404, "Corrida não encontrada")
    foto = Foto(corrida_id=corrida.id, url=salvar_imagem(arquivo))
    db.add(foto)
    db.commit()
    return {"url": foto.url}


@app.post("/corridas/{corrida_id}/curtir")
def curtir(corrida_id: int, u: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    if not db.get(Corrida, corrida_id):
        raise HTTPException(404, "Corrida não encontrada")
    curtida = db.get(Curtida, (u.id, corrida_id))
    if curtida:
        db.delete(curtida)
    else:
        db.add(Curtida(usuario_id=u.id, corrida_id=corrida_id))
    db.commit()
    return {"curtiu": curtida is None}


@app.get("/feed")
def feed(cidade: str | None = None, limite: int = 20, seguindo: bool = False,
         u: Usuario | None = Depends(usuario_opcional), db: Session = Depends(get_db)):
    q = (select(Corrida, Usuario.nome, Usuario.foto_perfil).join(Usuario, Usuario.id == Corrida.usuario_id)
         .order_by(Corrida.criado_em.desc()).limit(min(limite, 50)))
    if cidade:
        q = q.where(Usuario.cidade == cidade)
    if seguindo:
        if not u:
            raise HTTPException(401, "Entre na sua conta para ver quem você segue")
        q = q.where(or_(Corrida.usuario_id == u.id,
                        Corrida.usuario_id.in_(select(Seguidor.seguido_id)
                                               .where(Seguidor.seguidor_id == u.id))))
    q = q.where(Usuario.ativo.is_(True))
    itens = []
    for corrida, nome, foto_atleta in db.execute(q):  # N+1 aceitável no MVP; otimize depois
        curtidas = db.scalar(select(func.count()).select_from(Curtida)
                             .where(Curtida.corrida_id == corrida.id))
        itens.append({**CorridaOut.model_validate(corrida).model_dump(),
                      "atleta": nome, "atleta_foto": foto_atleta,
                      "trajeto": json.loads(corrida.trajeto) if corrida.trajeto else None, "fotos": [f.url for f in corrida.fotos],
                      "curtidas": curtidas})
    return itens


# ---------- Ranking ----------
@app.get("/ranking")
def ranking(distancia_km: float = 10, cidade: str | None = None,
            limite: int = 50, somente_gps: bool = False, db: Session = Depends(get_db)):
    melhor = func.min(Corrida.tempo_seg)
    q = (select(Usuario.id, Usuario.nome, Usuario.foto_perfil, melhor)
         .join(Corrida, Corrida.usuario_id == Usuario.id)
         .where(Corrida.distancia_km >= distancia_km,
                Corrida.distancia_km <= distancia_km * TOLERANCIA_PROVA)
         .group_by(Usuario.id, Usuario.nome, Usuario.foto_perfil).order_by(melhor).limit(min(limite, 100)))
    if cidade:
        q = q.where(Usuario.cidade == cidade)
    if somente_gps:
        q = q.where(Corrida.origem == "gps")
    q = q.where(Usuario.ativo.is_(True))
    return [{"posicao": i, "usuario_id": uid, "nome": nome, "foto": foto, "tempo_seg": tempo}
            for i, (uid, nome, foto, tempo) in enumerate(db.execute(q), start=1)]


# ---------- Turmas ----------
@app.post("/turmas", status_code=201)
def criar_turma(dados: TurmaIn, u: Usuario = Depends(usuario_atual),
                db: Session = Depends(get_db)):
    turma = Turma(criador_id=u.id, cidade=u.cidade, **dados.model_dump())
    db.add(turma)
    db.flush()
    db.add(TurmaMembro(turma_id=turma.id, usuario_id=u.id))
    db.commit()
    return {"id": turma.id}


@app.get("/turmas")
def listar_turmas(cidade: str | None = None, esporte: str = "corrida", db: Session = Depends(get_db)):
    membros = (select(func.count()).select_from(TurmaMembro)
               .where(TurmaMembro.turma_id == Turma.id).scalar_subquery())
    q = (select(Turma, membros).where(Turma.horario >= datetime.now())
         .order_by(Turma.horario).limit(50))
    if cidade:
        q = q.where(Turma.cidade == cidade)
    q = q.where(Turma.esporte == esporte)
    return [{"id": t.id, "local": t.local, "horario": t.horario, "nivel": t.nivel,
             "vagas": t.vagas, "inscritos": n} for t, n in db.execute(q)]


@app.post("/turmas/{turma_id}/entrar")
def entrar_turma(turma_id: int, u: Usuario = Depends(usuario_atual),
                 db: Session = Depends(get_db)):
    turma = db.get(Turma, turma_id)
    if not turma or turma.horario < datetime.now():
        raise HTTPException(404, "Turma não disponível")
    if db.get(TurmaMembro, (turma_id, u.id)):
        raise HTTPException(409, "Você já está nesta turma")
    inscritos = db.scalar(select(func.count()).select_from(TurmaMembro)
                          .where(TurmaMembro.turma_id == turma_id))
    if inscritos >= turma.vagas:
        raise HTTPException(409, "Turma lotada")
    db.add(TurmaMembro(turma_id=turma_id, usuario_id=u.id))
    db.commit()
    return {"inscritos": inscritos + 1}


# ---------- Campeonatos ----------
@app.post("/campeonatos", status_code=201)
def divulgar_campeonato(dados: CampeonatoIn, u: Usuario = Depends(usuario_atual),
                        db: Session = Depends(get_db)):
    camp = Campeonato(divulgador_id=u.id, **dados.model_dump())
    db.add(camp)
    db.commit()
    return {"id": camp.id}


@app.get("/campeonatos")
def listar_campeonatos(cidade: str | None = None, esporte: str = "corrida", db: Session = Depends(get_db)):
    q = (select(Campeonato).where(Campeonato.data >= date.today(), Campeonato.esporte == esporte)
         .order_by(Campeonato.data))
    if cidade:
        q = q.where(Campeonato.cidade == cidade)
    return [{"id": c.id, "nome": c.nome, "cidade": c.cidade, "data": c.data, "link": c.link}
            for c in db.scalars(q)]


# ---------- Futebol e Academia: publicações com foto e vídeo curto ----------
CATEGORIAS = {"futebol": ("jogo", "treino", "lance"), "academia": ("treino", "evolucao", "dica")}
TIPOS_VIDEO = {"video/mp4": ".mp4", "video/webm": ".webm", "video/quicktime": ".mov"}
MAX_FOTO_PUB = 10 * 1024 * 1024
MAX_VIDEO = 30 * 1024 * 1024


def salvar_midia(arquivo: UploadFile) -> tuple[str, str]:
    if arquivo.content_type in TIPOS_VIDEO:
        ext, tipo, limite = TIPOS_VIDEO[arquivo.content_type], "video", MAX_VIDEO
    elif arquivo.content_type in TIPOS_IMAGEM:
        ext, tipo, limite = TIPOS_IMAGEM[arquivo.content_type], "foto", MAX_FOTO_PUB
    else:
        raise HTTPException(415, "Envie uma foto (JPG, PNG, WEBP) ou um vídeo curto (MP4, WEBM, MOV)")
    conteudo = arquivo.file.read(limite + 1)
    if len(conteudo) > limite:
        raise HTTPException(413, f"O arquivo deve ter até {limite // (1024 * 1024)} MB")
    nome = f"{uuid.uuid4().hex}{ext}"
    with open(os.path.join("uploads", nome), "wb") as f:
        f.write(conteudo)
    return f"/uploads/{nome}", tipo


def _remover_arquivo(url: str | None) -> None:
    if url and url.startswith("/uploads/"):
        try:
            os.remove(os.path.join("uploads", os.path.basename(url)))
        except OSError:
            pass


@app.post("/publicacoes", status_code=201)
def criar_publicacao(esporte: str = Form(...), midia: UploadFile = File(...),
                     legenda: str | None = Form(None, max_length=300),
                     categoria: str | None = Form(None),
                     u: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    if esporte not in CATEGORIAS:
        raise HTTPException(422, "Esporte inválido")
    if categoria and categoria not in CATEGORIAS[esporte]:
        raise HTTPException(422, "Categoria inválida para este esporte")
    url, tipo = salvar_midia(midia)
    p = Publicacao(usuario_id=u.id, esporte=esporte, tipo=tipo, midia_url=url,
                   legenda=(legenda or "").strip() or None, categoria=categoria or None)
    db.add(p)
    db.commit()
    return {"id": p.id, "url": url, "tipo": tipo}


@app.get("/publicacoes")
def listar_publicacoes(esporte: str, usuario_id: int | None = None, seguindo: bool = False,
                       limite: int = 30, u: Usuario | None = Depends(usuario_opcional),
                       db: Session = Depends(get_db)):
    if esporte not in CATEGORIAS:
        raise HTTPException(422, "Esporte inválido")
    q = (select(Publicacao, Usuario.nome, Usuario.foto_perfil)
         .join(Usuario, Usuario.id == Publicacao.usuario_id)
         .where(Publicacao.esporte == esporte, Usuario.ativo.is_(True))
         .order_by(Publicacao.id.desc()).limit(min(limite, 60)))
    if usuario_id:
        q = q.where(Publicacao.usuario_id == usuario_id)
    if seguindo:
        if not u:
            raise HTTPException(401, "Entre na sua conta para ver quem você segue")
        q = q.where(or_(Publicacao.usuario_id == u.id,
                        Publicacao.usuario_id.in_(select(Seguidor.seguido_id)
                                                  .where(Seguidor.seguidor_id == u.id))))
    linhas = db.execute(q).all()
    ids = [p.id for p, _, _ in linhas]
    curtidas = dict(db.execute(select(CurtidaPublicacao.publicacao_id, func.count())
                               .where(CurtidaPublicacao.publicacao_id.in_(ids))
                               .group_by(CurtidaPublicacao.publicacao_id)).all()) if ids else {}
    meus = set(db.scalars(select(CurtidaPublicacao.publicacao_id)
                          .where(CurtidaPublicacao.usuario_id == u.id,
                                 CurtidaPublicacao.publicacao_id.in_(ids)))) if (u and ids) else set()
    return [{"id": p.id, "usuario_id": p.usuario_id, "atleta": nome, "atleta_foto": foto,
             "esporte": p.esporte, "tipo": p.tipo, "midia": p.midia_url, "legenda": p.legenda,
             "categoria": p.categoria, "criado_em": p.criado_em.isoformat() + "Z",
             "curtidas": curtidas.get(p.id, 0), "curtiu": p.id in meus}
            for p, nome, foto in linhas]


@app.post("/publicacoes/{publicacao_id}/curtir")
def curtir_publicacao(publicacao_id: int, u: Usuario = Depends(usuario_atual),
                      db: Session = Depends(get_db)):
    if not db.scalar(select(Publicacao.id).where(Publicacao.id == publicacao_id)):
        raise HTTPException(404, "Publicação não encontrada")
    curtida = db.get(CurtidaPublicacao, (u.id, publicacao_id))
    if curtida:
        db.delete(curtida)
    else:
        db.add(CurtidaPublicacao(usuario_id=u.id, publicacao_id=publicacao_id))
    db.commit()
    return {"curtiu": curtida is None}


@app.delete("/publicacoes/{publicacao_id}")
def apagar_publicacao(publicacao_id: int, u: Usuario = Depends(usuario_atual),
                      db: Session = Depends(get_db)):
    p = db.get(Publicacao, publicacao_id)
    if not p:
        raise HTTPException(404, "Publicação não encontrada")
    if p.usuario_id != u.id and not u.is_admin:
        raise HTTPException(403, "Você só pode apagar as suas publicações")
    url = p.midia_url
    db.execute(delete(CurtidaPublicacao).where(CurtidaPublicacao.publicacao_id == publicacao_id))
    db.execute(delete(Publicacao).where(Publicacao.id == publicacao_id))
    db.commit()
    _remover_arquivo(url)  # apaga também o arquivo de foto/vídeo
    return {"ok": True}


@app.get("/destaques")
def destaques(esporte: str, db: Session = Depends(get_db)):
    if esporte not in CATEGORIAS:
        raise HTTPException(422, "Esporte inválido")
    n_curtidas = func.count(CurtidaPublicacao.usuario_id)
    n_posts = func.count(func.distinct(Publicacao.id))
    q = (select(Usuario.id, Usuario.nome, Usuario.foto_perfil, n_posts, n_curtidas)
         .join(Publicacao, Publicacao.usuario_id == Usuario.id)
         .outerjoin(CurtidaPublicacao, CurtidaPublicacao.publicacao_id == Publicacao.id)
         .where(Publicacao.esporte == esporte, Usuario.ativo.is_(True))
         .group_by(Usuario.id, Usuario.nome, Usuario.foto_perfil)
         .order_by(n_curtidas.desc(), n_posts.desc()).limit(30))
    return [{"usuario_id": i, "nome": n, "foto": f, "posts": p, "curtidas": c}
            for i, n, f, p, c in db.execute(q)]


# ---------- Estatísticas, seguidores e desafios ----------
def _km_desafio(db: Session, d: Desafio, uid: int) -> float:
    return db.scalar(select(func.coalesce(func.sum(Corrida.distancia_km), 0))
                     .where(Corrida.usuario_id == uid, Corrida.data >= d.inicio,
                            Corrida.data <= d.fim)) or 0


def estatisticas(db: Session, uid: int) -> dict:
    hoje = date.today()
    seguidores = db.scalar(select(func.count()).select_from(Seguidor).where(Seguidor.seguido_id == uid))
    seguindo = db.scalar(select(func.count()).select_from(Seguidor).where(Seguidor.seguidor_id == uid))
    por_dia = dict(db.execute(
        select(Corrida.data, func.sum(Corrida.distancia_km))
        .where(Corrida.usuario_id == uid, Corrida.data >= hoje - timedelta(days=400))
        .group_by(Corrida.data)).all())
    semana = [{"d": (hoje - timedelta(days=i)).isoformat(),
               "km": round(por_dia.get(hoje - timedelta(days=i), 0), 1)} for i in range(6, -1, -1)]
    dia = hoje if hoje in por_dia else hoje - timedelta(days=1)  # a sequência só quebra se passar um dia inteiro sem correr
    sequencia = 0
    while dia in por_dia:
        sequencia += 1
        dia -= timedelta(days=1)
    concluidos = sum(1 for d in db.scalars(
        select(Desafio).join(DesafioParticipante, DesafioParticipante.desafio_id == Desafio.id)
        .where(DesafioParticipante.usuario_id == uid)) if _km_desafio(db, d, uid) >= d.meta_km)
    return {"seguidores": seguidores, "seguindo": seguindo, "sequencia": sequencia,
            "semana": semana, "desafios_concluidos": concluidos}


@app.post("/usuarios/{usuario_id}/seguir")
def seguir(usuario_id: int, u: Usuario = Depends(usuario_atual), db: Session = Depends(get_db)):
    alvo = db.get(Usuario, usuario_id)
    if not alvo or not alvo.ativo:
        raise HTTPException(404, "Atleta não encontrado")
    if alvo.id == u.id:
        raise HTTPException(400, "Você não pode seguir a si mesmo")
    rel = db.get(Seguidor, (u.id, alvo.id))
    if rel:
        db.delete(rel)
    else:
        db.add(Seguidor(seguidor_id=u.id, seguido_id=alvo.id))
    db.commit()
    total = db.scalar(select(func.count()).select_from(Seguidor).where(Seguidor.seguido_id == alvo.id))
    return {"seguindo": rel is None, "seguidores": total}


class DesafioIn(BaseModel):
    titulo: str = Field(min_length=3, max_length=100)
    descricao: str | None = Field(None, max_length=200)
    meta_km: float = Field(gt=0, le=10000)
    inicio: date
    fim: date


@app.get("/desafios")
def listar_desafios(u: Usuario | None = Depends(usuario_opcional), db: Session = Depends(get_db)):
    res = []
    for d in db.scalars(select(Desafio).where(Desafio.ativo.is_(True), Desafio.fim >= date.today())
                        .order_by(Desafio.fim)):
        participantes = db.scalar(select(func.count()).select_from(DesafioParticipante)
                                  .where(DesafioParticipante.desafio_id == d.id))
        participando = bool(u and db.get(DesafioParticipante, (d.id, u.id)))
        km = _km_desafio(db, d, u.id) if participando else 0
        res.append({"id": d.id, "titulo": d.titulo, "descricao": d.descricao, "meta_km": d.meta_km,
                    "inicio": d.inicio, "fim": d.fim, "participantes": participantes,
                    "participando": participando, "meu_km": round(km, 1), "concluido": km >= d.meta_km})
    return res


@app.post("/desafios/{desafio_id}/participar")
def participar_desafio(desafio_id: int, u: Usuario = Depends(usuario_atual),
                       db: Session = Depends(get_db)):
    d = db.get(Desafio, desafio_id)
    if not d or not d.ativo or d.fim < date.today():
        raise HTTPException(404, "Desafio não disponível")
    if not db.get(DesafioParticipante, (d.id, u.id)):
        db.add(DesafioParticipante(desafio_id=d.id, usuario_id=u.id))
        db.commit()
    return {"ok": True}


@app.get("/desafios/{desafio_id}/ranking")
def ranking_desafio(desafio_id: int, db: Session = Depends(get_db)):
    d = db.get(Desafio, desafio_id)
    if not d:
        raise HTTPException(404, "Desafio não encontrado")
    km = func.coalesce(func.sum(Corrida.distancia_km), 0)
    q = (select(Usuario.id, Usuario.nome, Usuario.foto_perfil, km)
         .join(DesafioParticipante, DesafioParticipante.usuario_id == Usuario.id)
         .outerjoin(Corrida, and_(Corrida.usuario_id == Usuario.id,
                                  Corrida.data >= d.inicio, Corrida.data <= d.fim))
         .where(DesafioParticipante.desafio_id == desafio_id, Usuario.ativo.is_(True))
         .group_by(Usuario.id, Usuario.nome, Usuario.foto_perfil).order_by(km.desc()).limit(20))
    return [{"usuario_id": uid, "nome": nome, "foto": foto, "km": round(total, 1)}
            for uid, nome, foto, total in db.execute(q)]


@app.post("/admin/desafios", status_code=201)
def admin_criar_desafio(dados: DesafioIn, admin: Usuario = Depends(so_admin),
                        db: Session = Depends(get_db)):
    if dados.fim < dados.inicio:
        raise HTTPException(422, "A data final deve ser depois da inicial")
    d = Desafio(**dados.model_dump())
    db.add(d)
    db.commit()
    return {"id": d.id}


@app.delete("/admin/desafios/{desafio_id}")
def admin_excluir_desafio(desafio_id: int, admin: Usuario = Depends(so_admin),
                          db: Session = Depends(get_db)):
    return _excluir(db, Desafio, desafio_id,
                    [(DesafioParticipante, DesafioParticipante.desafio_id)])


# ---------- Anúncios (público) ----------
def anuncio_dict(a: Anuncio) -> dict:
    return {"id": a.id, "anunciante": a.anunciante, "titulo": a.titulo,
            "texto": a.texto, "imagem": a.imagem_url, "link": a.link}


@app.get("/anuncios")
def anuncios_ativos(cidade: str | None = None, db: Session = Depends(get_db)):
    hoje = date.today()
    q = select(Anuncio).where(Anuncio.ativo.is_(True),
                              or_(Anuncio.inicio.is_(None), Anuncio.inicio <= hoje),
                              or_(Anuncio.fim.is_(None), Anuncio.fim >= hoje))
    if cidade:
        q = q.where(or_(Anuncio.cidade.is_(None), func.lower(Anuncio.cidade) == cidade.lower()))
    else:
        q = q.where(Anuncio.cidade.is_(None))
    return [anuncio_dict(a) for a in db.scalars(q.order_by(func.random()).limit(6))]


@app.post("/anuncios/{anuncio_id}/impressao")
def anuncio_impressao(anuncio_id: int, db: Session = Depends(get_db)):
    db.execute(update(Anuncio).where(Anuncio.id == anuncio_id)
               .values(impressoes=Anuncio.impressoes + 1))
    db.commit()
    return {"ok": True}


@app.post("/anuncios/{anuncio_id}/clique")
def anuncio_clique(anuncio_id: int, db: Session = Depends(get_db)):
    db.execute(update(Anuncio).where(Anuncio.id == anuncio_id)
               .values(cliques=Anuncio.cliques + 1))
    db.commit()
    return {"ok": True}


# ---------- Administração ----------
def _excluir(db: Session, modelo, id_: int, filhos=()):
    if not db.scalar(select(modelo.id).where(modelo.id == id_)):
        raise HTTPException(404, "Item não encontrado")
    for filho, coluna in filhos:
        db.execute(delete(filho).where(coluna == id_))
    db.execute(delete(modelo).where(modelo.id == id_))
    db.commit()
    return {"ok": True}


@app.get("/admin/resumo")
def admin_resumo(admin: Usuario = Depends(so_admin), db: Session = Depends(get_db)):
    def n(modelo):
        return db.scalar(select(func.count()).select_from(modelo))
    km = db.scalar(select(func.coalesce(func.sum(Corrida.distancia_km), 0)))
    impressoes, cliques = db.execute(select(func.coalesce(func.sum(Anuncio.impressoes), 0),
                                            func.coalesce(func.sum(Anuncio.cliques), 0))).one()
    ativos = db.scalar(select(func.count()).select_from(Anuncio).where(Anuncio.ativo.is_(True)))
    return {"usuarios": n(Usuario), "corridas": n(Corrida), "km_total": round(km, 1),
            "turmas": n(Turma), "campeonatos": n(Campeonato), "anuncios_ativos": ativos,
            "impressoes": impressoes, "cliques": cliques}


@app.get("/admin/usuarios")
def admin_usuarios(q: str | None = None, admin: Usuario = Depends(so_admin),
                   db: Session = Depends(get_db)):
    s = select(Usuario).order_by(Usuario.id.desc()).limit(100)
    if q:
        s = s.where(or_(Usuario.nome.ilike(f"%{q}%"), Usuario.email.ilike(f"%{q}%")))
    return [{"id": u.id, "nome": u.nome, "email": u.email, "cidade": u.cidade,
             "foto": u.foto_perfil, "ativo": u.ativo, "is_admin": u.is_admin}
            for u in db.scalars(s)]


@app.post("/admin/usuarios/{usuario_id}/suspender")
def admin_suspender(usuario_id: int, admin: Usuario = Depends(so_admin),
                    db: Session = Depends(get_db)):
    u = db.get(Usuario, usuario_id)
    if not u:
        raise HTTPException(404, "Atleta não encontrado")
    if u.is_admin:
        raise HTTPException(400, "Não é possível suspender um administrador")
    u.ativo = not u.ativo
    db.commit()
    return {"ativo": u.ativo}


@app.delete("/admin/corridas/{corrida_id}")
def admin_excluir_corrida(corrida_id: int, admin: Usuario = Depends(so_admin),
                          db: Session = Depends(get_db)):
    return _excluir(db, Corrida, corrida_id,
                    [(Curtida, Curtida.corrida_id), (Foto, Foto.corrida_id)])


@app.delete("/admin/turmas/{turma_id}")
def admin_excluir_turma(turma_id: int, admin: Usuario = Depends(so_admin),
                        db: Session = Depends(get_db)):
    return _excluir(db, Turma, turma_id, [(TurmaMembro, TurmaMembro.turma_id)])


@app.delete("/admin/campeonatos/{campeonato_id}")
def admin_excluir_campeonato(campeonato_id: int, admin: Usuario = Depends(so_admin),
                             db: Session = Depends(get_db)):
    return _excluir(db, Campeonato, campeonato_id)


@app.get("/admin/anuncios")
def admin_anuncios(admin: Usuario = Depends(so_admin), db: Session = Depends(get_db)):
    return [{**anuncio_dict(a), "cidade": a.cidade, "inicio": a.inicio, "fim": a.fim,
             "ativo": a.ativo, "impressoes": a.impressoes, "cliques": a.cliques}
            for a in db.scalars(select(Anuncio).order_by(Anuncio.id.desc()))]


@app.post("/admin/anuncios", status_code=201)
def admin_criar_anuncio(anunciante: str = Form(..., max_length=100),
                        titulo: str = Form(..., max_length=120),
                        link: str = Form(...),
                        texto: str | None = Form(None, max_length=300),
                        cidade: str | None = Form(None),
                        inicio: date | None = Form(None),
                        fim: date | None = Form(None),
                        imagem: UploadFile | None = File(None),
                        admin: Usuario = Depends(so_admin), db: Session = Depends(get_db)):
    if not link.startswith(("http://", "https://")):
        raise HTTPException(422, "O link deve começar com http:// ou https://")
    if inicio and fim and fim < inicio:
        raise HTTPException(422, "A data final deve ser depois da inicial")
    url = salvar_imagem(imagem) if imagem is not None and imagem.filename else None
    a = Anuncio(anunciante=anunciante, titulo=titulo, texto=texto, link=link,
                cidade=(cidade or "").strip() or None, inicio=inicio, fim=fim, imagem_url=url)
    db.add(a)
    db.commit()
    return {"id": a.id}


@app.post("/admin/anuncios/{anuncio_id}/alternar")
def admin_alternar_anuncio(anuncio_id: int, admin: Usuario = Depends(so_admin),
                           db: Session = Depends(get_db)):
    a = db.get(Anuncio, anuncio_id)
    if not a:
        raise HTTPException(404, "Anúncio não encontrado")
    a.ativo = not a.ativo
    db.commit()
    return {"ativo": a.ativo}


@app.delete("/admin/anuncios/{anuncio_id}")
def admin_excluir_anuncio(anuncio_id: int, admin: Usuario = Depends(so_admin),
                          db: Session = Depends(get_db)):
    return _excluir(db, Anuncio, anuncio_id)


# ---------- Site (front-end) ----------
# Fica por último: as rotas da API têm prioridade e o site responde na raiz "/"
app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True), name="site")