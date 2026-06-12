#!/usr/bin/env python3
"""
Capa de REGLAS de Noctis. Dos usos, misma logica compartida:

  1) EXTRACCION DE IOCs  -> reemplaza la extraccion de IOCs que hoy hace Groq.
     extract_iocs(texto) devuelve los IOCs REALES (rechazando placeholders).

  2) LIMPIEZA / DETECCION DE BASURA  -> para depurar el corpus y la BD viva.
     junk_reason(texto) devuelve por que un finding es basura (o None si sirve).

Las listas de placeholders y los regex se comparten entre ambos, asi extraccion
y limpieza NUNCA se contradicen. Es regex puro: sin LLM, corre en segundos sobre
las 52k filas. El volumen NO es el problema; definir bien que es basura, si.

CLAVE (el error tipico): "user:pass" como PLACEHOLDER es basura, pero
"mark:opensesame" es una credencial real con el mismo formato. Aqui se rechaza
el TOKEN placeholder (las palabras user/pass/example/...), nunca el formato.

USO read-only (port-forward abierto, venv activado):
    export DATABASE_URL="postgres://noctis:PASS@localhost:5432/noctis?sslmode=disable"
    python noctis_rules.py            # escanea la BD y reporta basura + cobertura IOC
                                       # NO borra nada; vuelca muestras a un CSV
"""

import argparse
import csv
import os
import re
import sys

try:
    import psycopg
except ImportError:
    psycopg = None  # solo hace falta para el modo escaneo

TABLE = "raw_content"
OUT_SAMPLES = "junk_scan_samples.csv"
ULTRA_SHORT = 15          # contenido util mas corto que esto = fragmento
SAMPLES_PER_REASON = 8    # cuantos ejemplos guardar por cada motivo de basura

# --------------------------------------------------------------------------
# Listas de placeholders. CONSERVADORAS a proposito: ante la duda, NO marcar.
# Amplialas tu segun lo que veas en el escaneo; estan aqui para que las edites.
# --------------------------------------------------------------------------
PLACEHOLDER_DOMAINS = {
    "example.com", "example.org", "example.net", "example.edu",
    "test.com", "test.net", "domain.com", "yourdomain.com", "sample.com",
    "site.com", "mysite.com", "foo.com", "bar.com", "foobar.com",
    "acme.com", "company.com", "yourcompany.com", "localhost",
    "domain.tld", "email.tld", "website.com",
}
# Rangos/IPs reservados para documentacion (RFC 5737) + ejemplos clasicos.
PLACEHOLDER_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "1.1.1.1", "8.8.8.8", "8.8.4.4", "1.2.3.4",
}
PLACEHOLDER_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.",
                           "10.", "192.168.", "172.16.")
# Partes locales de email que delatan un placeholder.
PLACEHOLDER_EMAIL_LOCAL = {
    "user", "test", "email", "your", "youremail", "name", "username",
    "example", "admin", "john.doe", "jane.doe", "foo", "bar", "noreply",
}
PLACEHOLDER_EMAIL_DOMAINS = PLACEHOLDER_DOMAINS  # mismo set de dominios dummy
# Tokens que, en un par tipo user:pass, indican que es un EJEMPLO, no una cred.
PH_USER_TOKENS = {"user", "username", "login", "email", "your_email",
                  "youremail", "name", "usuario", "admin", "uname"}
PH_PASS_TOKENS = {"pass", "password", "passwd", "your_password", "yourpassword",
                  "changeme", "contrasena", "clave", "secret", "1234", "12345",
                  "123456", "examplepass", "test"}

# --------------------------------------------------------------------------
# Regex de IOCs (tipos del taxonomy de Noctis).
# Orden de hashes: comprobar el mas largo primero.
# --------------------------------------------------------------------------
RE_URL    = re.compile(r"\b(?:https?|hxxps?|ftp)://[^\s<>\"')]+", re.I)
RE_EMAIL  = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.I)
RE_IPV4   = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                       r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
                       r"[a-z]{2,24}\b", re.I)
RE_CVE    = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
RE_SHA1   = re.compile(r"\b[a-f0-9]{40}\b", re.I)
RE_MD5    = re.compile(r"\b[a-f0-9]{32}\b", re.I)
RE_ETH    = re.compile(r"\b0x[a-f0-9]{40}\b", re.I)
RE_BTC    = re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")

# Un par credencial generico user:pass (con o sin espacios) para clasificar.
RE_CREDPAIR = re.compile(r"\b([A-Za-z0-9._\-]{2,64})\s*:\s*([^\s:@]{3,64})\b")
# Un texto que es SOLO un enlace/handle suelto (fragmento sin contexto).
RE_ONLY_LINK = re.compile(
    r"^\s*(?:https?://\S+|t\.me/\S+|@\w{3,})\s*$", re.I)


def _clean(text: str) -> str:
    """Quita HTML basico y normaliza espacios para medir longitud util."""
    text = re.sub(r"<[^>]+>", " ", text or "")
    return re.sub(r"\s+", " ", text).strip()


def is_placeholder_ioc(kind: str, value: str) -> bool:
    """True si el IOC es un placeholder/ejemplo y debe descartarse."""
    v = value.lower().rstrip(".,);]")
    if kind == "domain":
        return v in PLACEHOLDER_DOMAINS or v.endswith(".local") or v.endswith(".test")
    if kind == "url":
        host = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0]
        return host in PLACEHOLDER_DOMAINS or host in PLACEHOLDER_IPS
    if kind == "ip":
        return v in PLACEHOLDER_IPS or v.startswith(PLACEHOLDER_IP_PREFIXES)
    if kind == "email":
        local, _, dom = v.partition("@")
        return local in PLACEHOLDER_EMAIL_LOCAL or dom in PLACEHOLDER_EMAIL_DOMAINS
    if kind.startswith("hash") or kind == "crypto_wallet":
        # hashes degenerados (todo ceros, un solo caracter repetido)
        body = v[2:] if v.startswith("0x") else v
        return len(set(body)) <= 1
    return False


def is_placeholder_cred(user: str, pwd: str) -> bool:
    """True si user:pass es un EJEMPLO (tokens dummy), no una credencial real."""
    return user.lower() in PH_USER_TOKENS or pwd.lower() in PH_PASS_TOKENS


def extract_iocs(text: str) -> dict:
    """IOCs REALES del texto (placeholders descartados). dict tipo -> [valores]."""
    out = {}

    def add(kind, values):
        real = [v for v in values if not is_placeholder_ioc(kind, v)]
        if real:
            out.setdefault(kind, [])
            for v in real:
                if v not in out[kind]:
                    out[kind].append(v)

    add("url", RE_URL.findall(text))
    add("email", RE_EMAIL.findall(text))
    # enmascara URLs y emails para que no se lean como dominios ni como user:pass
    masked = RE_EMAIL.sub(" ", RE_URL.sub(" ", text))
    add("cve", [m.group(0).upper() for m in RE_CVE.finditer(masked)])
    add("hash_sha256", RE_SHA256.findall(masked))
    add("hash_sha1", RE_SHA1.findall(masked))
    add("hash_md5", RE_MD5.findall(masked))
    add("crypto_wallet", RE_ETH.findall(masked) + RE_BTC.findall(masked))
    add("ip", RE_IPV4.findall(masked))
    add("domain", RE_DOMAIN.findall(masked))

    # credenciales en pares user:pass (solo las que NO son placeholder)
    creds = []
    for u, p in RE_CREDPAIR.findall(masked):
        if u.isdigit() or p.startswith("/") or is_placeholder_cred(u, p):
            continue
        creds.append(f"{u}:{p}")
    if creds:
        out["credential"] = creds[:50]
    return out


def junk_reason(text: str):
    """Por que este finding es basura inservible, o None si aporta algo.

    OJO: 'basura' = el finding ENTERO no sirve. Un finding con texto real +
    un placeholder NO es basura; solo se descarta el placeholder al extraer."""
    raw = text or ""
    clean = _clean(raw)

    if not clean:
        return "vacio"
    # RESCATE: si hay un IOC REAL (placeholders ya descartados), NO es basura
    # aunque sea corto o un link suelto: es un finding de IOC que coge la capa
    # de reglas (links a leaks, IP suelta, C2 terso, hash, CVE...).
    if extract_iocs(raw):
        return None
    if RE_ONLY_LINK.match(clean):
        return "solo_enlace_o_handle"          # @handle o link SIN IOC extraible
    if not any(ch.isalpha() for ch in clean):
        # isalpha es Unicode-aware: reconoce arabe/persa/CJK/hebreo, no solo latino/cirilico
        return "sin_letras"                     # solo simbolos/emojis/numeros
    # placeholder puro: el contenido util ES un valor de ejemplo y nada mas
    # (se comprueba ANTES que la longitud: 'user:pass' es placeholder, no solo corto)
    low = clean.lower()
    if low in PLACEHOLDER_DOMAINS or low in PLACEHOLDER_IPS:
        return "placeholder_solo"
    m = RE_CREDPAIR.fullmatch(clean)
    if m and is_placeholder_cred(m.group(1), m.group(2)):
        return "placeholder_credencial"
    em = RE_EMAIL.fullmatch(clean)
    if em and is_placeholder_ioc("email", clean):
        return "placeholder_email"

    if len(clean) < ULTRA_SHORT:
        return "ultracorto"                     # fragmento sin contexto
    return None


def db_connect():
    """Conexion con timeout y TCP keepalives: si el port-forward se cae, da error
    rapido o lo detecta en ~1 min, en vez de colgarse para siempre en un socket
    muerto (la causa de los 'cuelgues' que obligaban a Ctrl+C)."""
    if psycopg is None:
        sys.exit('Falta psycopg. En el venv: pip install "psycopg[binary]"')
    if not os.environ.get("DATABASE_URL"):
        sys.exit("Define DATABASE_URL.")
    return psycopg.connect(
        os.environ["DATABASE_URL"],
        connect_timeout=10,
        keepalives=1, keepalives_idle=30, keepalives_interval=10, keepalives_count=3,
    )


# ----------------------------- modo escaneo BD -----------------------------
def scan_db():
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute(f"""
            SELECT id, COALESCE(category, 'NULL'), COALESCE(content, '')
            FROM {TABLE}
            WHERE classified = true
        """)
        rows = cur.fetchall()

    total = len(rows)
    reason_counts = {}
    reason_samples = {}
    junk_by_cat = {}
    ioc_hits = {}
    rows_with_ioc = 0
    survivors = 0

    for fid, cat, content in rows:
        reason = junk_reason(content)
        if reason:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            junk_by_cat.setdefault(cat, {})
            junk_by_cat[cat][reason] = junk_by_cat[cat].get(reason, 0) + 1
            s = reason_samples.setdefault(reason, [])
            if len(s) < SAMPLES_PER_REASON:
                s.append((fid, cat, _clean(content)[:120]))
            continue
        survivors += 1
        iocs = extract_iocs(content)
        if iocs:
            rows_with_ioc += 1
            for k in iocs:
                ioc_hits[k] = ioc_hits.get(k, 0) + 1

    junk_total = sum(reason_counts.values())

    print("=" * 70)
    print("ESCANEO DE BASURA + COBERTURA DE IOCs  (read-only, no se borra nada)")
    print("=" * 70)
    print(f"Filas clasificadas escaneadas: {total}\n")

    print(f"BASURA detectada: {junk_total}  ({100*junk_total/total:.1f}% del total)")
    print("Por motivo (revisa los ejemplos antes de borrar nada):")
    for r in sorted(reason_counts, key=lambda x: reason_counts[x], reverse=True):
        n = reason_counts[r]
        print(f"  {r:<24} {n:>6}  ({100*n/total:.1f}%)")
        for fid, cat, snip in reason_samples[r][:4]:
            print(f"        [{cat}] {snip}")

    print(f"\nSOBREVIVEN al filtro de basura: {survivors}  "
          f"({100*survivors/total:.1f}%)")
    print(f"  de ellos, con al menos un IOC real extraible: {rows_with_ioc} "
          f"({100*rows_with_ioc/survivors:.1f}% de los supervivientes)")
    print("  IOCs por tipo (nº de findings que contienen ese tipo):")
    for k in sorted(ioc_hits, key=lambda x: ioc_hits[x], reverse=True):
        print(f"    {k:<16} {ioc_hits[k]:>6}")

    print("\nBASURA por categoria de Groq (cuanta de cada etiqueta es inservible):")
    for cat in sorted(junk_by_cat, key=lambda c: sum(junk_by_cat[c].values()),
                      reverse=True):
        tot = sum(junk_by_cat[cat].values())
        print(f"  {cat:<22} {tot:>6} basura  -> "
              + ", ".join(f"{r}:{n}" for r, n in
                          sorted(junk_by_cat[cat].items(),
                                 key=lambda x: x[1], reverse=True)[:3]))

    # volcado de muestras a CSV para revision a mano
    with open(OUT_SAMPLES, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["junk_reason", "id", "groq_category", "content_snippet"])
        for r, samples in reason_samples.items():
            for fid, cat, snip in samples:
                w.writerow([r, fid, cat, snip])
    print(f"\nMuestras por motivo volcadas en: {OUT_SAMPLES}")
    print("Read-only: este script NO modifica la BD. El borrado es un paso aparte")
    print("que decides tu DESPUES de validar estas muestras.")


def apply_cleanup(mode, do_apply):
    """Marca o borra la basura. mode: 'flag' | 'delete' | 'unflag'.
    Usa el MISMO junk_reason que el escaneo, asi lo que revisaste == lo que se toca.
    Sin --apply es dry-run: cuenta y no escribe nada.

    Seguro con Noctis vivo: el ALTER va en su propia transaccion y con lock_timeout
    (si el pod tiene la tabla ocupada FALLA rapido en vez de colgarse y bloquear la
    ingesta), y los UPDATE matchean por id tipado uuid usando el indice PK; nada de
    reescribir las 53k filas enteras."""
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute("SET lock_timeout = '5s'")   # nunca colgarse esperando un lock

        if mode == "unflag":
            if not do_apply:
                print("DRY-RUN unflag: pondria is_noise=false en las filas marcadas. Anade --apply.")
                return
            cur.execute("ALTER TABLE raw_content ADD COLUMN IF NOT EXISTS "
                        "is_noise boolean NOT NULL DEFAULT false")
            conn.commit()
            cur.execute("UPDATE raw_content SET is_noise = false WHERE is_noise = true")
            conn.commit()
            print(f"Revertido: is_noise=false en {cur.rowcount} filas.")
            return

        print("Escaneando raw_content con regex (~53k filas, 10-30s SIN barra de "
              "progreso). NO es un cuelgue: espera al conteo.", flush=True)
        cur.execute("SELECT id, COALESCE(content, '') FROM raw_content "
                    "WHERE classified = true")
        noise_ids = [str(fid) for fid, content in cur.fetchall() if junk_reason(content)]
        print(f"Basura detectada (misma logica que el escaneo): {len(noise_ids)} filas.")

        if not do_apply:
            print(f"DRY-RUN: NO se escribe nada. Para ejecutar de verdad: --{mode} --apply")
            return

        if mode == "flag":
            # DDL en su propia transaccion: coge el ACCESS EXCLUSIVE un instante y lo suelta
            cur.execute("ALTER TABLE raw_content ADD COLUMN IF NOT EXISTS "
                        "is_noise boolean NOT NULL DEFAULT false")
            conn.commit()
            # marca por indice PK (id uuid); en re-ejecuciones desmarca lo que ya no es basura
            cur.execute("UPDATE raw_content SET is_noise = false "
                        "WHERE is_noise = true AND NOT (id = ANY(%s::uuid[]))", (noise_ids,))
            cleared = cur.rowcount
            cur.execute("UPDATE raw_content SET is_noise = true "
                        "WHERE is_noise = false AND id = ANY(%s::uuid[])", (noise_ids,))
            marked = cur.rowcount
            conn.commit()
            print(f"FLAG aplicado: {marked} filas marcadas is_noise=true"
                  + (f", {cleared} desmarcadas (ya no eran basura)" if cleared else "")
                  + ". REVERSIBLE.")
            print("  filtra con    WHERE is_noise = false")
            print("  revierte con  python noctis_rules.py --unflag --apply")
        elif mode == "delete":
            print("AVISO: borrado IRREVERSIBLE. Si otras tablas referencian estas filas")
            print("(correlaciones, entidades, briefs) el DELETE puede fallar o cascada.")
            print("Haz BACKUP antes. Continuo en 5s, Ctrl+C para abortar...")
            import time
            time.sleep(5)
            cur.execute("DELETE FROM raw_content WHERE id = ANY(%s::uuid[])", (noise_ids,))
            conn.commit()
            print(f"BORRADAS {cur.rowcount} filas.")


def show_status():
    """Muestra si la columna is_noise existe y cuantas filas estan marcadas."""
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM information_schema.columns "
                    "WHERE table_name = 'raw_content' AND column_name = 'is_noise'")
        if not cur.fetchone():
            print("La columna is_noise NO existe -> el flag no se aplico.")
            print("Re-ejecuta: python noctis_rules.py --flag --apply")
            return
        cur.execute("SELECT is_noise, count(*) FROM raw_content "
                    "GROUP BY is_noise ORDER BY is_noise")
        counts = dict(cur.fetchall())
        flagged, clean = counts.get(True, 0), counts.get(False, 0)
        print(f"is_noise=true  (basura marcada): {flagged}")
        print(f"is_noise=false (limpio):         {clean}")
        if flagged == 0:
            print("-> columna creada pero 0 marcadas: el UPDATE no llego. Re-ejecuta --flag --apply.")
        elif 8000 <= flagged <= 9200:
            print("-> coincide con lo esperado (~8613): FLAG aplicado. Hecho.")
        else:
            print("-> conteo raro; --flag --apply es idempotente, re-ejecuta para fijarlo.")


def show_locks(do_apply):
    """Muestra (y con --apply termina) las sesiones que tienen un lock sobre
    raw_content. Util cuando el ALTER se queda sin lock por una sesion zombie
    (idle in transaction) que sobrevivio a un Ctrl+C anterior."""
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.pid, a.state, COALESCE(a.application_name, ''),
                   COALESCE(EXTRACT(EPOCH FROM (now() - a.state_change))::int, 0),
                   COALESCE(left(a.query, 90), '')
            FROM pg_locks l
            JOIN pg_stat_activity a ON a.pid = l.pid
            JOIN pg_class c ON c.oid = l.relation
            WHERE c.relname = 'raw_content'
              AND a.pid <> pg_backend_pid()
            GROUP BY a.pid, a.state, a.application_name, a.state_change, a.query
            ORDER BY a.pid
        """)
        blockers = cur.fetchall()
        if not blockers:
            print("Nadie mas tiene lock sobre raw_content; el bloqueo no viene de una sesion.")
            print("Si el ALTER sigue fallando, reinicia el pod de postgres (ver instrucciones).")
            return
        print(f"Sesiones con lock sobre raw_content (sin contar esta): {len(blockers)}")
        for pid, state, app, idle_s, q in blockers:
            print(f"  pid={pid}  estado='{state}'  idle={idle_s}s  app='{app}'")
            print(f"      ultima query: {q}")
        if not do_apply:
            print("\nDRY-RUN: no se termina nada. Para matarlas: python noctis_rules.py --locks --apply")
            return
        pids = [b[0] for b in blockers]
        cur.execute("SELECT pg_terminate_backend(pid) FROM unnest(%s::int[]) AS pid", (pids,))
        conn.commit()
        print(f"Terminadas {len(pids)} sesiones. Reintenta: python noctis_rules.py --flag --apply")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Capa de reglas Noctis. Sin flags: escaneo read-only.")
    ap.add_argument("--flag", action="store_true",
                    help="marcar la basura con is_noise=true (REVERSIBLE, recomendado)")
    ap.add_argument("--delete", action="store_true",
                    help="BORRAR la basura de la BD (IRREVERSIBLE)")
    ap.add_argument("--unflag", action="store_true",
                    help="revertir el flag: is_noise=false en todo")
    ap.add_argument("--apply", action="store_true",
                    help="ejecutar de verdad; SIN esto todo es dry-run")
    ap.add_argument("--status", action="store_true",
                    help="ver si is_noise existe y cuantas filas hay marcadas")
    ap.add_argument("--locks", action="store_true",
                    help="ver/terminar sesiones que bloquean raw_content (con --apply mata)")
    args = ap.parse_args()

    if args.locks:
        show_locks(args.apply)
    elif args.status:
        show_status()
    elif args.unflag:
        apply_cleanup("unflag", args.apply)
    elif args.delete:
        apply_cleanup("delete", args.apply)
    elif args.flag:
        apply_cleanup("flag", args.apply)
    else:
        scan_db()
