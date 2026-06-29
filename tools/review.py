#!/usr/bin/env python3
"""
Revisor de terminal para adjudicar las worksheets de validacion de Noctis (F1.1-F1.3).

Muestra una fila a la vez (contenido completo + etiqueta vieja/nueva), tu pulsas
una tecla para el veredicto, y se GUARDA AL INSTANTE en el mismo CSV (columna
'verdict', y 'notes' opcional). Reanudable: si cierras y vuelves a abrir, salta
las filas ya adjudicadas y sigue donde lo dejaste. Nunca pierde trabajo.

Veredictos:
    o  = ok      -> la nueva etiqueta es correcta (el relabel acerto)
    w  = wrong   -> la nueva etiqueta es un ERROR (p. ej. se perdio una credencial real)
    u  = unsure  -> no esta claro; lo revisas luego / lo dejas fuera del set de confianza
    n  = nota    -> escribe una nota libre para esta fila (no cambia el veredicto)
    b  = back    -> vuelve a la fila anterior (para corregir un veredicto)
    s  = skip    -> salta sin marcar (queda pendiente)
    q  = quit     -> guarda y sale

USO (con el venv activado):
    python3 review.py tools/data/review_credential-exits.csv
    python3 review.py tools/data/review_needs-review-sample.csv
    python3 review.py tools/data/review_downgrade-sample.csv

Las columnas esperadas: id, content, old_label, new_label, decision_source, verdict, notes
(si tu CSV no trae 'verdict'/'notes', se anaden automaticamente).
"""

import csv
import os
import sys

csv.field_size_limit(sys.maxsize)

# colores ANSI (degradan a nada si la terminal no los soporta)
class C:
    R = "\033[0m"; B = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GRN = "\033[32m"; YEL = "\033[33m"
    CYN = "\033[36m"; MAG = "\033[35m"


VERDICT_KEYS = {"o": "ok", "w": "wrong", "u": "unsure"}
VERDICT_COLOR = {"ok": C.GRN, "wrong": C.RED, "unsure": C.YEL, "": C.DIM}


def getch():
    """Lee una sola tecla sin Enter (Unix)."""
    import termios, tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return ch


def load(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        sys.exit(f"{path} esta vacio o no tiene filas.")
    # asegura columnas verdict/notes
    for r in rows:
        r.setdefault("verdict", "")
        r.setdefault("notes", "")
    return rows


def save(path, rows):
    fields = ["id", "content", "old_label", "new_label",
              "decision_source", "verdict", "notes"]
    # conserva cualquier columna extra que trajera el CSV
    extra = [k for k in rows[0].keys() if k not in fields]
    fields = fields + extra
    tmp = path + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, path)  # escritura atomica: nunca corrompe el CSV si se corta


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def render(row, idx, total, done):
    clear()
    pending = total - done
    bar = f"{C.B}Fila {idx+1}/{total}{C.R}  {C.DIM}(adjudicadas {done} · pendientes {pending}){C.R}"
    print(bar)
    print("=" * 78)
    print(f"{C.DIM}id:{C.R} {row['id']}")
    print(f"{C.DIM}fuente decision:{C.R} {row.get('decision_source','')}")
    old = row.get("old_label", "")
    new = row.get("new_label", "")
    arrow = f"{C.RED}{old}{C.R}  {C.DIM}->{C.R}  {C.CYN}{new}{C.R}"
    print(f"{C.DIM}etiqueta:{C.R} {arrow}")
    cur = row.get("verdict", "")
    if cur:
        print(f"{C.DIM}veredicto actual:{C.R} {VERDICT_COLOR.get(cur,'')}{cur}{C.R}")
    if row.get("notes"):
        print(f"{C.DIM}nota:{C.R} {row['notes']}")
    print("-" * 78)
    content = row.get("content", "") or "(sin contenido en la BD)"
    print(content.strip())
    print("=" * 78)
    print(f"{C.GRN}[o]{C.R}k   {C.RED}[w]{C.R}rong   {C.YEL}[u]{C.R}nsure   "
          f"[n]ota   [b]ack   [s]kip   [q]uit")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    if not os.path.exists(path):
        sys.exit(f"No existe: {path}")
    rows = load(path)
    total = len(rows)

    # reanuda: primer indice sin veredicto
    idx = 0
    while idx < total and rows[idx].get("verdict"):
        idx += 1
    if idx >= total:
        idx = 0  # todo adjudicado ya; empieza por el principio para revisar/corregir

    while True:
        done = sum(1 for r in rows if r.get("verdict"))
        if idx >= total:
            clear()
            print(f"{C.GRN}{C.B}Fin de la worksheet.{C.R} Adjudicadas {done}/{total}.")
            print("Pulsa [b] para volver atras y revisar, o [q] para salir.")
            ch = getch().lower()
            if ch == "b":
                idx = total - 1
                continue
            if ch == "q":
                save(path, rows); break
            continue

        render(rows[idx], idx, total, done)
        ch = getch().lower()

        if ch in VERDICT_KEYS:
            rows[idx]["verdict"] = VERDICT_KEYS[ch]
            save(path, rows)          # guarda en cada tecla
            idx += 1
        elif ch == "n":
            clear(); render(rows[idx], idx, total, done)
            try:
                note = input(f"\n{C.MAG}nota> {C.R}")
            except (EOFError, KeyboardInterrupt):
                note = ""
            rows[idx]["notes"] = note.strip()
            save(path, rows)
        elif ch == "b":
            idx = max(0, idx - 1)
        elif ch == "s":
            idx += 1
        elif ch == "q":
            save(path, rows)
            done = sum(1 for r in rows if r.get("verdict"))
            print(f"\nGuardado. Adjudicadas {done}/{total} en {path}")
            break


if __name__ == "__main__":
    main()
