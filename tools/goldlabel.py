#!/usr/bin/env python3
"""
goldlabel.py — Etiquetado manual del gold set para Noctis.

Lee un CSV con columnas: id, content, [relabel_suggestion opcional]
Escribe/actualiza la columna 'gold_label' con la clase que TÚ asignas.

Diseñado para velocidad:
  - una tecla por clase (no escribir)
  - sugerencia del relabel pre-rellenada: Enter la acepta
  - guardado atómico tras cada fila (resumible, a prueba de cierres)
  - navegación: volver atrás, saltar, ir a una fila concreta
  - los dumps gigantes se truncan en pantalla (no hay que leerlos enteros)

Uso:
  python3 goldlabel.py gold_candidates.csv

El CSV de entrada debe tener al menos 'id' y 'content'.
Si tiene 'relabel_suggestion' (la etiqueta que puso el relabel), se usa como
sugerencia pre-rellenada. Si no, no pasa nada — eliges desde cero.
"""

import csv
import sys
import os
import shutil

csv.field_size_limit(sys.maxsize)  # algunos content (dumps) superan el límite por defecto

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG: las clases y su tecla. Edita esto si tus clases o nombres cambian.
# La tecla es lo que pulsas; el valor es lo que se guarda en gold_label.
# ─────────────────────────────────────────────────────────────────────────────
CLASSES = {
    "1": "irrelevant",
    "2": "data_dump",
    "3": "credential_leak",
    "4": "vulnerability",
    "5": "access_broker",
    "6": "malware_sample",
    "7": "threat_actor_comms",
    "8": "canary_hit",
}

# Cuántos caracteres del content mostrar antes de truncar (los dumps son enormes)
CONTENT_PREVIEW = 1600

# Columnas de salida que el script gestiona
GOLD_COL = "gold_label"
NOTE_COL = "gold_note"

# ─────────────────────────────────────────────────────────────────────────────

HELP = """
┌─ TECLAS ────────────────────────────────────────────────────────────────────
│  1 irrelevant      2 data_dump        3 credential_leak   4 vulnerability
│  5 access_broker   6 malware_sample   7 threat_actor_comms  8 canary_hit
│
│  Enter  aceptar la sugerencia [entre corchetes], si la hay
│  n      añadir/editar nota         f      ver content completo (sin truncar)
│  b      fila anterior              g      ir a fila Nº
│  s      saltar (sin etiquetar)     u      marcar como dudosa (unsure)
│  ?      mostrar esta ayuda         q      guardar y salir
└──────────────────────────────────────────────────────────────────────────────
"""


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def load(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        sys.exit("CSV vacío.")
    if "id" not in rows[0] or "content" not in rows[0]:
        sys.exit("El CSV necesita al menos las columnas 'id' y 'content'.")
    # asegurar columnas de salida
    for r in rows:
        r.setdefault(GOLD_COL, "")
        r.setdefault(NOTE_COL, "")
    return rows


def fieldnames(rows):
    # preservar el orden original + garantizar gold/note al final
    base = list(rows[0].keys())
    for c in (GOLD_COL, NOTE_COL):
        if c not in base:
            base.append(c)
    return base


def save_atomic(path, rows):
    tmp = path + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames(rows))
        w.writeheader()
        w.writerows(rows)
    shutil.move(tmp, path)  # move atómico: o está el archivo viejo, o el nuevo completo


def first_unlabeled(rows):
    for i, r in enumerate(rows):
        if not (r.get(GOLD_COL) or "").strip():
            return i
    return 0  # todo etiquetado → empezar al principio para revisar


def progress(rows):
    done = sum(1 for r in rows if (r.get(GOLD_COL) or "").strip())
    return done, len(rows)


def show(rows, i, msg=""):
    clear()
    r = rows[i]
    done, total = progress(rows)
    sugg = (r.get("relabel_suggestion") or "").strip()
    cur = (r.get(GOLD_COL) or "").strip()
    note = (r.get(NOTE_COL) or "").strip()

    print(f"Fila {i+1}/{total}   etiquetadas {done}   ", end="")
    print(f"id: {r.get('id','?')}")
    print("=" * 78)
    if sugg:
        print(f"sugerencia relabel: {sugg}   (Enter acepta)")
    if cur:
        print(f"gold actual: {cur}")
    if note:
        print(f"nota: {note}")
    print("-" * 78)

    content = r.get("content", "") or ""
    if len(content) > CONTENT_PREVIEW:
        print(content[:CONTENT_PREVIEW])
        print(f"\n   … [truncado: {len(content)} chars en total. 'f' para ver todo] …")
    else:
        print(content)
    print("=" * 78)
    # recordatorio compacto de teclas
    print("1 irrel  2 dump  3 cred  4 vuln  5 broker  6 malware  7 actor  8 canary   "
          "| Enter=sugerencia  n=nota  b=atrás  s=saltar  u=dudosa  f=full  g=ir  q=salir")
    if msg:
        print(f">>> {msg}")


def main():
    if len(sys.argv) < 2:
        sys.exit("Uso: python3 goldlabel.py <archivo.csv>")
    path = sys.argv[1]
    rows = load(path)
    i = first_unlabeled(rows)
    msg = "Listo. '?' para ayuda."

    while True:
        show(rows, i, msg)
        msg = ""
        try:
            key = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            save_atomic(path, rows)
            print("\nGuardado. Hasta luego.")
            return

        # ── asignar clase por número ──
        if key in CLASSES:
            rows[i][GOLD_COL] = CLASSES[key]
            save_atomic(path, rows)
            if i < len(rows) - 1:
                i += 1
            else:
                msg = "Última fila. 'b' para revisar, 'q' para salir."
            continue

        # ── Enter: aceptar sugerencia ──
        if key == "":
            sugg = (rows[i].get("relabel_suggestion") or "").strip()
            if sugg in CLASSES.values():
                rows[i][GOLD_COL] = sugg
                save_atomic(path, rows)
                if i < len(rows) - 1:
                    i += 1
                else:
                    msg = "Última fila. 'b' para revisar, 'q' para salir."
            else:
                msg = "No hay sugerencia válida que aceptar. Pulsa un número 1-7."
            continue

        # ── nota ──
        if key == "n":
            rows[i][NOTE_COL] = input("nota: ").strip()
            save_atomic(path, rows)
            msg = "Nota guardada."
            continue

        # ── unsure ──
        if key == "u":
            rows[i][GOLD_COL] = "unsure"
            save_atomic(path, rows)
            if i < len(rows) - 1:
                i += 1
            msg = "Marcada dudosa."
            continue

        # ── ver content completo ──
        if key == "f":
            clear()
            print(rows[i].get("content", ""))
            print("\n" + "─" * 78)
            input("[Enter para volver]")
            continue

        # ── navegación ──
        if key == "b":
            i = max(0, i - 1)
            continue
        if key == "s":
            if i < len(rows) - 1:
                i += 1
            msg = "Saltada (sin etiquetar)."
            continue
        if key == "g":
            tgt = input("ir a fila Nº: ").strip()
            if tgt.isdigit():
                n = int(tgt) - 1
                if 0 <= n < len(rows):
                    i = n
                else:
                    msg = f"Fuera de rango (1-{len(rows)})."
            continue
        if key == "?":
            clear()
            print(HELP)
            input("[Enter para volver]")
            continue
        if key == "q":
            save_atomic(path, rows)
            done, total = progress(rows)
            print(f"\nGuardado. {done}/{total} etiquetadas en {path}")
            return

        msg = "Tecla no reconocida. '?' para ayuda."


if __name__ == "__main__":
    main()
