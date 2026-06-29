#!/usr/bin/env python3
"""
gold_sample.py — Construye un gold_candidates.csv ESTRATIFICADO para etiquetar a mano.

Qué hace:
  1. Lee el CSV del relabel (los ~24k actionable, con su categoría de referencia).
  2. Para cada clase, muestrea N filas al azar de ESA clase (estratificado).
  3. Saca el content COMPLETO de cada fila desde la BD (raw_content), igual que
     hicieron las worksheets — el snippet del CSV puede venir truncado.
  4. Escribe gold_candidates.csv con: id, content, relabel_suggestion.
  5. Emite gold_ids.txt (los IDs del gold set) para pasarlo luego a
     build_dataset.py --gold-ids-file y mantener el examen fuera del entrenamiento.

POR DEFECTO ES DRY-RUN: solo imprime la distribución y cuántas filas cogería por
clase. No escribe ni toca la BD. Añade --write para generar los archivos.

Uso:
  # 1) ver tu distribución y el plan (seguro, no escribe nada):
  python3 gold_sample.py relabel_results.csv

  # 2) si el plan te cuadra, generar de verdad (requiere NOCTIS_DB_DSN):
  python3 gold_sample.py relabel_results.csv --write

Opciones:
  --label-col COL     columna por la que estratificar (default: autodetecta
                      model_category, luego final_label)
  --exclude FILE      archivo con IDs (uno por línea) a excluir del muestreo
                      (p. ej. los IDs de las worksheets ya adjudicadas)
  --content-limit N   recortar el content guardado a N chars (default: 4096,
                      = classifyContentLimit, lo que el clasificador ve en prod;
                      usa 0 para guardar el content completo)
  --seed N            semilla aleatoria (default: 42, reproducible)
  --out FILE          nombre del CSV de salida (default: gold_candidates.csv)
"""

import csv
import sys
import os
import argparse
import random

csv.field_size_limit(sys.maxsize)

# ─────────────────────────────────────────────────────────────────────────────
# Reparto objetivo por clase. Edita a gusto.
# Nota: credential_leak (193 totales) y access_broker (156 totales) bajados a ~25-30
# a propósito: meter 60 en el gold set sacaría ~1/3 de la clase del ENTRENAMIENTO,
# justo las dos clases que peor entrenan. Por D10 esas clases viven en reglas, no en
# el modelo, así que se evalúa COBERTURA DE REGLAS sobre ellas (roadmap §5.5), para lo
# que 25-30 sobra. canary_hit eliminado: 0 ejemplos en el corpus (es señal interna,
# no se clasifica desde contenido).
# ─────────────────────────────────────────────────────────────────────────────
TARGETS = {
    "irrelevant":          80,
    "data_dump":           60,
    "vulnerability":       60,
    "malware_sample":      50,
    "threat_actor_comms":  40,
    "credential_leak":     30,
    "access_broker":       25,
}

CANDIDATE_LABEL_COLS = ["model_category", "final_label", "category"]


def detect_label_col(header, requested):
    if requested:
        if requested not in header:
            sys.exit(f"La columna '{requested}' no está en el CSV. Columnas: {header}")
        return requested
    for c in CANDIDATE_LABEL_COLS:
        if c in header:
            return c
    sys.exit(f"No encuentro columna de etiqueta. Pásala con --label-col. Columnas: {header}")


def load_exclude(path):
    if not path:
        return set()
    with open(path, encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("relabel_csv")
    ap.add_argument("--label-col", default=None)
    ap.add_argument("--exclude", default=None)
    ap.add_argument("--content-limit", type=int, default=4096)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="gold_candidates.csv")
    ap.add_argument("--write", action="store_true",
                    help="generar archivos de verdad (si no, dry-run)")
    args = ap.parse_args()

    random.seed(args.seed)

    with open(args.relabel_csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames
        rows = list(reader)

    if "id" not in header:
        sys.exit(f"El CSV necesita columna 'id'. Columnas: {header}")

    label_col = detect_label_col(header, args.label_col)
    exclude = load_exclude(args.exclude)

    # agrupar por clase
    from collections import defaultdict
    buckets = defaultdict(list)
    for r in rows:
        if r["id"] in exclude:
            continue
        lab = (r.get(label_col) or "").strip()
        buckets[lab].append(r)

    # ── informe de distribución ──
    print(f"\nCSV: {args.relabel_csv}   filas: {len(rows)}   "
          f"estrato por: '{label_col}'   excluidas: {len(exclude)}")
    print("=" * 64)
    print(f"{'clase':<22}{'disponibles':>12}{'objetivo':>10}{'cogería':>10}")
    print("-" * 64)
    plan = {}
    total_take = 0
    # mostrar primero las clases del TARGETS, luego cualquier otra que aparezca
    seen = set()
    for cls in TARGETS:
        avail = len(buckets.get(cls, []))
        want = TARGETS[cls]
        take = min(avail, want)
        plan[cls] = take
        total_take += take
        seen.add(cls)
        flag = "  ⚠ faltan" if avail < want else ""
        print(f"{cls:<22}{avail:>12}{want:>10}{take:>10}{flag}")
    # clases presentes en el CSV pero no en TARGETS (avisar, no muestrear)
    extras = [(c, len(v)) for c, v in buckets.items() if c not in seen]
    if extras:
        print("-" * 64)
        print("clases en el CSV no contempladas en TARGETS (NO se muestrean):")
        for c, n in sorted(extras, key=lambda x: -x[1]):
            print(f"  {c or '(vacío)':<22}{n:>12}")
    print("-" * 64)
    print(f"{'TOTAL a etiquetar':<22}{'':>12}{'':>10}{total_take:>10}")
    print("=" * 64)

    if not args.write:
        print("\n[DRY-RUN] No se ha escrito nada ni tocado la BD.")
        print("Si el plan te cuadra, repite con --write (necesita NOCTIS_DB_DSN).")
        print("Ajusta el reparto editando TARGETS al inicio del script,")
        print("o cambia el estrato con --label-col.")
        return

    # ── modo write: muestrear y traer content de la BD ──
    dsn = os.environ.get("NOCTIS_DB_DSN")
    if not dsn:
        sys.exit("\n--write requiere la variable NOCTIS_DB_DSN (igual que las worksheets).")

    try:
        import psycopg2
    except ImportError:
        sys.exit("Falta psycopg2. Instala: pip install psycopg2-binary --break-system-packages")

    # muestreo
    picked = []
    for cls, take in plan.items():
        pool = buckets.get(cls, [])
        chosen = random.sample(pool, take) if take < len(pool) else list(pool)
        for r in chosen:
            picked.append((r["id"], cls))
    random.shuffle(picked)  # mezclar para no etiquetar 60 data_dump seguidos

    ids = [pid for pid, _ in picked]
    sugg_by_id = {pid: cls for pid, cls in picked}

    # traer content completo
    print(f"\nConsultando content de {len(ids)} filas en la BD…")
    conn = psycopg2.connect(dsn)
    cur = conn.cursor()
    # raw_content: ajusta el nombre de la columna de texto si no es 'content'
    cur.execute(
        "SELECT id, content FROM raw_content WHERE id = ANY(%s::uuid[])",
        (ids,),
    )
    content_by_id = {str(r[0]): (r[1] or "") for r in cur.fetchall()}
    cur.close()
    conn.close()

    missing = [pid for pid in ids if pid not in content_by_id]
    if missing:
        print(f"⚠ {len(missing)} IDs no encontrados en raw_content (se omiten).")

    # escribir gold_candidates.csv en el MISMO orden mezclado
    limit = args.content_limit
    written = 0
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id", "content", "relabel_suggestion", "gold_label", "gold_note"])
        w.writeheader()
        for pid, _ in picked:
            if pid not in content_by_id:
                continue
            content = content_by_id[pid]
            if limit and len(content) > limit:
                content = content[:limit]
            w.writerow({
                "id": pid,
                "content": content,
                "relabel_suggestion": sugg_by_id[pid],
                "gold_label": "",
                "gold_note": "",
            })
            written += 1

    # escribir gold_ids.txt
    with open("gold_ids.txt", "w", encoding="utf-8") as f:
        for pid in ids:
            if pid in content_by_id:
                f.write(pid + "\n")

    print(f"\n✓ Escrito {args.out} ({written} filas)")
    print(f"✓ Escrito gold_ids.txt ({written} IDs) — pásalo a build_dataset.py --gold-ids-file")
    print(f"\nAhora etiqueta:  python3 goldlabel.py {args.out}")


if __name__ == "__main__":
    main()
