# oritypo-solver

**oritypo-solver** is the Oriradar **scan HTTP service**: orchestration, **orifold** (permutations), **oriseek** (Rust DNS batch engine), **oriprobe** (HTTP), **oriscore** (risk ranking), plus optional **orirdap**, **oriframe**, **oricrawl** and **oristream** enrichments.

- **Open source** in spirit — reusable outside Oriradar; the **website** adds auth, billing, and UI.
- **Python 3.11+** — always use a **virtual environment** (never install deps globally).

## Setup (venv required)

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

Optional editable install:

```bash
pip install -e .
```

### **orifold** + **oriseek** (Rust, recommandés en prod)

Les permutations utilisent le binaire **`orifold`** ([`crates/orifold`](../crates/orifold)), moteur Rust autonome. Les résolutions DNS batch utilisent le binaire **`oriseek`** ([`crates/oriseek`](../crates/oriseek)). Sans binaire, l’API retombe sur un mode Python de secours, moins performant.

```bash
cd ../crates/orifold
cargo build --release
cd ../oriseek
cargo build --release
```

Puis, avec le venv activé :

```bash
export ORIFOLD_PATH=/chemin/vers/orifold/target/release/orifold
export ORISEEK_PATH=/chemin/vers/oriseek/target/release/oriseek
export ORI_MAX_VARIANTS=500   # plafond par scan (1–50000)
uvicorn oritypo_solver.main:app --reload --host 0.0.0.0 --port 8000
```

L’image Docker **`deploy/Dockerfile`** compile **orifold** et **oriseek**, puis définit `ORIFOLD_PATH` et `ORISEEK_PATH` automatiquement.

### Enrichissements optionnels

```bash
export ORI_HTTP_MAX_PROBES=25     # nombre max de domaines probés en HTTP
export ORI_HTTP_TIMEOUT=4         # timeout HTTP par domaine
export ORI_HTTP_CONCURRENCY=25    # probes HTTP parallèles
export ORI_HTTP_CONNECT_TIMEOUT=1.5
export ORI_HTTP_READ_TIMEOUT=3.5
export ORI_DNS_CONCURRENCY=256    # parallélisme batch de oriseek
export ORI_DNS_TIMEOUT_MS=2000    # timeout DNS unitaire côté oriseek
export ORI_DNS_BATCH_SIZE=128     # taille d'un lot DNS Rust
export ORI_DNS_RUST_MIN_BATCH=32  # sous ce seuil, fallback Python possible
export ORI_ENABLE_RDAP=1          # active orirdap
export ORI_RDAP_MAX_LOOKUPS=10    # limite les appels RDAP
export ORI_WEBHOOK_URL=https://.../scan-events
export ORI_ENABLE_SCREENSHOTS=1   # active oriframe
export ORI_ENABLE_CRAWL=1         # active oricrawl
```

- **orirdap** : lookup RDAP sur les domaines les mieux classés.
- **oriframe** : capture screenshot si les seuils score / prediction sont atteints.
- **oricrawl** : crawl léger multi-pages pour formulaires, chemins login et signaux de contenu.
- **oristream** : webhook JSON sur fin de scan.

## Run

With venv **activated**:

```bash
uvicorn oritypo_solver.main:app --reload --host 0.0.0.0 --port 8000
```

- Swagger: <http://127.0.0.1:8000/docs>
- Health: `GET /health` → `{"service":"oritypo-solver",...}`

## Worker mode (Redis)

Pour un mode proche VPS :

```bash
export REDIS_URL=redis://127.0.0.1:6379/0
python -m oritypo_solver.worker
```

Dans ce mode, l’API crée les scans et les pousse en file Redis ; le worker les consomme.

## API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/scans` | `{"target":"https://example.com"}` |
| `GET` | `/v1/scans/{id}` | Poll until `completed` |

## Client SPA (monorepo Oriradar uniquement)

Dans le dépôt **complet** Oriradar, `.env` à la racine pour Vite :

```env
VITE_SCAN_API_BASE_URL=http://127.0.0.1:8000
```

Le dépôt **oriradar-resolver** (VPS) n’embarque pas le front ; tu appelles l’API directement (curl, autre client) ou tu pointes ton SPA hébergé ailleurs vers l’URL publique du scan.

## Docs

- **[docs/ori-tools.md](../docs/ori-tools.md)** — catalogue complet des outils Ori (oritypo-solver, orifold, oriseek, oriprobe, …), distinction lib / service, et **déploiement Docker** (style ail-typo).
- **[deploy/README.md](../deploy/README.md)** — `docker compose` (Caddy, Redis, API).
- **[docs/scoring.md](../docs/scoring.md)** — explication complète du scoring de risque et du scoring prédictif.

## Production / VPS (Docker)

Ne pas exposer Uvicorn directement sur Internet. Utiliser la stack **`deploy/`** : Caddy en reverse proxy, Redis pour la file et l’état des scans, conteneurs **api** + workers (`scan`, `oriframe`, `oricrawl`, `oridigest`).

```bash
cd deploy && docker compose up -d --build
```

Étendre les origines CORS dans [`oritypo_solver/main.py`](oritypo_solver/main.py) pour votre domaine de prod (et pour le front Vercel si besoin).
