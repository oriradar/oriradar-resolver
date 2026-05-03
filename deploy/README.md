# Déploiement Docker (oritypo-solver)

Stack proche d’une installation **ail-typo** sur VPS :

- **Caddy** : reverse proxy (TLS à configurer sur votre domaine).
- **Redis** : file de jobs, état des scans, heartbeat du worker, cache futur.
- **api** : image **oritypo-solver** + binaires Rust **orifold** / **oriseek** — voir [`Dockerfile`](Dockerfile) multi-stage.
- **worker** : consomme la file Redis et exécute les scans.
- **oriframe** : worker Playwright pour les captures conditionnelles.
- **oricrawl** : worker de crawl léger multi-pages.
- **oridigest** : worker de digest planifié / monitoring.

Périmètre officiel de la suite : **[`docs/ori-tools.md`](../docs/ori-tools.md)** § *Périmètre officiel de la suite Ori*.

## Prérequis

- Docker + Docker Compose v2.

## Lancer

Depuis ce dossier :

```bash
docker compose up -d --build
```

Exemple VPS avec HTTPS automatique :

```bash
export ORI_CADDY_ADDRESS=scan.votredomaine.tld
export ORI_ENABLE_RDAP=1
export ORI_WEBHOOK_URL=https://votre-endpoint-interne.example/webhooks/scan
docker compose up -d --build
```

- API derrière Caddy : <http://localhost/> (health : <http://localhost/health>).
- Swagger : <http://localhost/docs>

Vérifications utiles :

```bash
docker compose ps
docker compose logs --tail=100 api worker oriframe oricrawl oridigest
curl http://127.0.0.1/health
```

## Variables

| Variable | Description |
|----------|-------------|
| `REDIS_URL` | Injectée dans `api` (`redis://redis:6379/0`). L’application peut l’utiliser quand le code lira Redis. |
| `ORIFOLD_PATH` | Chemin du binaire `orifold` (défaut dans l’image : `/usr/local/bin/orifold`). |
| `ORISEEK_PATH` | Chemin du binaire `oriseek` (défaut dans l’image : `/usr/local/bin/oriseek`). |
| `ORI_MAX_VARIANTS` | Nombre max de variantes testées par scan (plafonné côté API, défaut compose : `500`). |
| `ORI_DNS_CONCURRENCY` | Concurrence batch DNS côté **oriseek**. |
| `ORI_DNS_TIMEOUT_MS` | Timeout DNS par lookup côté **oriseek**. |
| `ORI_DNS_BATCH_SIZE` | Taille d’un lot DNS envoyé à **oriseek**. |
| `ORI_DNS_RUST_MIN_BATCH` | Sous ce seuil, le fallback Python peut rester plus rapide que le batch Rust. |
| `ORI_HTTP_MAX_PROBES` | Limite le nombre de domaines enrichis par **oriprobe**. |
| `ORI_HTTP_TIMEOUT` | Timeout HTTP par domaine pour **oriprobe**. |
| `ORI_HTTP_CONCURRENCY` | Nombre de probes HTTP parallèles. |
| `ORI_HTTP_CONNECT_TIMEOUT` | Timeout de connexion HTTP. |
| `ORI_HTTP_READ_TIMEOUT` | Timeout de lecture HTTP. |
| `ORI_ENABLE_RDAP` | Active **orirdap** (`1` / `true`). |
| `ORI_RDAP_MAX_LOOKUPS` | Nombre max de lookups RDAP par scan. |
| `ORI_RDAP_TIMEOUT` | Timeout RDAP par domaine. |
| `ORI_ENABLE_SCREENSHOTS` | Active les captures **oriframe**. |
| `ORI_SCREENSHOT_MAX_JOBS` | Nombre max de captures planifiées par scan. |
| `ORI_SCREENSHOT_SCORE_THRESHOLD` | Seuil de score pour déclencher `oriframe`. |
| `ORI_SCREENSHOT_PREDICTION_THRESHOLD` | Seuil prédictif pour déclencher `oriframe`. |
| `ORI_SCREENSHOT_DIR` | Répertoire partagé où stocker les captures. |
| `ORI_ENABLE_CRAWL` | Active **oricrawl**. |
| `ORI_CRAWL_MAX_JOBS` | Nombre max de crawls planifiés par scan. |
| `ORI_CRAWL_TIMEOUT` | Timeout HTTP par page pour **oricrawl**. |
| `ORI_CRAWL_MAX_PAGES` | Budget pages pour **oricrawl** (défaut compose : 12). |
| `ORI_CRAWL_MAX_DEPTH` | Profondeur max pour **oricrawl** (défaut compose : 2). |
| `ORI_CRAWL_MAX_HTML_BYTES` | Taille max du HTML téléchargé par page. |
| `ORI_CRAWL_SNIPPET_CHARS` | Taille max de l’extrait texte agrégé (`content_snippet`). |
| `ORI_CRAWL_MAX_LINKS_PER_PAGE` | Liens suivis / échantillonnés par page HTML. |
| `ORI_QUEUE_POP_TIMEOUT` | Attente max du worker sur la file Redis. |
| `ORI_WORKER_HEARTBEAT_TTL` | Fenêtre de validité du heartbeat worker. |
| `ORI_WEBHOOK_URL` | Active **oristream** : webhook JSON envoyé en fin de scan. |
| `ORI_DIGEST_INTERVAL_S` | Intervalle entre deux runs de **oridigest**. |
| `ORI_DIGEST_LOOKBACK_HOURS` | Fenêtre d’agrégation du digest. |
| `ORI_DIGEST_TOP_N` | Nombre max de findings mis en avant dans le digest. |
| `ORI_DIGEST_WEBHOOK_URL` | Webhook de sortie pour **oridigest**. |
| `ORI_CADDY_ADDRESS` | Adresse Caddy. Laisser vide pour `:80` local ; mettre `scan.votredomaine.tld` sur VPS pour HTTPS auto. |

## HTTPS

Définissez `ORI_CADDY_ADDRESS=scan.votredomaine.tld` dans l’environnement du service `caddy` pour activer automatiquement HTTPS (Let’s Encrypt) si le DNS pointe vers le VPS.

## Réglage hôte recommandé

Redis recommande d’activer l’overcommit mémoire sur le VPS :

```bash
sudo sysctl vm.overcommit_memory=1
echo 'vm.overcommit_memory = 1' | sudo tee /etc/sysctl.d/99-oriradar.conf
```

## Client web (hors dépôt resolver)

Si ton SPA vit dans le **monorepo Oriradar** (Vite), configure `VITE_SCAN_API_BASE_URL` vers l’URL publique du scan, par ex. :

```env
VITE_SCAN_API_BASE_URL=https://scan.votredomaine.tld
```

(ou `http://IP` en test, en autorisant l’origine dans CORS côté [`backend/oritypo_solver/main.py`](../backend/oritypo_solver/main.py).)

Sur le VPS, le dépôt **oriradar-resolver** ne contient que backend / Docker ; pas de variables Vite.

## Test de scan

```bash
curl -X POST http://127.0.0.1/v1/scans \
  -H 'content-type: application/json' \
  -d '{"target":"example.com"}'
```

Puis :

```bash
curl http://127.0.0.1/v1/scans/<scan_id>
```

Les findings peuvent ensuite être enrichis avec :

- `screenshot.status`
- `screenshot.url`
- `crawl.status`
- `crawl.pages_visited`
- `crawl.forms_count`

## Workers

- **worker** : scan principal
- **oriframe** : screenshots conditionnels
- **oricrawl** : crawl léger
- **oridigest** : digest récurrent
