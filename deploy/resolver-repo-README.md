# oriradar-resolver

API et workers **oritypo-solver** pour Oriradar : permutations (**orifold**), DNS (**oriseek**), HTTP, scoring, enrichissements optionnels (captures, crawl, digest).

Ce dépôt est la **vue serveur uniquement**, synchronisée depuis le monorepo Oriradar (`scripts/publish-to-oriradar-resolver.sh`).

## Contenu

| Dossier | Rôle |
| -------- | ------------------------------------------ |
| `backend/` | FastAPI + workers Python (`oritypo_solver`) |
| `crates/` | Binaires Rust **orifold** et **oriseek** |
| `deploy/` | Docker Compose, Dockerfiles, Caddy |
| `docs/` | Documentation des outils Ori et du scoring |

## Déploiement VPS

```bash
cd deploy
cp .env.example .env   # adapter variables
docker compose up -d --build
```

Détails : `deploy/README.md`. Outils : `docs/ori-tools.md`. Scoring : `docs/scoring.md`.

## Développement local

Voir `backend/README.md`.

## Licence

Apache-2.0 — voir `LICENSE`.
