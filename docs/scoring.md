# Scoring Ori (oriscore) — référence complète

Ce document décrit **comment** le module [`backend/oritypo_solver/services/scoring.py`](../backend/oritypo_solver/services/scoring.py) calcule les scores, **sans** dépendre d'une implémentation externe : la source de vérité est le code cité.

## Rôle des deux scores

Chaque *finding* (domaine enregistré détecté) reçoit :

| Champ | Question |
|--------|----------|
| **`score`** | Risque **immédiat** : le domaine est-il déjà actif ou dangereux au sens *abus / usurpation / hébergement malveillant probable* ? |
| **`prediction_score`** | **Potentiel prédictif** : même immature (DNS minimal, page vide, parking), mérite-t-il une veille renforcée ? |

Les niveaux associés :

| Champ | Seuils (implémentation actuelle) |
|--------|-----------------------------------|
| **`risk_level`** | `critical` >= 80 · `high` >= 60 · `medium` >= 35 · sinon `low` |
| **`prediction_level`** | `critical` >= 75 · `high` >= 55 · `medium` >= 35 · sinon `low` |

Les deux scores sont **bornés entre 0 et 100** après sommation des contributions.

## Données d'entrée

Le scoring utilise :

- **`distance`** et **`kind`** : produits par **orifold** (préfixe de kind `orifold:` dans le code).
- **`dns_records`** : dictionnaires de listes (`A`, `AAAA`, `MX`, `NS`, `CNAME`) depuis **oriseek** / fallback Python.
- **`http_result`** : **oriprobe** (`httpx`), ou `None` si non sondé. Inclut désormais `favicon_hash` et `cert_sans`.
- **`rdap_result`** : **orirdap**, uniquement si `available` est vrai (métadonnées obtenues).
- **`crawl_result`** : **oricrawl** après exécution du worker ; absent ou `status != "completed"` tant que le crawl n'a pas fini.
- **`reference_data`** : données de référence du site officiel (crawl, embedding, favicon hash, certificat TLS), collectées au début du scan par `_fetch_reference_data`.

Les **captures oriframe** ne modifient **pas** les scores numériques dans la version actuelle : elles servent à l'investigation humaine et à l'UI.

## Familles de permutation (`kind`)

Les constantes `HIGH_SIGNAL_KINDS` et `MEDIUM_SIGNAL_KINDS` du fichier `scoring.py` classent les types `orifold:*` et `oricert:*` :

- **Fort signal** : ex. `Bitsquatting`, `Homoglyph`, `Mapped`, `Subdomain`, `WrongSld`, `MultiOmission`, `PermutationCrossTld`, `ReverseWord`, `CountryCodeAffix`, **`oricert:CT`** (domaine déjà certifié dans la nature).
- **Signal moyen** : ex. `Addition`, `Tld`, `VowelSwap`, `Keyword`, etc.

> `oricert:CT` représente un domaine **réellement enregistré** et **déjà certifié** par une autorité publique (visible dans les Certificate Transparency logs). Comme cette preuve d’existence est plus forte qu’une simple permutation théorique, il est traité comme un fort signal.

Contribution au **`score`** :

| Régime | Points |
|--------|--------|
| Kind fort | +18 |
| Kind moyen | +10 |
| Autre / non listé | 0 (la distance compte toujours) |

Contribution au **`prediction_score`** :

| Régime | Points |
|--------|--------|
| Kind fort | +18 |
| Kind moyen | +10 |
| Autre | 0 |

## Distance de Levenshtein (apex)

| Distance | `score` | `prediction_score` |
|----------|---------|---------------------|
| <= 1 | +25 / raison *very close...* | +35 / *very close brand distance* |
| 2 | +18 / *close...* | +24 |
| 3 | +8 / *moderately close...* | +12 |
| >= 4 | **-10** / *far from the target* | **0** |

Distance >= 4 entraine une penalite : la ressemblance est trop faible pour etre un typosquat credible.

## Signaux DNS

Les MX « significatifs » excluent les enregistrements placeholder (`0 .`, `localhost`, etc.) — fonction `_meaningful_mx_records`.

### Score immédiat (`score`)

| Condition | Points | Note |
|-----------|--------|------|
| Presence `A` ou `AAAA` | +15 | *resolves to an IP address* |
| MX significatifs | +8 | *has mail infrastructure* |
| MX uniquement placeholder | +2 | *placeholder mail exchange* |
| `NS` presents | +4 | *delegated name servers* |
| `CNAME` presents | +6 | *aliases another hostname* |
| CNAME vers hote parking (heuristique) | -8 | *aliases a parking-like host* |
| NS seuls, sans A/AAAA/MX utile/CNAME | -4 | *only exposes name servers* |

### Score prédictif (`prediction_score`)

| Condition | Points |
|-----------|--------|
| `A` ou `AAAA` | +5 |
| `NS` | +3 |
| MX significatifs | +5 |
| MX placeholder | +2 |
| `CNAME` | +3 |

## Signaux HTTP (oriprobe)

### Score immédiat

Appliqué seulement si `http_result` est présent et `reachable` est vrai (sauf pénalités explicites).

| Condition | Points | Commentaire |
|-----------|--------|-------------|
| `reachable` | +10 | *serves HTTP content* |
| `200 <= status_code < 400` | +5 | succes ou redirection HTTP |
| `status_code >= 400` | **-12** | code d'erreur HTTP (renforce) |
| `scheme == "https"` | +3 | |
| `title` non vide | +2 | |
| `login_page` | +8 | page type login / compte |
| `redirects >= 2` | +3 | chaine de redirections |
| `final_host_matches_input is False` | +4 | redirection vers autre hote |
| `challenge_page` | -6 | protection type challenge |
| `parking_page` | -32 | parking / vente de domaine |
| `favicon_hash` identique au site officiel | +10 | *favicon matches the official site* |
| Certificat TLS mentionne la marque | +6 | *TLS certificate references the brand name* |
| Certificat TLS wildcard generique (SANs <= 2) | **-8** | *generic wildcard certificate* (renforce, exclusif du brand match) |

### Score predictif

| Condition | Points |
|-----------|--------|
| `reachable` | +5 |
| `login_page` | +8 |
| `parking_page` | +5 (signal de monetisation / revendeur) |
| `challenge_page` | +2 |
| `final_host_matches_input is False` | +5 |
| `favicon_hash` identique au site officiel | +8 |
| Certificat TLS mentionne la marque | +5 |

Si `http_result` est absent, aucune de ces lignes ne s'applique.

## Signaux RDAP (orirdap)

Uniquement si `rdap_result.get("available")` est vrai.

### Score immédiat

| Condition | Points |
|-----------|--------|
| Métadonnées disponibles | +5 |
| `registrar` renseigné | +3 |
| Âge d'enregistrement <= 30 jours | +10 |
| Âge <= 180 jours | +6 |
| Âge >= 3650 jours (environ 10 ans) | -4 |

### Score predictif

Les bonus pour domaine recent dependent desormais de la presence d'**infrastructure** (A/AAAA/MX/HTTP reachable). Sans infra, les bonus sont divises par 2 : un domaine juste enregistre mais inactif n'est pas une menace imminente.

| Condition | Points (avec infra) | Points (sans infra) |
|-----------|---------------------|---------------------|
| Metadonnees disponibles | +2 | +2 |
| Age <= 30 jours | +12 | +6 |
| Age <= 180 jours | +7 | +3 |
| Age >= 3650 jours | -3 | -3 |

L'âge est dérivé de `registered_at` via `_registered_age_days`.

## Signaux crawl (oricrawl)

Uniquement si `crawl_result.get("status") == "completed"`.

### Score immédiat

| Condition | Points |
|-----------|--------|
| `password_forms_count > 0` | +8 |
| `forms_count > 0` | +4 |
| `login_urls` non vide | +6 |
| `payment_urls` non vide | +5 |
| `meta_brand_hits > 0` | +4 |
| `external_http_urls` non vide | +2 |
| `content_snippet` < 50 caractères | -3 |

### Score prédictif

| Condition | Points |
|-----------|--------|
| `brand_term_hits > 0` | +6 |
| `meta_brand_hits > 0` | +5 |
| `login_urls` non vide | +6 |
| `payment_urls` non vide | +5 |
| `password_forms_count > 0` | +8 |
| `external_http_urls` non vide | +3 |

**oricrawl** enrichit la page d'accueil et les liens **même host** jusqu'aux limites `ORI_CRAWL_MAX_PAGES`, `ORI_CRAWL_MAX_DEPTH`, etc. Les champs agrégés incluent titres, meta descriptions, extrait de texte (`content_snippet`), URLs externes échantillonnées, compteurs de scripts, etc. (voir [`oricrawl.py`](../backend/oritypo_solver/services/oricrawl.py)).

## Similarité sémantique (orisim)

Module [`backend/oritypo_solver/services/orisim.py`](../backend/oritypo_solver/services/orisim.py).

Au début du scan, le contenu du **site officiel** (titre, meta descriptions, headings, snippet) est crawlé et encodé en **embedding** via `sentence-transformers` (modèle `all-MiniLM-L6-v2` par défaut). Cet embedding de référence est stocké dans `reference_data.content_embedding`.

Après chaque crawl de finding, la similarité cosinus entre l'embedding de référence et celui du contenu crawlé est calculée et stockée dans `finding.similarity` (0.0 à 1.0).

Les bonus et penalites de similarite ne s'appliquent que si `reference_data.content_embedding` est disponible (le site officiel a ete crawle avec succes).

### Score immediat

| Similarite | Points | Raison |
|------------|--------|--------|
| >= 0.85 | +15 | *content closely resembles the official site* |
| >= 0.65 | +8 | *content moderately resembles the official site* |
| >= 0.45 et < 0.65 | **-5** | *content shows limited overlap* (zone grise) |
| >= 0.30 et < 0.45 | **-12** | *content has little overlap* |
| < 0.30 | **-20** | *content bears no resemblance to the official site* |

La zone grise (0.30 - 0.65) est desormais **penalisante** : un site qui a peu de rapport avec la marque officielle est traite comme suspect (faible chance d'imitation reelle), pas comme un signal positif.

### Score predictif

| Similarite | Points |
|------------|--------|
| >= 0.85 | +12 |
| >= 0.65 | +6 |
| >= 0.30 et < 0.45 | **-5** |
| < 0.30 | **-10** |

### Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `ORI_ENABLE_SIMILARITY` | `true` | Active/désactive le calcul de similarité |
| `ORI_SIMILARITY_MODEL` | `all-MiniLM-L6-v2` | Modèle sentence-transformers utilisé |

## Données de référence (`reference_data`)

Collectées au début de chaque scan par `_fetch_reference_data(apex)` dans [`scan_engine.py`](../backend/oritypo_solver/services/scan_engine.py) :

| Champ | Source | Usage |
|-------|--------|-------|
| `target` | Apex du scan | Extraction du label de marque |
| `favicon_hash` | `oriprobe` du site officiel | Comparaison favicon |
| `cert_sans` | Certificat TLS du site officiel | Détection de marque dans les SANs |
| `content_text` | `oricrawl` du site officiel (1 page) | Texte de référence |
| `content_embedding` | `orisim.encode_text()` | Vecteur pour similarité cosinus |

## Deductions de legitimite (score immediat uniquement)

Apres le calcul de tous les signaux positifs et negatifs, un bloc de **deductions de legitimite** est applique dans `score_finding`. Il reduit le score quand des indices convergent vers un site independant et non une imitation :

| Condition | Deduction | Raison |
|-----------|-----------|--------|
| Age RDAP >= 10 ans (3650 jours) | -12 | Domaine ancien, peu probable qu'il s'agisse de typosquatting recent |
| Age RDAP >= 5 ans (1825 jours) | -6 | Domaine etabli |
| Similarite < 0.30 + aucun signal malveillant (pas de login, payment, password forms) | -10 | Contenu sans rapport et pas de tentative d'usurpation |
| Favicon different du site officiel (les deux presents) | -5 | Pas une copie visuelle |

Les deductions sont cumulatives. Par exemple, un domaine de 12 ans avec similarite 0.18, sans login et avec un favicon different recevra : -12 (age) -10 (sim+legit) -5 (favicon) = **-27 points** de deductions de legitimite, en plus du -15 de la penalite de similarite.

Ce mecanisme permet a un site comme `oogle.com` (sim=0.18, legit, ancien) de passer de ~100 a ~45-55, tandis qu'un vrai site de phishing (sim=0.90, login, recent) conserve son score critique.

## Resume de scan (`build_summary`)

La fonction `build_summary` agrège des **compteurs** sur l'ensemble des findings : variantes totales, nombre enregistrés, sondages HTTP, RDAP, parking, login-like, redirections cross-host, files screenshot/crawl en file ou terminées, répartition des niveaux de risque et de prédiction, scores max, etc. Elle ne recalcule pas les scores ; elle reflète l'état **après** le dernier passage de `score_finding` / `score_prediction_finding` (et **recompute** après enrichissements asynchrones).

## Recalcul après enrichissements

[`scan_engine.recompute_scan_derived_state`](../backend/oritypo_solver/services/scan_engine.py) re-note chaque finding et régénère le résumé lorsque **oricrawl** ou **oriframe** met à jour un enregistrement : les scores peuvent **changer** lorsque `crawl_result` devient disponible. Le recalcul inclut désormais le calcul de similarité pour les findings dont le crawl vient de se terminer.

## Politiques de déclenchement (hors scoring)

Les seuils pour mettre en file **oriframe** et **oricrawl** sont dans [`enrichment_policy.py`](../backend/oritypo_solver/services/enrichment_policy.py) (`ORI_ENABLE_SCREENSHOTS`, `ORI_SCREENSHOT_*`, `ORI_ENABLE_CRAWL`, `ORI_CRAWL_*`, etc.). Elles ne modifient pas la formule de score : elles décident **quels** findings recevront un enrichissement lourd.

## Webhooks et digest

- **oristream** : événement de fin de scan (`ORI_WEBHOOK_URL`) — indépendant des formules de score.
- **oridigest** : agrégat périodique sur les scans complétés (`ORI_DIGEST_*`) — statistiques et envoi optionnel vers `ORI_DIGEST_WEBHOOK_URL`, pas de score par finding supplémentaire.

## Limites et évolution

- Pas de calibration par secteur ni par client dans le code actuel.
- Les captures d'écran n'entrent pas dans la somme des points (pas d'OCR / pas de classif image).
- Les pondérations sont **explicables** (liste `reasons` par finding) et peuvent être ajustées dans `scoring.py` en conservant des tests unitaires.

Pour la liste des outils et du déploiement : [`docs/ori-tools.md`](ori-tools.md).
