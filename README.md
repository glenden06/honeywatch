# 🍯 HoneyWatch — Live Threat Map

Un **honeypot défensif** léger qui attire les scanners automatisés d'Internet, capture
chaque tentative de connexion (IP, identifiant, mot de passe, service visé) et la projette
en temps réel sur une **carte mondiale des attaques**.

> 100 % bibliothèque standard Python — aucun `pip install`. Backend < 400 lignes, dashboard autonome.

![Blue Team](https://img.shields.io/badge/Blue%20Team-Detection-f0564a)
![Python](https://img.shields.io/badge/Python-3.9%2B-36c3a8)
![Dependencies](https://img.shields.io/badge/dependencies-0-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## 🇫🇷 À quoi ça sert

Dès qu'une machine est exposée sur Internet, elle est scannée et attaquée en continu par des
botnets (Mirai & co.) qui testent des identifiants par défaut. HoneyWatch se fait passer pour
une cible facile (faux Telnet / SSH / FTP), **laisse les attaquants croire qu'ils dialoguent
avec un vrai service**, et enregistre tout ce qu'ils tentent — sans jamais exécuter quoi que
ce soit. C'est un outil de **threat intelligence** : on observe les tactiques réelles des
attaquants pour mieux défendre les vrais systèmes.

### Démarrage en 2 minutes (démo locale, données simulées)

```bash
python3 seed_demo.py          # génère ~400 attaques réalistes réparties sur 24 h
python3 server.py             # lance le dashboard
# ouvrir http://localhost:8080
```

### En conditions réelles

```bash
# Terminal 1 — le leurre (ports hauts, sans privilèges)
python3 honeypot.py --ports 2323,2121,2222

# Terminal 2 — le dashboard
python3 server.py
```

Pour capter le trafic des bots sur les **vrais ports** (23, 21, 22), il faut les privilèges
root et libérer le port SSH réel au préalable (voir « Déploiement VPS » plus bas).

---

## 🗺️ Ce que montre le dashboard

| Élément | Donnée |
|---|---|
| **Carte mondiale** | chaque point = une IP attaquante, taille ∝ nombre de tentatives |
| **Flux en direct** | les dernières attaques avec pays, service, identifiant / mot de passe testés |
| **Compteurs** | total de tentatives, IP uniques, nombre de pays sources |
| **Top pays / identifiants / mots de passe** | les classements les plus parlants pour un rapport |
| **Activité 24 h** | histogramme horaire des attaques |

Rafraîchissement automatique toutes les 5 s. Géolocalisation via `ip-api.com` (sans clé),
mise en cache sur disque pour rester rapide et fonctionner hors-ligne après le premier appel.

---

## 🎯 Mapping MITRE ATT&CK

HoneyWatch collecte des preuves directes des techniques suivantes :

| Technique | ID | Observé dans |
|---|---|---|
| Brute Force | **T1110** | tentatives répétées d'identifiants |
| Brute Force : Password Guessing | **T1110.001** | couples login/mot de passe du flux |
| Valid Accounts / Default Accounts | **T1078.001** | usage de comptes par défaut (`root`, `admin`…) |
| Remote Services | **T1021** | ciblage SSH / Telnet / FTP |
| Active Scanning | **T1595** | connexions sans tentative de login |

---

## 🏗️ Architecture

```
          Internet (scanners, botnets)
                     │
          ┌──────────▼──────────┐
          │     honeypot.py     │  asyncio, multi-ports, capture seule
          │  (faux Telnet/SSH)  │  → n'exécute jamais rien
          └──────────┬──────────┘
                     │ append JSON Lines
             data/attacks.jsonl
                     │
          ┌──────────▼──────────┐      ┌─────────────┐
          │      server.py      │─────▶│  geoip.py   │ cache disque
          │  agrégation + API   │      │ (ip-api)    │
          └──────────┬──────────┘      └─────────────┘
                     │ /api/stats (JSON)
          ┌──────────▼──────────┐
          │  dashboard/index.html│  carte Leaflet + flux temps réel
          └─────────────────────┘
```

**Choix de conception :**

- **Capture uniquement, jamais d'exécution** → risque nul côté hôte, c'est un *low-interaction honeypot*.
- **JSON Lines append-only** → format simple, inviolable en écriture concurrente, ré-analysable par n'importe quel outil (jq, pandas, un SIEM…).
- **Zéro dépendance** → se déploie sur n'importe quel VPS en `git clone` + `python3`, aucune surface d'attaque ajoutée par des libs tierces.
- **Géoloc cachée sur disque** → une IP n'est résolue qu'une fois ; le dashboard reste utilisable sans réseau.

---

## 🚀 Déploiement VPS (capture réelle)

```bash
# Sur un VPS jetable que VOUS possédez (jamais chez vous / au bureau)
git clone https://github.com/glenden06/honeywatch.git && cd honeywatch

# Déplacer votre vrai SSH sur un autre port AVANT d'ouvrir le 22 au leurre
sudo sed -i 's/#Port 22/Port 2200/' /etc/ssh/sshd_config && sudo systemctl restart ssh
# (reconnectez-vous en 2200, vérifiez, puis seulement ensuite :)

sudo python3 honeypot.py --ports 22,23,21     # root pour les ports < 1024
python3 server.py --port 8080                  # dashboard (derrière un reverse proxy / VPN de préférence)
```

Les premières tentatives arrivent en général **en quelques minutes**.

---

## 🛡️ Usage responsable & cadre légal

- Déployez uniquement sur une infrastructure **que vous possédez**. Capturer le trafic qui
  vous est envoyé est légal ; sonder ou piéger les systèmes d'autrui ne l'est pas.
- Un honeypot **ne doit jamais** tourner sur un réseau de production, domestique ou d'entreprise :
  isolez-le (VPS dédié, segment réseau séparé).
- Les identifiants capturés appartiennent aux **attaquants**, pas à de vrais utilisateurs —
  mais traitez les logs comme des données sensibles malgré tout.

---

## 🇬🇧 Developer notes

### Project layout

| File | Role |
|---|---|
| `honeypot.py` | asyncio TCP listener, per-port service persona, capture-only login flow |
| `geoip.py` | key-less GeoIP lookup with on-disk cache |
| `server.py` | stdlib HTTP server: static dashboard + `/api/stats` live aggregation |
| `seed_demo.py` | realistic demo data + pre-filled geo cache (for screenshots/video) |
| `dashboard/index.html` | self-contained live UI (Leaflet dark map + feed, no build step) |

### Event schema (`data/attacks.jsonl`)

```json
{"ts":"...","event":"login_attempt","ip":"...","port":2323,"service":"telnet","username":"root","password":"123456"}
{"ts":"...","event":"connection","ip":"...","port":2323,"service":"telnet"}
```

### Extending it

- **More services:** add an entry to `SERVICES` in `honeypot.py` (port → banner + prompts).
- **Feed a SIEM:** `tail -f data/attacks.jsonl` into Filebeat/Fluent Bit, or point your SOC-AI
  log parser at it — the JSONL format is already normalised.
- **Alerting:** threshold on `unique_ips` or a single IP's attempt count in `build_stats()`.

---

## 💼 Points de défense (oral / entretien)

- *« Pourquoi un honeypot plutôt qu'un IDS ? »* → l'IDS détecte dans **mon** trafic ; le honeypot
  génère de la **threat intel** sur les TTP réels des attaquants, sans faux positifs (toute
  connexion y est malveillante par définition).
- *« Low vs high interaction ? »* → j'ai choisi low-interaction : capture seule, aucune exécution,
  donc aucun risque de compromission de l'hôte. Un high-interaction donnerait plus de contexte
  mais demande une sandbox durcie.
- *« Et le passage à l'échelle ? »* → JSON Lines append-only + géoloc cachée ; on branche
  directement un SIEM ou mon pipeline SOC-AI sur le fichier normalisé.
- *« Secteur bancaire ? »* → le credential stuffing et les comptes par défaut sont le vecteur
  n°1 ; HoneyWatch chiffre concrètement la pression d'attaque et alimente les règles de détection.

---

## 📣 Template de post LinkedIn

> 🍯 J'ai exposé un honeypot sur Internet pendant 48 h. Voici qui a frappé à la porte.
>
> J'ai développé **HoneyWatch**, un honeypot défensif en Python (zéro dépendance) qui se fait
> passer pour un serveur vulnérable, capture chaque tentative d'intrusion et la projette sur une
> carte mondiale en temps réel.
>
> Résultat : **X tentatives** depuis **Y pays** en 48 h, avec toujours les mêmes identifiants
> par défaut (`root` / `123456`…). Un rappel brutal que tout ce qui est exposé est attaqué
> en continu.
>
> Mapping MITRE ATT&CK (T1110 Brute Force), carte live, flux d'attaques, top credentials —
> code open-source 👇
>
> #cybersecurity #blueteam #honeypot #threatintelligence #python #SOC
```
(Remplacez X et Y par vos vrais chiffres après déploiement — c'est ce qui rend le post crédible.)
```
