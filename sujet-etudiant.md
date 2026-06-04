# TP DevSecOps — Sécurité applicative avec pipeline CI/CD
## Master 1 Cybersécurité SECU | École IT · Durée : 5 heures

## Vous pouvez vous servir d'internet ou de l'IA pour faire des recherches afin de finaliser le TP, améliorer le code, et déployer l'application sur Gitlab

---

## Contexte

Vous intégrez l'équipe DevSecOps de **VulnShop**, une application e-commerce Python.
Le code source contient des vulnérabilités intentionnelles que votre pipeline de sécurité doit détecter automatiquement.

Votre mission : mettre en place un pipeline GitLab CI qui analyse, détecte et reporte les vulnérabilités **sans intervention humaine**, puis exploiter manuellement certaines failles pour comprendre leur impact réel.

**Environnement:**
- Kali Linux (VM ou poste de TP)
- Docker + Docker Compose
- Gitlab CI
- Burp Suite Community Edition
- Outils CLI : `bandit`, `trivy`, `sonar-scanner`

---

## Architecture du projet

```
vulnshop/
├── .gitlab-ci.yml          ← Pipeline CI (à compléter)
├── sonar-project.properties
├── app/
│   ├── app.py              ← Application Flask vulnérable
│   ├── requirements.txt
│   └── Dockerfile
└── ci/
    ├── docker-compose.yml
    └── generate_report.py
```

---

## Partie 1 — Mise en place de l'environnement 

### 1.1 Démarrage de l'environnement local

```bash
# Cloner le dépôt 
git clone https://gitlab.votre_compte.com/tp-devsecops/vulnshop.git
cd vulnshop

# Vérifier que Docker est opérationnel
docker --version
docker compose version

# Démarrer SonarQube et l'application
docker compose -f ci/docker-compose.yml up -d sonarqube vulnshop-app sonar-db

# Attendre ~2 min que SonarQube démarre
docker compose -f ci/docker-compose.yml logs -f sonarqube
# Appuyer Ctrl+C quand vous voyez "SonarQube is operational"
```

### 1.2 Configuration SonarQube

1. Ouvrir http://localhost:9000 dans votre navigateur
2. Se connecter : `admin` / `admin` (changer le mot de passe quand demandé)
3. Créer un nouveau projet manuel : **Clé** = `vulnshop`, **Nom** = `VulnShop TP`
4. Générer un token d'authentification et le noter

```bash
# Exporter le token (remplacer par votre token réel)
export SONAR_TOKEN="squ_xxxxxxxxxxxxxxxxxxxx"
```

### 1.3 Vérification de Trivy et Bandit

```bash
# Installer Bandit
pip install bandit

# Vérifier Trivy (installer si absent)
trivy --version || curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Test rapide
bandit --version
trivy --version
```

**Question 1.1** : Quelle est la version de Trivy installée ? Quelle base de données de CVE utilise-t-il par défaut ?

---

## Partie 2 — Analyse statique avec Bandit 

### 2.1 Première analyse

```bash
# Analyse basique
bandit -r app/

# Analyse avec rapport JSON
bandit -r app/ -f json -o bandit-report.json

# Analyser uniquement les sévérités HIGH
bandit -r app/ --severity-level high

# Afficher le contexte (lignes de code autour de chaque vuln)
bandit -r app/ -v
```

### 2.2 Analyse des résultats

Ouvrir le fichier `bandit-report.json` et répondre aux questions suivantes :

**Question 2.1** : Combien de vulnérabilités de sévérité HIGH Bandit détecte-t-il ? Lesquelles ?

**Question 2.2** : Quel identifiant Bandit correspond à l'utilisation de `subprocess` avec `shell=True` ? Pourquoi est-ce dangereux ?

**Question 2.3** : Bandit signale `B324` sur la fonction `hashlib.md5`. Quel algorithme de hachage faudrait-il utiliser à la place pour stocker des mots de passe ? Justifiez.

**Question 2.4** : Identifiez la ligne de code correspondant au test `B506`. Quelle est la vulnérabilité ? Comment la corriger ?

### 2.3 Ajout de règles dans `.banditrc`

Créez un fichier `.banditrc` à la racine du projet pour exclure certains tests non pertinents :

```ini
[bandit]
skips = B101
tests = B102,B103,B104,B105,B106,B107,B108
```

**Question 2.5** : Pourquoi exclure `B101` (assertions) dans un TP mais pas en production ?

---

## Partie 3 — Analyse de composition avec Trivy 

### 3.1 Scan du système de fichiers

```bash
# Scanner les dépendances Python
trivy fs app/ --severity HIGH,CRITICAL

# Scanner avec sortie JSON
trivy fs app/ --format json -o trivy-fs.json

# Scanner le Dockerfile pour les mauvaises pratiques
trivy config app/Dockerfile
```

### 3.2 Build et scan de l'image Docker

```bash
# Construire l'image
docker build -t vulnshop:tp app/

# Scanner l'image complète
trivy image vulnshop:tp --severity CRITICAL,HIGH,MEDIUM

# Lister uniquement les CVEs avec un correctif disponible
trivy image vulnshop:tp --ignore-unfixed --severity HIGH,CRITICAL
```

**Question 3.1** : Combien de CVEs CRITICAL l'image Docker contient-elle ? Listez les 3 plus sévères avec leur score CVSS.

**Question 3.2** : Quelle version de `PyYAML` est installée ? Quelle CVE lui est associée ? Quelle version corrige la vulnérabilité ?

**Question 3.3** : Trivy signale des problèmes dans le Dockerfile. Lesquels ? Comment réécrire le Dockerfile pour les corriger ?

**Question 3.4** : Quelle est la différence entre `trivy fs` et `trivy image` ? Dans quel cas utiliser l'un ou l'autre dans un pipeline CI ?

---

## Partie 4 — Analyse avec SonarQube

### 4.1 Lancer l'analyse

```bash
# Depuis la racine du projet
sonar-scanner \
  -Dsonar.projectKey=vulnshop \
  -Dsonar.sources=app/ \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=$SONAR_TOKEN \
  -Dsonar.python.version=3
```

### 4.2 Explorer l'interface SonarQube

1. Ouvrir http://localhost:9000/dashboard?id=vulnshop
2. Explorer les onglets **Issues**, **Security Hotspots** et **Measures**

**Question 4.1** : Combien de Security Hotspots SonarQube identifie-t-il ? Lesquels se recoupent avec les résultats Bandit ?

**Question 4.2** : Quelle est la différence entre un **Bug**, une **Vulnerability** et un **Security Hotspot** dans la terminologie SonarQube ?

**Question 4.3** : Quelle note de fiabilité (**Reliability Rating**) obtient l'application ? Que faudrait-il corriger pour passer en note A ?

---

## Partie 5 — Exploitation manuelle avec Burp Suite

Démarrez l'application si ce n'est pas déjà fait :

```bash
docker compose -f ci/docker-compose.yml up -d vulnshop-app
# Application disponible sur http://localhost:5000
```

Configurez Burp Suite Community en proxy (127.0.0.1:8080) et votre navigateur pour l'utiliser.

### 5.1 Injection SQL

Testez le point d'entrée `/login` :

```bash
# Test avec curl (sans Burp)
curl -X POST http://localhost:5000/login \
  -d "username=admin'--&password=anything"
```

**Question 5.1** : La requête ci-dessus vous connecte-t-elle ? Expliquez pourquoi en affichant la requête SQL construite côté serveur.

**Question 5.2** : Formulez une payload SQLi permettant de récupérer tous les utilisateurs sans connaître aucun mot de passe.

### 5.2 XSS reflété

Tester le point `/search` :

```
http://localhost:5000/search?q=<script>alert('XSS')</script>
```

**Question 5.3** : L'alerte s'affiche-t-elle ? Formulez un payload XSS permettant d'exfiltrer le cookie de session vers un serveur externe.

### 5.3 Injection de commande OS

```bash
curl "http://localhost:5000/ping?host=localhost;id"
```

**Question 5.4** : Que retourne la requête ? Proposez un payload permettant d'afficher le fichier `/etc/passwd`.

---

## Partie 6 — Pipeline GitLab CI 

### 6.1 Configuration du pipeline

Ouvrir le fichier `.gitlab-ci.yml` fourni. Il comporte des commentaires `# TODO` à compléter :

**TODO 6.1** : Dans le job `bandit-sast`, modifier la commande pour que le pipeline **échoue** si Bandit détecte au moins une vulnérabilité de sévérité HIGH. (Indice : paramètre `--exit-zero`)

**TODO 6.2** : Dans le job `trivy-image-scan`, modifier `TRIVY_EXIT_CODE` pour que le pipeline bloque sur les CVEs CRITICAL.

**TODO 6.3** : Ajouter un job `dependency-check` dans le stage `sast` qui utilise `pip-audit` pour analyser les dépendances Python :

```yaml
pip-audit:
  stage: sast
  image: python:3.9-slim
  script:
    # Compléter ici
```

### 6.2 Push et observation

```bash
git add .
git commit -m "feat: add devsecops pipeline"
git push origin main
```

Observer l'exécution dans **CI/CD → Pipelines** de votre projet GitLab.

**Question 6.1** : Combien de jobs s'exécutent en parallèle ? Pourquoi ?

**Question 6.2** : Le stage `scan-image` a un `needs: [build-image]`. Que se passerait-il si on supprimait cette dépendance ?

**Question 6.3** : Pourquoi les jobs ont-ils `allow_failure: true` ? Dans un vrai pipeline de production, changeriez-vous cette valeur ? Pour quel(s) job(s) ?

---

## Partie 7 — Remédiation (bonus)

Corrigez **3 vulnérabilités** de votre choix dans `app.py` et relancez le pipeline. Documenter chaque correction :

| Vuln | Ancienne ligne | Nouvelle ligne | Bandit ID |
|------|---------------|----------------|-----------|
| ...  | ...           | ...            | ...       |

**Question 7.1** : Le nombre d'issues Bandit a-t-il diminué après vos corrections ? SonarQube reflète-t-il les changements immédiatement ?

---

## Rendu attendu

1. Le fichier `.gitlab-ci.yml` complété (TODOs résolus)
2. Un fichier `reponses.md` avec toutes les réponses numérotées
3. Les rapports `bandit-report.json` et `trivy-fs.json`
4. Une capture d'écran du tableau de bord SonarQube
5. Une capture d'écran du pipeline GitLab réussi
