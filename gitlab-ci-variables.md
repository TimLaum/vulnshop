# gitlab-ci-variables.md
# Variables CI/CD à configurer dans GitLab
# Settings → CI/CD → Variables

## Variables obligatoires

| Variable            | Type     | Valeur exemple                  | Protégée | Masquée |
|---------------------|----------|---------------------------------|----------|---------|
| SONAR_TOKEN         | Variable | squ_xxxxxxxxxxxxxxxxxxxxxxxx    | Oui      | Oui     |
| SONAR_HOST_URL      | Variable | http://sonarqube:9000           | Non      | Non     |
| CI_REGISTRY_USER    | Variable | (auto GitLab)                   | Non      | Non     |
| CI_REGISTRY_PASSWORD| Variable | (auto GitLab)                   | Oui      | Oui     |

## Variables optionnelles (contrôle du pipeline)

| Variable          | Valeur défaut | Description                                |
|-------------------|---------------|--------------------------------------------|
| TRIVY_EXIT_CODE   | 0             | Mettre à 1 pour bloquer sur CRITICAL/HIGH  |
| TRIVY_SEVERITY    | CRITICAL,HIGH,MEDIUM | Niveaux à remonter                  |
| BANDIT_EXIT_ZERO  | true          | false = bloque si sévérité ≥ HIGH          |

## Génération du token SonarQube
# 1. Ouvrir http://localhost:9000
# 2. Se connecter (admin / admin par défaut, changer au 1er login)
# 3. Mon compte → Sécurité → Générer un token
# 4. Copier le token dans la variable SONAR_TOKEN de GitLab

## Enregistrement du runner GitLab (mode shell ou Docker)

# Mode Docker (recommandé pour le TP) :
docker run --rm -v /srv/gitlab-runner/config:/etc/gitlab-runner \
  gitlab/gitlab-runner register \
  --non-interactive \
  --url "https://gitlab.com/" \
  --registration-token "YOUR_REGISTRATION_TOKEN" \
  --executor "docker" \
  --docker-image "python:3.9-slim" \
  --description "tp-devsecops-runner" \
  --tag-list "devsecops,python" \
  --run-untagged="true" \
  --locked="false"

# Mode shell (si Docker indisponible) :
gitlab-runner register \
  --url "https://gitlab.com/" \
  --registration-token "YOUR_REGISTRATION_TOKEN" \
  --executor "shell" \
  --description "tp-shell-runner"

## Structure de dépôt GitLab attendue

vulnshop/
├── .gitlab-ci.yml
├── sonar-project.properties
├── app/
│   ├── app.py
│   ├── requirements.txt
│   └── Dockerfile
├── ci/
│   ├── docker-compose.yml
│   └── generate_report.py
└── README.md
