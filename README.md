# Network Mapper

`network_mapper.py` est un petit outil Python de cartographie réseau local basé sur Nmap. Il détecte des sous-réseaux locaux, lance une découverte d'hôtes, scanne des services ouverts sans mode agressif par défaut, extrait les informations utiles depuis les XML Nmap et génère des rapports exploitables.

## Usage autorisé uniquement

Utilise cet outil uniquement sur des réseaux que tu possèdes, administres ou pour lesquels tu as une autorisation explicite. Nmap peut déclencher des alertes de sécurité et perturber certains équipements fragiles. Le script limite volontairement les scans à `/16` ou plus précis pour réduire les erreurs de périmètre.

## Prérequis

- Python 3.10 ou plus récent.
- Nmap installé et présent dans le `PATH`.
- PyYAML si tu utilises `--known-topology` : `python -m pip install PyYAML`.
- Droits administrateur/root recommandés pour l'identification OS Nmap (`-O`). Sans ces droits, le script relance automatiquement le scan services sans `-O`.

## Installation de Python

Windows : installe Python depuis <https://www.python.org/downloads/windows/> et coche l'option `Add python.exe to PATH`.

Linux Debian/Ubuntu :

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip
```

Linux Fedora :

```bash
sudo dnf install python3 python3-pip
```

## Installation de Nmap

Windows : installe Nmap depuis <https://nmap.org/download.html>. Redémarre PowerShell si le `PATH` a été modifié.

Linux Debian/Ubuntu :

```bash
sudo apt update
sudo apt install nmap
```

Linux Fedora :

```bash
sudo dnf install nmap
```

## Vérification de Nmap dans le PATH

Windows PowerShell :

```powershell
nmap --version
Get-Command nmap
```

Linux :

```bash
nmap --version
command -v nmap
```

## Utilisation Windows PowerShell

```powershell
python .\network_mapper.py --subnet 192.168.20.0/24
python .\network_mapper.py --auto
python .\network_mapper.py --subnet 192.168.20.0/24 --skip-os
python .\network_mapper.py --subnet 192.168.20.0/24 --json --html-report
python .\network_mapper.py --subnet 192.168.20.0/24 --top-ports 100 --timeout 2400
python .\network_mapper.py --auto --detect-ip-conflicts
python .\network_mapper.py --auto --debug-auto
python .\network_mapper.py --auto --discover-routed-subnets
python .\network_mapper.py --auto --known-topology known_topology.yml
python .\network_mapper.py --auto --known-topology known_topology.yml --vuln passive
python .\network_mapper.py --auto --vuln nse --confirm-vuln-scan
```

Plusieurs sous-réseaux :

```powershell
python .\network_mapper.py --subnet 192.168.20.0/24 --subnet 192.168.30.0/24
```

## Utilisation Linux

```bash
python3 network_mapper.py --subnet 192.168.20.0/24
python3 network_mapper.py --auto
python3 network_mapper.py --subnet 192.168.20.0/24 --skip-os
python3 network_mapper.py --subnet 192.168.20.0/24 --json --html-report
python3 network_mapper.py --subnet 192.168.20.0/24 --top-ports 100 --timeout 2400
python3 network_mapper.py --auto --detect-ip-conflicts
python3 network_mapper.py --auto --debug-auto
python3 network_mapper.py --auto --discover-routed-subnets
python3 network_mapper.py --auto --known-topology known_topology.yml
python3 network_mapper.py --auto --known-topology known_topology.yml --vuln passive
python3 network_mapper.py --subnet 192.168.20.0/24 --vuln safe
```

Plusieurs sous-réseaux :

```bash
python3 network_mapper.py --subnet 192.168.20.0/24 --subnet 192.168.30.0/24
```

## Topologie connue

`--known-topology known_topology.yml` permet de corriger les limites d'une découverte Nmap pure : bridges Proxmox sans IP hôte, interfaces pfSense multi-réseaux, VM/CT et noms d'équipements. Les champs connus remplacent les déductions Nmap.

Exemple adapté au lab :

```yaml
bridges:
  vmbr0:
    network: 192.168.1.0/24
    interfaces: [tap100i0]
  vmbr1:
    network: 192.168.20.0/24
    interfaces: [tap100i1, tap102i0, veth200i0, enp1s0f0]

nodes:
  - name: pve-home
    role: proxmox
    ip: 192.168.1.2/24
    bridges: [vmbr0, vmbr1]
  - name: pfSense
    role: pfsense
    vmid: 100
    interfaces:
      - name: em0
        ip: 192.168.1.56/24
        bridge: vmbr0
      - name: em1
        ip: 192.168.20.1/24
        mac: BC:24:11:12:0B:E6
        bridge: vmbr1
  - name: FacturX-debian
    role: vm
    vmid: 102
    interfaces:
      - name: ens18
        ip: 192.168.20.28/24
        mac: BC:24:11:69:F4:A9
        bridge: vmbr1
  - name: gdrive-backup
    role: ct
    ctid: 200
    bridge: vmbr1
```

Exemples :

```bash
python network_mapper.py --auto --known-topology known_topology.yml
python network_mapper.py --auto --known-topology known_topology.yml --vuln passive
python network_mapper.py --subnet 192.168.20.0/24 --vuln safe
python network_mapper.py --auto --vuln nse --confirm-vuln-scan
```

Détection de conflits IP avec réglage de l'échantillonnage :

```bash
python network_mapper.py --subnet 192.168.20.0/24 --detect-ip-conflicts --conflict-samples 5 --conflict-interval 3
```

## Options principales

- `--auto` : détecte les sous-réseaux IPv4 privés de la machine locale. Sous Windows, PowerShell `Get-NetIPAddress -AddressFamily IPv4` est utilisé en priorité, avec fallback `ipconfig /all`.
- `--debug-auto` : affiche les interfaces vues par la détection automatique et les réseaux conservés.
- `--discover-routed-subnets` : ajoute une découverte heuristique des réseaux routés/amont via table de routes, passerelle par défaut et traceroute vers `1.1.1.1`/`8.8.8.8`. Les indices privés sont ramenés en candidats `/24`, validés par `nmap -sn`, et les candidats sans hôte actif sont rejetés.
- `--hunt-private-subnets --confirm-wide-scan` : active explicitement un mode large sur les plages privées RFC1918 complètes. Sans cette confirmation, le script ne scanne jamais `10.0.0.0/8`, `172.16.0.0/12` ou `192.168.0.0/16` par défaut.
- `--known-topology` : charge un YAML de topologie connue pour imposer noms, rôles, IP, MAC, VMID/CTID, bridges et interfaces. Ces données priment sur Nmap.
- `--subnet` : ajoute un sous-réseau à scanner. L'option est répétable.
- `--ports` : définit une liste de ports au format Nmap.
- `--top-ports` : utilise les N ports les plus courants selon Nmap au lieu de la liste par défaut.
- `--skip-os` ou `--no-os-detection` : désactive l'identification OS Nmap.
- `--discover-only` : limite l'exécution à `nmap -sn`.
- `--json` : génère `devices.json`.
- `--html-report` : génère `report.html`.
- `--detect-ip-conflicts` : échantillonne la table ARP/neigh locale pour détecter des conflits IP probables.
- `--vuln passive` : analyse localement les ports/services déjà détectés, sans scan supplémentaire.
- `--vuln safe` : lance des scripts NSE `safe` en plus de l'analyse passive.
- `--vuln nse --confirm-vuln-scan` : lance les scripts NSE `vuln`; ce mode exige une confirmation explicite et n'est jamais activé par défaut.
- `--conflict-samples` : nombre d'échantillons ARP/neigh, par défaut `3`.
- `--conflict-interval` : intervalle entre deux échantillons, par défaut `2` secondes.
- `--timeout` : définit le timeout par commande Nmap en secondes.

## Fichiers générés

Par défaut, les fichiers sont écrits dans `network_map_output/` :

- `devices.csv` : inventaire tabulaire des équipements.
- `ip_conflicts.csv` : conflits IP probables observés à partir des MAC Nmap, de la topologie connue et, si activé, ARP/neigh.
- `vulnerabilities.csv` : expositions/vulnérabilités détectées si `--vuln` est utilisé.
- `vulnerabilities.json` : export JSON des vulnérabilités si `--vuln` est utilisé.
- `vulnerability_report.md` : rapport Markdown des vulnérabilités si `--vuln` est utilisé.
- `report.md` : rapport Markdown lisible et versionnable.
- `topology.mmd` : schéma Mermaid de topologie logique.
- `commands.log` : commandes Nmap exécutées, code retour, sortie standard et erreur.
- `discovery_*.xml` : XML brut de découverte Nmap.
- `services_*.xml` : XML brut de scan services Nmap.
- `devices.json` : export JSON optionnel avec `--json`, contenant les clés `devices` et `ip_conflicts`.
- `report.html` : rapport HTML optionnel avec `--html-report`.

## CSV

`devices.csv` utilise le séparateur `;` pour faciliter l'ouverture dans Excel en environnement francophone. Colonnes :

- `ip` : adresse IPv4 détectée.
- `hostname` : noms d'hôtes fournis par Nmap.
- `mac` : adresse MAC si disponible.
- `vendor` : constructeur associé à la MAC si Nmap l'identifie.
- `status` : état Nmap de l'hôte.
- `device_type` : classification probable.
- `os_guess` et `os_accuracy` : OS probable et confiance Nmap si `-O` fonctionne.
- `ports` : ports ouverts.
- `services` : signatures services Nmap.
- `notes` : commentaire synthétique.

## Détection de conflits IP

Un conflit IP probable est signalé quand une même adresse IPv4 est observée avec plusieurs adresses MAC différentes. Une anomalie `same_mac_multiple_ips` est aussi signalée quand une même MAC apparaît sur plusieurs IPv4, par exemple une MAC vue sur `192.168.20.18` puis `192.168.20.60`. Le script utilise les MAC vues dans Nmap et dans `known_topology.yml`. Avec `--detect-ip-conflicts`, il ajoute plusieurs échantillons de la table locale des voisins : `arp -a` sous Windows, `ip neigh` sous Linux, puis `arp -n` en fallback si disponible.

Les adresses MAC sont normalisées en format `AA:BB:CC:DD:EE:FF`. Les entrées vides, incomplètes, broadcast `FF:FF:FF:FF:FF:FF`, nulles `00:00:00:00:00:00` ou invalides sont ignorées.

Sévérité :

- `high` : plusieurs MAC observées depuis plusieurs sources ou plusieurs échantillons.
- `medium` : plusieurs MAC observées dans une seule source.
- `low` : suspicion faible ou observation partielle.

Cette détection reste prudente : elle indique un conflit IP probable, pas une certitude absolue. Les tables ARP/neigh sont locales, temporaires et influencées par le trafic récent, les VLAN, les proxys ARP, les équipements redondants et les changements DHCP. Confirme avec les journaux DHCP, les tables ARP des routeurs, les tables MAC des switchs et, si possible, SNMP/LLDP/CDP.

## CSV des conflits IP

`ip_conflicts.csv` utilise le séparateur `;`. Colonnes :

- `ip` : IPv4 concernée.
- `mac_addresses` : MAC distinctes observées.
- `vendors` : constructeurs connus via Nmap si disponibles.
- `hostnames` : noms d'hôtes connus via Nmap si disponibles.
- `sources` : `nmap`, `arp` ou `ip_neigh`.
- `samples` : index d'échantillon, `0` et suivants pour Nmap, `1` et suivants pour ARP/neigh.
- `severity` : `high`, `medium` ou `low`.
- `notes` : explication courte.

## Rapport Markdown

`report.md` contient les sous-réseaux scannés, les passerelles détectées, l'inventaire des équipements, les conflits IP probables, le détail des services ouverts, les limites d'interprétation et le schéma Mermaid intégré.

## Schéma Mermaid

`topology.mmd` représente une topologie logique : poste de scan, passerelles/firewalls, sous-réseaux, bridges connus et hôtes. Avec `known_topology.yml`, pfSense peut être affiché comme routeur/firewall entre WAN et LAN, et les bridges Proxmox `vmbr0`/`vmbr1` peuvent apparaître même si un bridge n'a pas d'IPv4 côté hôte. Le schéma peut être visualisé dans VS Code avec une extension Mermaid ou sur <https://mermaid.live>.

## Limites de la détection Nmap

Nmap déduit beaucoup d'informations par signatures réseau. Ces résultats sont probabilistes : pare-feu local, filtrage, VLAN, droits insuffisants, hôtes silencieux, services masqués ou signatures ambiguës peuvent produire des manques ou des erreurs.

L'identification OS (`-O`) nécessite souvent des privilèges administrateur/root et peut échouer. Le script relance alors le scan services sans `-O`.

## Topologie logique et physique

La topologie générée est logique : elle indique quels hôtes répondent dans quels sous-réseaux depuis le poste de scan. Elle ne prouve pas le câblage réel, le port switch utilisé, le point d'accès Wi-Fi associé ou le chemin physique exact.

Pour une topologie physique fiable, il faut compléter Nmap avec SNMP, LLDP, CDP, tables MAC des switchs, table ARP des routeurs et baux DHCP.

## Dépannage

Nmap introuvable : vérifie `nmap --version` et redémarre le terminal après installation.

Aucun sous-réseau avec `--auto` : relance avec `--debug-auto`. Sous Windows, vérifie que PowerShell peut exécuter `Get-NetIPAddress -AddressFamily IPv4`. Tu peux aussi préciser `--subnet` manuellement, par exemple `192.168.20.0/24`, fournir `--known-topology known_topology.yml`, ou essayer `--discover-routed-subnets` pour valider des candidats `/24` issus des routes et traceroutes.

Scan OS en échec : relance avec `--skip-os`, ou démarre PowerShell en administrateur / utilise `sudo` sous Linux.

Scan trop lent : réduis les ports avec `--ports 22,80,443,445` ou utilise `--top-ports 50`.

Résultats incomplets : certains hôtes bloquent ICMP/ARP ou filtrent les ports. Essaie depuis un autre segment réseau autorisé.

## Développement

Créer un environnement virtuel :

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Sous Windows PowerShell :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Commandes locales utiles :

```powershell
python .\network_mapper.py --subnet 192.168.20.0/24
python .\network_mapper.py --auto
python .\network_mapper.py --subnet 192.168.20.0/24 --skip-os
python .\network_mapper.py --auto --detect-ip-conflicts
python -m pytest
ruff check .
ruff format --check .
bandit -r .
```

Commandes qualité complètes :

```bash
python -m compileall network_mapper.py tests
ruff check .
ruff format --check .
mypy .
python -m pytest --cov=network_mapper --cov-report=term-missing
bandit -r .
pip-audit
```

## CI/CD

Le projet fournit deux workflows GitHub Actions :

- `.github/workflows/ci.yml` : compile Python, Ruff, format check, mypy, pytest et coverage sur Python 3.10, 3.11 et 3.12.
- `.github/workflows/security.yml` : Bandit, pip-audit et Gitleaks sur `push`, `pull_request` et chaque semaine.

Dependabot est configuré pour les GitHub Actions et les dépendances pip.

## Sécurité et gestion des secrets

Ne stocke jamais de secrets, tokens, identifiants, mots de passe ou exports sensibles dans le dépôt. Les exemples utilisent uniquement des adresses privées documentaires. Les logs générés peuvent contenir des noms d'hôtes, IP, MAC et bannières de services : traite-les comme des données internes et ne les publie pas sans revue.
