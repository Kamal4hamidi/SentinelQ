# Système de Détection d'Intrusion avec Apprentissage par Renforcement

Un projet de cybersécurité implémenté en Java

## 📋 Vue d'ensemble

Ce projet implémente un système de détection d'intrusion (IDS) utilisant l'apprentissage par renforcement pour identifier et classer les comportements malveillants sur un réseau. Le système s'améliore progressivement grâce à un algorithme de Q-learning qui apprend à distinguer le trafic normal des activités suspectes.

## ✨ Fonctionnalités principales

- Surveillance de trafic réseau via sockets Java
- Simulation de trafic normal et d'attaques (DoS, scan de ports, etc.)
- Détection d'intrusion basée sur les signatures et le comportement
- Algorithme de Q-learning pour l'amélioration continue des détections
- Interface utilisateur simple (console et GUI basée sur Swing)
- Système d'alertes en temps réel
- Génération de rapports d'incidents

## 🔧 Prérequis

- Java Development Kit (JDK) 11 ou supérieur
- Maven 3.6 ou supérieur
- Espace disque minimum: 100 MB
- RAM minimum recommandée: 2 GB
- Droits administrateur pour la capture de paquets réseau (sur certains systèmes)

## 📥 Installation

```bash
# Cloner le repository
git clone https://github.com/kamal4hamidi/network-ids-rl.git

# Se déplacer dans le répertoire du projet
cd network-ids-rl

# Compiler le projet avec Maven
mvn clean package

# Exécuter l'application
java -jar target/network-ids-rl-1.0.jar

```

🏗️ Architecture du projet
Le projet est structuré en modules fonctionnels :
```bash
network-ids-rl/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   ├── com/
│   │   │   │   ├── idsproject/
│   │   │   │   │   ├── Main.java              # Point d'entrée principal
│   │   │   │   │   ├── ui/                    # Interface utilisateur
│   │   │   │   │   ├── network/               # Gestionnaires de trafic réseau
│   │   │   │   │   ├── detection/             # Logique de détection d'intrusion
│   │   │   │   │   └── rl/                    # Modules d'apprentissage par renforcement
│   ├── test/                                  # Tests unitaires et d'intégration
├── data/                                      # Données pour simulation et entraînement
└── doc/                                       # Documentation technique
```

🧠 Algorithme d'apprentissage par renforcement
Le système utilise un algorithme de Q-learning pour améliorer sa détection au fil du temps :

États : Représentations des caractéristiques du trafic réseau (nombre de paquets, distribution des ports, etc.)

Actions : Classification du trafic (normal, DoS, scan de port, etc.)

Récompenses : Attribution de valeurs positives pour les détections correctes et négatives pour les faux positifs/négatifs

Politique : Exploration/exploitation avec epsilon-greedy pour équilibrer l'apprentissage

La formule de mise à jour Q implémentée est :
```bash
Q(s,a) = Q(s,a) + α * (r + γ * max(Q(s',a')) - Q(s,a))
```
Où :

α (alpha) est le taux d'apprentissage

γ (gamma) est le facteur d'actualisation

r est la récompense immédiate

s est l'état actuel et s' l'état suivant

a est l'action actuelle et a' l'action suivante

🖥️ Utilisation
Interface console
```bash
# Mode de surveillance en temps réel
java -jar target/network-ids-rl-1.0.jar --mode=monitor

# Mode de simulation avec dataset préchargé
java -jar target/network-ids-rl-1.0.jar --mode=simulate --dataset=data/scenario1.csv

# Mode d'entraînement
java -jar target/network-ids-rl-1.0.jar --mode=train --iterations=1000

```
Interface graphique
Exécutez l'application sans arguments pour lancer l'interface graphique :
```bash
java -jar target/network-ids-rl-1.0.jar
```
La GUI permet de :

Visualiser le trafic réseau en temps réel

Configurer les paramètres de détection

Observer l'apprentissage du système

Générer des rapports d'incidents

📊 Tests et évaluation
Le système a été testé avec différents scénarios d'attaque :

Attaques par déni de service (DoS)

Scans de ports (TCP SYN, XMAS)

Tentatives d'exploitation de vulnérabilités courantes

Traffic légitime à haute fréquence (pour tester les faux positifs)

Les métriques suivantes ont été collectées :

Précision : 92%

Rappel : 89%

F1-Score : 90.5%

Taux de faux positifs : 7%

Pour exécuter les tests :
```bash
mvn test
```
🔍 À propos du projet
Ce projet a été développé dans le cadre d'un cours de cybersécurité avancée. L'objectif principal était d'explorer l'application des techniques d'apprentissage par renforcement dans le domaine de la détection d'intrusions réseau. Bien que ce système soit principalement éducatif, il démontre comment l'intelligence artificielle peut être appliquée pour améliorer les systèmes de sécurité classiques.

🤝 Contribution
Les contributions sont les bienvenues ! Pour contribuer :

Forkez le projet

Créez une branche pour votre fonctionnalité (git checkout -b feature/ma-fonctionnalite)

Committez vos changements (git commit -m 'Ajout de ma fonctionnalité')

Poussez vers la branche (git push origin feature/ma-fonctionnalite)

Ouvrez une Pull Request
