1. Installation des dépendances
Installez Python sur votre système si ce n'est pas déjà fait. Ensuite, installez les bibliothèques nécessaires :

pip install pycryptodome
pip install pyinstaller

2. Script Python
Télecharger le script Python qui combine le chiffrement de César et AES-256 


3. Conversion en fichier exécutable (.exe)
Utilisez pyinstallerpour convertir le script Python en un fichier exécutable :


Copier le code

pyinstaller --onefile --windowed votre_script.py


Cette commande générera un fichier exécutable dans le répertoire dist. Utilisez --windowedpour ne pas afficher la console de commande.

4. Distribution
Distribuez le fichier .exegénéré sous le répertoire distà vos utilisateurs. Assurez-vous de tester l'exécutable sur Windows 11 pour garantir qu'il fonctionne correctement.

Avec ce processus, vous devriez avoir un logiciel fonctionnel qui chiffre et déchiffre le texte en utilisant à la fois le chiffrement de César et AES-256.





