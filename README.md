# mytekup-proj-py
authentication_RSA_encryption
python project 
1- Enregistrement
1-a Email (devrait être valide (Regular Expression)
1-b Pwd (tapé d'une façon invisible A pwd qui est composé par 1 majuscule, 1 lettre minuscule, 1 chiffre, 1 car. Special et de taille 8)Ind. 
Email:Login vont être enregistrés ds un fichier Enregistrement.txt
2- Authentification
2-a : Email
2-b : Pwd 
Si les credentials existent ds l'enregistrement.txt un menu s'affichera ,sinon il est amené à s'enregistrer Ind. 
Le menu, une fois authentifié,est comme suit : 
A- Donnez un mot à haché (en mode invisible)
a- Haché le mot par sha256 
b- Haché le mot en générant un salt (bcrypt)
c- Attaquer par dictionnaire le mot inséré. 
d- Revenir au menu principal 
