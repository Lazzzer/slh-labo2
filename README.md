# SLH - Labo #2

### Auteur: Lazar Pavicevic

## Variables d'environnement

Il faut créer un fichier `.env` à la racine du projet en copiant le fichier `.env.example` et en y ajoutant les variables d'environnement manquantes.

Pour les variables liées au `mailer`, je suis parti du principe que nous allons utiliser le relais SMTP gratuit de Gmail avec, du coup, des identifiants d'un compte Gmail classique. Si vous avez le 2FA d'activé, il est possible de générer un [mot de passe d'application](https://support.google.com/accounts/answer/185833?hl=fr) pour que le `mailer` puisse effectuer les envois.

## Choix d'implémentation

La vérification de l'email se fait avec un lien envoyé par mail. Ce lien contient un JWT qui stocke l'adresse à valider et dispose d'une durée de vie de _10 minutes_. Je n'ai pas implémenté de système qui redemande l'envoi du mail si celui-ci n'a pas été ouvert dans les temps vu que cela sort un peu du scope du laboratoire. Cela reste néanmoins une limitation à prendre en compte pour cette implémentation.

Ensuite, pour ne pas toucher aux schémas déjà existants et aux migrations, j'ai décidé d'utiliser un mot de passe par défaut pour tous les utilisateurs inscrit avec `Oauth`. Ce champs n'étant absolument pas utilisé pour ces utilisateurs, cela ne devrait pas poser de problème même s'il s'agit d'un point à améliorer pour la suite.
