Étapes d’installation du projet Awkaf
1️1 Installer les outils nécessaires

Installe XAMPP Control Panel

Télécharge et installe MariaDB

2️⃣ Mettre à jour MariaDB

Suivez cette vidéo pour la mise à jour :
🔗 https://youtu.be/RmrU_t5vpe8?si=99XfykbwtekLUXZi

3️⃣ Lancer les services

Ouvre XAMPP Control Panel

Lance les services :

✅ Apache

✅ MySQL

4️⃣ Cloner le projet
git clone https://github.com/6laza/Awkaf.git
cd Awkaf
git checkout NoOtp

5️⃣ Configurer le backend (Django)
cd backend
python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
python manage.py makemigrations
python manage.py migrate
python manage.py runserver


⚠️ Vérifie que ta base de données MariaDB est bien connectée avant de lancer runserver.

6️⃣ Configurer le frontend (React)

Dans un nouveau terminal :

cd frontend
npm i
npm run dev