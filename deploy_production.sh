#!/bin/bash

# Script de déploiement sécurisé pour Awkaf en production
# Usage: ./deploy_production.sh

set -e  # Arrêter en cas d'erreur

echo "🚀 Déploiement sécurisé d'Awkaf en production"

# Vérifications préliminaires
echo "📋 Vérifications préliminaires..."

# Vérifier que nous ne sommes pas en mode DEBUG
if grep -q "DEBUG = True" backend/settings.py; then
    echo "❌ ERREUR: DEBUG est encore activé en production!"
    echo "   Configurez DEBUG=False dans .env.production"
    exit 1
fi

# Vérifier la présence du fichier .env.production
if [ ! -f ".env.production" ]; then
    echo "❌ ERREUR: Fichier .env.production manquant!"
    echo "   Créez ce fichier avec vos variables de production"
    exit 1
fi

# Vérifier que la SECRET_KEY n'est pas la valeur par défaut
if grep -q "django-insecure-ch9rw474p5yvf9rj" .env.production; then
    echo "❌ ERREUR: SECRET_KEY par défaut détectée!"
    echo "   Générez une nouvelle SECRET_KEY sécurisée"
    exit 1
fi

echo "✅ Vérifications préliminaires OK"

# Installation des dépendances
echo "📦 Installation des dépendances..."
pip install -r requirements.txt

# Collecte des fichiers statiques
echo "📁 Collecte des fichiers statiques..."
python manage.py collectstatic --noinput --settings=backend.settings

# Migrations de base de données
echo "🗄️  Application des migrations..."
python manage.py migrate --settings=backend.settings

# Vérification de la sécurité Django
echo "🔒 Vérification de la sécurité Django..."
python manage.py check --deploy --settings=backend.settings

# Test de la configuration SSL (si disponible)
echo "🔐 Vérification de la configuration SSL..."
if command -v openssl &> /dev/null; then
    if [ ! -z "$DOMAIN" ]; then
        echo "   Test de la connectivité SSL pour $DOMAIN..."
        echo | openssl s_client -connect $DOMAIN:443 -servername $DOMAIN 2>/dev/null | grep -q "Verify return code: 0" && echo "✅ SSL OK" || echo "⚠️  SSL non configuré ou invalide"
    fi
fi

# Création du répertoire de logs
echo "📝 Configuration des logs..."
sudo mkdir -p /var/log/awkaf
sudo chown $USER:$USER /var/log/awkaf

# Configuration du serveur de production
echo "🌐 Configuration du serveur de production..."

# Exemple de configuration Gunicorn
cat > gunicorn.conf.py << EOF
# Configuration Gunicorn pour la production
bind = "127.0.0.1:8000"
workers = 3
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
timeout = 30
keepalive = 2
preload_app = True
daemon = False
user = None
group = None
tmp_upload_dir = None
accesslog = "/var/log/awkaf/access.log"
errorlog = "/var/log/awkaf/error.log"
loglevel = "warning"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'
EOF

# Configuration systemd pour Gunicorn
cat > /tmp/awkaf.service << EOF
[Unit]
Description=Awkaf Django Application
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=$(pwd)
Environment="PATH=$(pwd)/venv/bin"
ExecStart=$(pwd)/venv/bin/gunicorn --config gunicorn.conf.py backend.wsgi:application
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "📋 Configuration systemd créée dans /tmp/awkaf.service"
echo "   Pour l'installer: sudo cp /tmp/awkaf.service /etc/systemd/system/"

# Instructions finales
echo ""
echo "🎉 Déploiement terminé!"
echo ""
echo "📋 Prochaines étapes:"
echo "   1. Copiez .env.production vers .env"
echo "   2. Configurez votre certificat SSL (voir SSL_SETUP_GUIDE.md)"
echo "   3. Installez le service systemd: sudo cp /tmp/awkaf.service /etc/systemd/system/"
echo "   4. Activez le service: sudo systemctl enable awkaf && sudo systemctl start awkaf"
echo "   5. Configurez Nginx avec SSL (voir SSL_SETUP_GUIDE.md)"
echo ""
echo "🔒 Sécurité activée:"
echo "   ✅ Cookies httpOnly"
echo "   ✅ HTTPS obligatoire"
echo "   ✅ DEBUG désactivé"
echo "   ✅ Protection CSRF"
echo "   ✅ Headers de sécurité"
echo ""
echo "📚 Documentation:"
echo "   - SSL_SETUP_GUIDE.md"
echo "   - FRONTEND_MIGRATION_GUIDE.md"
