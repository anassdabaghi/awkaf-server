# Guide de Configuration SSL avec Let's Encrypt

## Installation de Certbot

### Sur Ubuntu/Debian :
```bash
sudo apt update
sudo apt install certbot python3-certbot-nginx
```

### Sur CentOS/RHEL :
```bash
sudo yum install certbot python3-certbot-nginx
```

### Sur Windows (avec WSL ou Docker) :
```bash
# Option 1: WSL
sudo apt install certbot

# Option 2: Docker
docker run -it --rm --name certbot \
  -v "/etc/letsencrypt:/etc/letsencrypt" \
  -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
  certbot/certbot certonly --manual
```

## Génération du Certificat SSL

### Méthode 1: Nginx (Recommandée)
```bash
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

### Méthode 2: Mode Standalone (si pas de serveur web)
```bash
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com
```

### Méthode 3: Mode Manual (pour serveurs distants)
```bash
sudo certbot certonly --manual -d yourdomain.com -d www.yourdomain.com
```

## Configuration Nginx pour HTTPS

Créer `/etc/nginx/sites-available/awkaf` :
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # Certificats SSL
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # Configuration SSL sécurisée
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Protection XSS
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /var/www/awkaf/static/;
    }

    location /media/ {
        alias /var/www/awkaf/media/;
    }
}
```

## Activation du site
```bash
sudo ln -s /etc/nginx/sites-available/awkaf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## Renouvellement automatique

### Test du renouvellement :
```bash
sudo certbot renew --dry-run
```

### Configuration cron pour renouvellement automatique :
```bash
sudo crontab -e
# Ajouter cette ligne :
0 12 * * * /usr/bin/certbot renew --quiet
```

## Variables d'environnement pour la production

Créer `.env.production` avec :
```env
DEBUG=False
SECRET_KEY=your-super-secret-production-key
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
CSRF_COOKIE_SECURE=True
SESSION_COOKIE_SECURE=True
SECURE_SSL_REDIRECT=True
CORS_ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

## Vérification de la sécurité

Utiliser ces outils pour vérifier votre configuration SSL :
- https://www.ssllabs.com/ssltest/
- https://securityheaders.com/
- https://observatory.mozilla.org/

## Notes importantes

1. **Backup** : Toujours sauvegarder vos certificats
2. **Renouvellement** : Les certificats Let's Encrypt expirent après 90 jours
3. **Monitoring** : Configurer des alertes pour les expirations
4. **HTTP vers HTTPS** : Rediriger automatiquement tout le trafic HTTP vers HTTPS
