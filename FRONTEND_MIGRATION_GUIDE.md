# Guide de Migration: localStorage → Cookies httpOnly

## Problème de sécurité identifié

**CRITIQUE** : L'utilisation de localStorage pour stocker les tokens JWT est une vulnérabilité majeure car :
- Les tokens sont accessibles via JavaScript (XSS)
- Pas de protection contre le vol de tokens
- Pas de contrôle sur l'expiration côté serveur

## Solution : Cookies httpOnly

### Avantages des cookies httpOnly :
- ✅ **Protection XSS** : Inaccessible via JavaScript
- ✅ **Sécurité renforcée** : Contrôlés par le navigateur
- ✅ **Expiration automatique** : Gérée côté serveur
- ✅ **Protection CSRF** : Avec SameSite
- ✅ **HTTPS obligatoire** : Avec Secure flag

## Changements côté Backend (Déjà implémentés)

### 1. Configuration JWT mise à jour
```python
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(seconds=3600),
    "REFRESH_TOKEN_LIFETIME": timedelta(seconds=604800),
    "AUTH_COOKIE": "access_token",
    "AUTH_COOKIE_REFRESH": "refresh_token",
    "AUTH_COOKIE_HTTP_ONLY": True,  # CRITICAL
    "AUTH_COOKIE_SECURE": True,     # HTTPS seulement
    "AUTH_COOKIE_SAMESITE": "Lax",  # Protection CSRF
}
```

### 2. Middleware personnalisé ajouté
- `JWTCookieMiddleware` gère automatiquement les cookies
- Supprime les tokens des réponses JSON
- Configure les options de sécurité

## Changements côté Frontend

### 1. Supprimer localStorage (CRITIQUE)

**AVANT (Vulnérable)** :
```javascript
// ❌ DANGEREUX - Supprimer ce code
localStorage.setItem('access_token', response.data.access);
localStorage.setItem('refresh_token', response.data.refresh);

const token = localStorage.getItem('access_token');
```

**APRÈS (Sécurisé)** :
```javascript
// ✅ SÉCURISÉ - Les cookies sont automatiquement gérés
// Plus besoin de gérer manuellement les tokens
```

### 2. Mise à jour des requêtes HTTP

**AVANT** :
```javascript
// ❌ DANGEREUX
const token = localStorage.getItem('access_token');
fetch('/api/protected/', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

**APRÈS** :
```javascript
// ✅ SÉCURISÉ - Cookies automatiquement inclus
fetch('/api/protected/', {
  credentials: 'include'  // Important pour les cookies
});
```

### 3. Configuration Axios

```javascript
// Configuration Axios pour les cookies
import axios from 'axios';

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL,
  withCredentials: true,  // CRITICAL: Inclut les cookies
  headers: {
    'Content-Type': 'application/json',
  }
});

// Plus besoin d'intercepteurs pour les tokens
// Les cookies sont automatiquement gérés par le navigateur
```

### 4. Gestion de l'authentification

```javascript
// Login - Les tokens sont automatiquement stockés en cookies
const login = async (credentials) => {
  const response = await fetch('/api/auth/login/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(credentials)
  });
  
  // Les tokens ne sont plus dans response.data
  // Ils sont automatiquement stockés en cookies httpOnly
  return response.json();
};

// Logout - Les cookies sont automatiquement supprimés
const logout = async () => {
  await fetch('/api/auth/logout/', {
    method: 'POST',
    credentials: 'include'
  });
  
  // Les cookies sont automatiquement supprimés par le serveur
};
```

### 5. Vérification de l'authentification

```javascript
// Vérifier si l'utilisateur est connecté
const checkAuth = async () => {
  try {
    const response = await fetch('/api/auth/verify/', {
      credentials: 'include'
    });
    return response.ok;
  } catch (error) {
    return false;
  }
};
```

## Checklist de Migration

### Backend ✅
- [x] Configuration JWT avec cookies httpOnly
- [x] Middleware personnalisé implémenté
- [x] Variables d'environnement configurées
- [x] HTTPS obligatoire en production
- [x] Protection CSRF réactivée

### Frontend (À faire)
- [ ] Supprimer tout code localStorage pour les tokens
- [ ] Ajouter `credentials: 'include'` à toutes les requêtes
- [ ] Mettre à jour la configuration Axios
- [ ] Tester l'authentification avec cookies
- [ ] Vérifier que les tokens ne sont plus accessibles via JavaScript

## Tests de Sécurité

### 1. Vérifier que les tokens ne sont plus accessibles via JavaScript :
```javascript
// Cette commande ne doit plus retourner les tokens
console.log(document.cookie); // Ne doit pas contenir access_token ou refresh_token
```

### 2. Vérifier les cookies dans les DevTools :
- Onglet Application → Cookies
- Les cookies `access_token` et `refresh_token` doivent avoir :
  - ✅ HttpOnly: true
  - ✅ Secure: true (en production)
  - ✅ SameSite: Lax

### 3. Test de protection XSS :
```javascript
// Ce script ne doit pas pouvoir accéder aux tokens
document.cookie // Ne doit pas contenir les tokens JWT
```

## Migration Progressive

1. **Phase 1** : Déployer les changements backend
2. **Phase 2** : Mettre à jour le frontend progressivement
3. **Phase 3** : Tester en environnement de staging
4. **Phase 4** : Déployer en production avec monitoring

## Support et Dépannage

### Problèmes courants :
- **401 Unauthorized** : Vérifier `credentials: 'include'`
- **Cookies non envoyés** : Vérifier CORS et domaines
- **Tokens dans JSON** : Vérifier que le middleware fonctionne

### Logs utiles :
```python
# Dans Django, surveiller les logs
logger.info("Access token cookie set successfully")
logger.error("Invalid access token")
```

Cette migration élimine la plus grande vulnérabilité de votre application et améliore considérablement la sécurité.
