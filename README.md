# LIGAS BBALL — Guía de configuración

## Estructura del repositorio

```
ligas-bball/
├── index_bball.html          ← frontend principal
├── netlify.toml              ← config Netlify
├── netlify/
│   └── functions/
│       └── admin.js          ← admin_bball.js va aquí renombrado
└── README.md
```

---

## 1. SUPABASE

**Proyecto:** `bhnmdkfvfpvvddqalaql.supabase.co`

### Tablas (ejecutar en SQL Editor)
1. Ir a Supabase → SQL Editor → New query
2. Pegar el contenido de `ligas_bball_schema.sql`
3. Clic en **Run**

### Storage (ejecutar por separado)
```sql
insert into storage.buckets (id, name, public)
values ('ligas-bball', 'ligas-bball', true)
on conflict do nothing;

create policy "publico_lee_storage" on storage.objects
  for select using (bucket_id = 'ligas-bball');

create policy "service_sube_storage" on storage.objects
  for insert with check (bucket_id = 'ligas-bball');
```

---

## 2. GITHUB

```bash
# En tu máquina local:
git init ligas-bball
cd ligas-bball

# Crear carpeta de functions
mkdir -p netlify/functions

# Copiar archivos
cp ruta/index_bball.html .
cp ruta/admin_bball.js netlify/functions/admin.js
cp ruta/netlify.toml .

# Commit inicial
git add .
git commit -m "feat: LIGAS BBALL v1.0 inicial"

# Conectar con GitHub (crear repo en github.com primero)
git remote add origin https://github.com/TU_USUARIO/ligas-bball.git
git push -u origin main
```

---

## 3. NETLIFY

1. Ir a [netlify.com](https://netlify.com) → **Add new site → Import from Git**
2. Elegir el repo `ligas-bball`
3. Build settings:
   - **Publish directory:** `.`
   - **Functions directory:** `netlify/functions`
4. Clic en **Deploy site**

### Variables de entorno (Site settings → Environment variables)

| Variable | Valor |
|---|---|
| `SUPABASE_URL` | `https://bhnmdkfvfpvvddqalaql.supabase.co` |
| `SUPABASE_SERVICE_KEY` | `eyJ...service_role...` (la segunda key) |
| `SUPER_ADMIN_PASSWORD` | Elige una contraseña segura |
| `TURNSTILE_SECRET_KEY` | Desde Cloudflare Turnstile (cuando lo configures) |

---

## 4. CLOUDFLARE TURNSTILE (opcional, recomendado)

1. Ir a [dash.cloudflare.com](https://dash.cloudflare.com) → Turnstile
2. **Add site** → nombre: `LIGAS BBALL`
3. Dominio: `ligasbball.netlify.app` (o tu dominio)
4. Copiar **Site Key** → pegar en `index_bball.html` donde dice `TURNSTILE_SITE_KEY_AQUI`
5. Copiar **Secret Key** → pegar en Netlify como `TURNSTILE_SECRET_KEY`

---

## 5. PRIMER ACCESO

- URL: `https://ligasbball.netlify.app`
- Abrir el panel admin con el ícono de configuración
- Contraseña: la que pusiste en `SUPER_ADMIN_PASSWORD`
- Desde ahí crear Sub-Admins por ciudad y Delegados por equipo

---

## Notas importantes

- La **service role key** de Supabase NUNCA va en el frontend (solo en variables de entorno Netlify)
- El modo demo (datos de ejemplo) se activa automáticamente si Supabase no responde
- Para actualizar el sitio: `git push origin main` — Netlify deploya automáticamente
