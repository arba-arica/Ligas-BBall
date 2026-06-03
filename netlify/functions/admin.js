/**
 * netlify/functions/admin.js — ACTIVA PLAY v2.1 (secure)
 *
 * Variables de entorno Netlify:
 *   SUPABASE_URL         = https://bhnmdkfvfpvvddqalazl.supabase.co
 *   SUPABASE_SERVICE_KEY = eyJ...service_role...
 *   ADMIN_EMAIL          = n.moraganavarro@gmail.com
 *   ADMIN_PASSWORD       = BballAdmin2026*
 *   ALLOWED_ORIGIN       = https://activaplay.cl  (o * para dev)
 *
 * CAMBIOS v2.1:
 *   - Token de admin es un hash seguro (no la contraseña)
 *   - Token con expiración de 8 horas
 *   - Ownership check en TODAS las operaciones de organizador
 *   - Rate limiting básico en checkLogin (tabla login_attempts)
 *   - CORS restringido al dominio de producción
 *   - Errores internos no expuestos al cliente
 *   - clave_acceso se borra de solicitudes al regenerar
 *   - Validación: equipo_local !== equipo_visita en backend
 *   - RLS policies SQL al final del archivo (comentario)
 */

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const db = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const ADMIN_EMAIL = process.env.ADMIN_EMAIL    || 'n.moraganavarro@gmail.com';
const ADMIN_PASS  = process.env.ADMIN_PASSWORD || 'BballAdmin2026*';

// ── CORS ── restringir al dominio real en producción
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const CORS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const ok   = b => ({ statusCode: 200, headers: CORS, body: JSON.stringify(b) });

// Errores internos NO se exponen — solo mensaje genérico al cliente
function fail(e, publicMsg) {
  const internal = e?.message || e?.details || String(e);
  if (internal) console.error('[ACTIVA PLAY]', internal);
  return { success: false, message: publicMsg || 'Error al procesar la solicitud' };
}

// ── HASH ──────────────────────────────────────────────────────────────────────
function hashPass(pass) {
  return crypto.createHash('sha256').update(pass + 'activaplay2026').digest('hex');
}

// Token de admin: hash del email+password+timestamp_hora → no es la contraseña
function makeAdminToken() {
  const hourSlot = Math.floor(Date.now() / (8 * 60 * 60 * 1000)); // cambia cada 8h
  return crypto.createHash('sha256')
    .update(ADMIN_EMAIL + ADMIN_PASS + 'admin_salt_2026' + hourSlot)
    .digest('hex');
}

// Token de org: org_id:passHash:timestamp_8h
function makeOrgToken(orgId, passHash) {
  const hourSlot = Math.floor(Date.now() / (8 * 60 * 60 * 1000));
  const sig = crypto.createHash('sha256')
    .update(orgId + passHash + 'org_salt_2026' + hourSlot)
    .digest('hex').substring(0, 16);
  return orgId + ':' + passHash + ':' + sig;
}

function validateOrgToken(token, orgId, passHash) {
  // Validar hora actual y hora anterior (ventana de 16h para no romper sesión al rotar)
  const hourSlot = Math.floor(Date.now() / (8 * 60 * 60 * 1000));
  for (const slot of [hourSlot, hourSlot - 1]) {
    const sig = crypto.createHash('sha256')
      .update(orgId + passHash + 'org_salt_2026' + slot)
      .digest('hex').substring(0, 16);
    const expected = orgId + ':' + passHash + ':' + sig;
    if (token === expected) return true;
  }
  return false;
}

function generateOrgId(n) {
  return 'AP-' + String(n).padStart(4, '0');
}

function generatePassword() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let pass = '';
  for (let i = 0; i < 8; i++) pass += chars[Math.floor(Math.random() * chars.length)];
  return pass;
}

// ── RATE LIMITING ─────────────────────────────────────────────────────────────
// Requiere tabla: login_attempts(ip TEXT, attempts INT, window_start TIMESTAMPTZ)
// Crear con: CREATE TABLE IF NOT EXISTS login_attempts (
//   ip TEXT PRIMARY KEY, attempts INT DEFAULT 0, window_start TIMESTAMPTZ DEFAULT NOW()
// );
const MAX_LOGIN_ATTEMPTS = 10;
const WINDOW_MINUTES = 15;

async function checkRateLimit(ip) {
  try {
    const { data } = await db.from('login_attempts')
      .select('attempts, window_start')
      .eq('ip', ip)
      .maybeSingle();

    if (!data) {
      await db.from('login_attempts').upsert({ ip, attempts: 1, window_start: new Date().toISOString() });
      return true; // OK
    }

    const windowStart = new Date(data.window_start);
    const minutesPassed = (Date.now() - windowStart.getTime()) / 60000;

    if (minutesPassed > WINDOW_MINUTES) {
      // Reset ventana
      await db.from('login_attempts').update({ attempts: 1, window_start: new Date().toISOString() }).eq('ip', ip);
      return true;
    }

    if (data.attempts >= MAX_LOGIN_ATTEMPTS) return false; // BLOQUEADO

    await db.from('login_attempts').update({ attempts: data.attempts + 1 }).eq('ip', ip);
    return true;
  } catch (e) {
    // Si falla la tabla de rate limiting, no bloquear (fail open)
    console.error('[rate-limit]', e.message);
    return true;
  }
}

async function resetRateLimit(ip) {
  try {
    await db.from('login_attempts').delete().eq('ip', ip);
  } catch (e) {}
}

// ── SESIÓN ───────────────────────────────────────────────────────────────────
async function getSession(token) {
  if (!token) return null;

  // Admin: verificar contra token rotativo de 8h
  const adminToken = makeAdminToken();
  if (token === adminToken) {
    return { rol: 'admin', org_id: null, nombre: 'Administrador', email: ADMIN_EMAIL };
  }

  // Organizador: token = "org_id:password_hash:signature"
  if (token.startsWith('AP-')) {
    const parts = token.split(':');
    if (parts.length < 3) return null;
    const orgId = parts[0];
    const passHash = parts[1];

    // Validar firma con expiración
    if (!validateOrgToken(token, orgId, passHash)) return null;

    // Verificar que el org existe y está activo
    const { data } = await db.from('organizadores')
      .select('org_id, nombre, email, ciudad, activo, password_hash')
      .eq('org_id', orgId)
      .eq('activo', true)
      .maybeSingle();

    if (!data || data.password_hash !== passHash) return null;

    return { rol: 'organizador', org_id: data.org_id, nombre: data.nombre, email: data.email, ciudad: data.ciudad };
  }

  return null;
}

function requireAdmin(session) {
  if (!session || session.rol !== 'admin') throw new Error('Acceso solo para administradores');
}

function requireOrg(session) {
  if (!session || (session.rol !== 'admin' && session.rol !== 'organizador')) {
    throw new Error('Acceso no autorizado');
  }
}

// ── OWNERSHIP CHECK ───────────────────────────────────────────────────────────
// Verifica que el recurso (categoría, equipo, partido, etc.) pertenece al org del token
async function verifyTorneoOwnership(torneoId, orgId) {
  if (!torneoId || !orgId) throw new Error('Parámetros insuficientes');
  const { data } = await db.from('torneos')
    .select('org_id')
    .eq('id', torneoId)
    .neq('estado', 'eliminado')
    .maybeSingle();
  if (!data) throw new Error('Torneo no encontrado');
  if (data.org_id !== orgId) throw new Error('No tienes permiso sobre este torneo');
  return true;
}

async function verifyCategoriaTorneo(categoriaId, orgId) {
  const { data } = await db.from('categorias')
    .select('torneo_id')
    .eq('id', categoriaId)
    .maybeSingle();
  if (!data) throw new Error('Categoría no encontrada');
  await verifyTorneoOwnership(data.torneo_id, orgId);
}

async function verifyPartidoOwnership(partidoId, orgId) {
  const { data } = await db.from('partidos')
    .select('categoria_id')
    .eq('id', partidoId)
    .maybeSingle();
  if (!data) throw new Error('Partido no encontrado');
  await verifyCategoriaTorneo(data.categoria_id, orgId);
}

async function verifyNoticiaOwnership(noticiaId, orgId) {
  const { data } = await db.from('noticias')
    .select('torneo_id')
    .eq('id', noticiaId)
    .maybeSingle();
  if (!data) throw new Error('Noticia no encontrada');
  await verifyTorneoOwnership(data.torneo_id, orgId);
}

async function verifySancionOwnership(sancionId, orgId) {
  const { data } = await db.from('sanciones')
    .select('categoria_id')
    .eq('id', sancionId)
    .maybeSingle();
  if (!data) throw new Error('Sanción no encontrada');
  await verifyCategoriaTorneo(data.categoria_id, orgId);
}

// ── HANDLER ──────────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return ok('');

  const ip = event.headers['x-forwarded-for']?.split(',')[0].trim()
          || event.headers['client-ip']
          || 'unknown';

  try {
    const body = JSON.parse(event.body || '{}');
    const { action, token, ...data } = body;

    const PUBLIC = ['checkLogin', 'crearSolicitud', 'getTorneos', 'getCategoriasPublic',
                    'getEquiposPublic', 'getPartidosPublic', 'getNoticiasPublic',
                    'getStandings', 'getSancionesPublic'];

    let session = null;
    if (!PUBLIC.includes(action)) {
      session = await getSession(token);
      if (!session) return ok({ success: false, message: 'Sesión inválida o expirada. Inicia sesión nuevamente.' });
    }

    let result;

    switch (action) {

      // ══ AUTH ════════════════════════════════════════════════════════════════

      case 'checkLogin': {
        // Rate limiting
        const allowed = await checkRateLimit(ip);
        if (!allowed) {
          result = { success: false, message: 'Demasiados intentos fallidos. Espera 15 minutos.' };
          break;
        }

        // Admin
        if (data.email?.toLowerCase().trim() === ADMIN_EMAIL.toLowerCase() && data.password === ADMIN_PASS) {
          await resetRateLimit(ip);
          result = {
            success: true,
            rol: 'admin',
            token: makeAdminToken(), // hash seguro, no la contraseña
            nombre: 'Administrador',
            email: ADMIN_EMAIL,
          };
          break;
        }

        // Organizador
        const passHash = hashPass(data.password);
        const { data: org, error } = await db.from('organizadores')
          .select('org_id, nombre, email, ciudad, activo, password_hash')
          .eq('email', data.email?.toLowerCase().trim())
          .maybeSingle();

        if (error || !org || org.password_hash !== passHash) {
          // Mismo mensaje para email incorrecto o password incorrecto (evitar enumeración)
          result = { success: false, message: 'Email o contraseña incorrectos' };
          break;
        }
        if (!org.activo) {
          result = { success: false, message: 'Tu cuenta está suspendida. Contacta al administrador.' };
          break;
        }

        await resetRateLimit(ip);
        result = {
          success: true,
          rol: 'organizador',
          token: makeOrgToken(org.org_id, passHash),
          org_id: org.org_id,
          nombre: org.nombre,
          email: org.email,
          ciudad: org.ciudad,
        };
        break;
      }

      // ══ SOLICITUDES ══════════════════════════════════════════════════════════

      case 'crearSolicitud': {
        if (!data.nombre?.trim() || !data.email?.trim() || !data.ciudad?.trim()) {
          result = { success: false, message: 'Nombre, email y ciudad son obligatorios' };
          break;
        }
        const emailClean = data.email.toLowerCase().trim();

        // Verificar si ya existe una solicitud con ese correo
        const { data: existe } = await db.from('solicitudes')
          .select('id, estado')
          .eq('email', emailClean)
          .maybeSingle();

        if (existe) {
          if (existe.estado === 'pendiente') {
            result = { success: false, message: 'Ya tienes una solicitud pendiente con ese correo. Te contactaremos pronto.' };
            break;
          }
          if (existe.estado === 'aprobada') {
            result = { success: false, message: 'Este correo ya tiene una cuenta activa. Ingresa desde el panel de organizador.' };
            break;
          }
          // Si fue rechazada, permitir reenviar — actualizar la solicitud existente
          if (existe.estado === 'rechazada') {
            await db.from('solicitudes').update({
              nombre:          data.nombre.trim(),
              telefono:        data.telefono || null,
              ciudad:          data.ciudad.trim(),
              deporte:         data.deporte || 'Básquetbol',
              descripcion:     data.descripcion || null,
              cant_categorias: data.cant_categorias || 1,
              estado:          'pendiente',
              notas_admin:     null,
            }).eq('id', existe.id);
            result = { success: true, message: '¡Solicitud reenviada! Te contactaremos pronto.' };
            break;
          }
        }

        // También verificar si ya existe como organizador
        const { data: orgExiste } = await db.from('organizadores')
          .select('org_id, activo')
          .eq('email', emailClean)
          .maybeSingle();

        if (orgExiste) {
          result = { success: false, message: orgExiste.activo
            ? 'Este correo ya tiene una cuenta activa. Ingresa desde el panel de organizador.'
            : 'Este correo tiene una cuenta suspendida. Contacta al administrador.' };
          break;
        }

        const { error } = await db.from('solicitudes').insert({
          nombre:          data.nombre.trim(),
          email:           emailClean,
          telefono:        data.telefono || null,
          ciudad:          data.ciudad.trim(),
          deporte:         data.deporte || 'Básquetbol',
          descripcion:     data.descripcion || null,
          cant_categorias: data.cant_categorias || 1,
          estado:          'pendiente',
        });
        result = error ? fail(error, 'Error al enviar solicitud') : { success: true, message: '¡Solicitud enviada!' };
        break;
      }

      case 'listarSolicitudes': {
        requireAdmin(session);
        const { data: sols, error } = await db.from('solicitudes')
          .select('*')
          .order('created_at', { ascending: false });
        result = error ? fail(error, 'Error al cargar solicitudes') : { success: true, data: sols || [] };
        break;
      }

      case 'aprobarSolicitud': {
        requireAdmin(session);
        const { data: sol } = await db.from('solicitudes').select('*').eq('id', data.id).maybeSingle();
        if (!sol) { result = { success: false, message: 'Solicitud no encontrada' }; break; }

        const { count } = await db.from('organizadores').select('id', { count: 'exact', head: true });
        const orgId = generateOrgId((count || 0) + 1);
        const claveAcceso = generatePassword();
        const passHash = hashPass(claveAcceso);

        const { error: errOrg } = await db.from('organizadores').insert({
          org_id:             orgId,
          nombre:             sol.nombre,
          email:              sol.email,
          password_hash:      passHash,
          ciudad:             sol.ciudad,
          activo:             true,
          suscripcion_inicio: new Date().toISOString(),
        });
        if (errOrg) { result = fail(errOrg, 'Error al crear organizador'); break; }

        // Guardar clave en solicitud solo para que el admin la vea UNA VEZ
        await db.from('solicitudes').update({
          estado:       'aprobada',
          org_id:       orgId,
          clave_acceso: claveAcceso, // Se limpiará en la siguiente versión con cron job
          notas_admin:  data.notas || null,
        }).eq('id', data.id);

        result = { success: true, org_id: orgId, clave_acceso: claveAcceso, email: sol.email };
        break;
      }

      case 'rechazarSolicitud': {
        requireAdmin(session);
        const { error } = await db.from('solicitudes').update({
          estado: 'rechazada',
          notas_admin: data.notas || null,
        }).eq('id', data.id);
        result = error ? fail(error, 'Error al rechazar solicitud') : { success: true, message: 'Solicitud rechazada' };
        break;
      }

      // ══ ORGANIZADORES ════════════════════════════════════════════════════════

      case 'listarOrganizadores': {
        requireAdmin(session);
        const { data: orgs, error } = await db.from('organizadores')
          .select('id, org_id, nombre, email, ciudad, activo, suscripcion_inicio, suscripcion_fin')
          .order('created_at', { ascending: false });
        const result_data = await Promise.all((orgs || []).map(async o => {
          const { count } = await db.from('torneos')
            .select('id', { count: 'exact', head: true })
            .eq('org_id', o.org_id).neq('estado', 'eliminado');
          return { ...o, torneos_count: count || 0 };
        }));
        result = error ? fail(error, 'Error al cargar organizadores') : { success: true, data: result_data };
        break;
      }

      case 'toggleOrganizador': {
        requireAdmin(session);
        const { error } = await db.from('organizadores')
          .update({ activo: data.activo })
          .eq('org_id', data.org_id);
        result = error ? fail(error, 'Error al actualizar organizador')
          : { success: true, message: data.activo ? 'Organizador activado' : 'Organizador suspendido' };
        break;
      }

      case 'resetPassword': {
        requireAdmin(session);
        const nuevaClave = generatePassword();
        const { error } = await db.from('organizadores')
          .update({ password_hash: hashPass(nuevaClave) })
          .eq('org_id', data.org_id);
        if (error) { result = fail(error, 'Error al resetear contraseña'); break; }
        // Limpiar clave anterior de solicitudes (no guardar la nueva en texto plano)
        await db.from('solicitudes').update({ clave_acceso: null }).eq('org_id', data.org_id);
        result = { success: true, clave_acceso: nuevaClave, message: 'Clave regenerada' };
        break;
      }

      // ══ TORNEOS ══════════════════════════════════════════════════════════════

      case 'getTorneos': {
        const { data: torneos, error } = await db.from('torneos')
          .select('id, nombre, ciudad, deporte, temporada, descripcion, estado, visible, org_id, created_at')
          .eq('visible', true).neq('estado', 'eliminado')
          .order('created_at', { ascending: false });
        result = error ? fail(error, 'Error al cargar torneos') : { success: true, data: torneos || [] };
        break;
      }

      case 'getTorneosAdmin': {
        requireAdmin(session);
        const { data: torneos, error } = await db.from('torneos')
          .select('*, organizadores(nombre, email)')
          .neq('estado', 'eliminado')
          .order('created_at', { ascending: false });
        result = error ? fail(error, 'Error al cargar torneos') : { success: true, data: torneos || [] };
        break;
      }

      case 'getMiTorneo': {
        requireOrg(session);
        const { data: torneo, error } = await db.from('torneos')
          .select('*').eq('org_id', session.org_id).neq('estado', 'eliminado')
          .order('created_at', { ascending: false }).limit(1).maybeSingle();
        result = error ? fail(error, 'Error al cargar torneo') : { success: true, data: torneo };
        break;
      }

      case 'getMisTorneos': {
        requireOrg(session);
        const { data: torneos, error } = await db.from('torneos')
          .select('*')
          .eq('org_id', session.org_id)
          .order('created_at', { ascending: false });
        result = error ? fail(error, 'Error al cargar torneos') : { success: true, data: torneos || [] };
        break;
      }

      case 'crearTorneo': {
        requireOrg(session);
        const { data: torneo, error } = await db.from('torneos').insert({
          org_id:      session.org_id,
          nombre:      data.nombre?.trim(),
          ciudad:      data.ciudad?.trim() || session.ciudad,
          deporte:     data.deporte || 'Básquetbol',
          temporada:   data.temporada || null,
          descripcion: data.descripcion || null,
          fecha_inicio: data.fecha_inicio || null,
          fecha_fin:    data.fecha_fin || null,
          estado:      'borrador',
          visible:     false,
        }).select().single();
        result = error ? fail(error, 'Error al crear torneo') : { success: true, data: torneo, message: 'Torneo creado' };
        break;
      }

      case 'actualizarTorneo': {
        requireOrg(session);
        // Ownership: admin puede editar cualquier torneo, org solo el suyo
        if (session.rol !== 'admin') await verifyTorneoOwnership(data.id, session.org_id);
        const { error } = await db.from('torneos').update({
          nombre:         data.nombre?.trim(),
          temporada:      data.temporada,
          descripcion:    data.descripcion,
          reglamento_url: data.reglamento_url,
          fecha_inicio:   data.fecha_inicio || null,
          fecha_fin:      data.fecha_fin || null,
        }).eq('id', data.id);
        result = error ? fail(error, 'Error al actualizar torneo') : { success: true, message: 'Torneo actualizado' };
        break;
      }

      case 'publicarTorneo': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyTorneoOwnership(data.id, session.org_id);
        const { error } = await db.from('torneos').update({
          visible: data.visible,
          estado:  data.visible ? 'activo' : 'borrador',
        }).eq('id', data.id);
        result = error ? fail(error, 'Error al publicar torneo')
          : { success: true, message: data.visible ? 'Torneo publicado' : 'Torneo ocultado' };
        break;
      }

      case 'eliminarTorneo': {
        requireAdmin(session);
        const { error } = await db.from('torneos').update({ estado: 'eliminado', visible: false }).eq('id', data.id);
        result = error ? fail(error, 'Error al eliminar torneo') : { success: true, message: 'Torneo eliminado' };
        break;
      }

      // ══ CATEGORIAS ═══════════════════════════════════════════════════════════

      case 'getCategoriasPublic': {
        const { data: cats, error } = await db.from('categorias')
          .select('*').eq('torneo_id', data.torneo_id).eq('activo', true).order('orden');
        result = error ? fail(error, 'Error al cargar categorías') : { success: true, data: cats || [] };
        break;
      }

      case 'getMisCategorias': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyTorneoOwnership(data.torneo_id, session.org_id);
        const { data: cats, error } = await db.from('categorias')
          .select('*').eq('torneo_id', data.torneo_id).order('orden');
        result = error ? fail(error, 'Error al cargar categorías') : { success: true, data: cats || [] };
        break;
      }

      case 'crearCategoria': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyTorneoOwnership(data.torneo_id, session.org_id);
        const { data: cat, error } = await db.from('categorias').insert({
          torneo_id:    data.torneo_id,
          nombre:       data.nombre?.trim(),
          pts_victoria: data.pts_victoria || 2,
          pts_empate:   data.pts_empate   || 0,
          pts_derrota:  data.pts_derrota  || 1,
          orden:        data.orden        || 0,
        }).select().single();
        result = error ? fail(error, 'Error al crear categoría') : { success: true, data: cat, message: 'Categoría creada' };
        break;
      }

      case 'actualizarCategoria': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyCategoriaTorneo(data.id, session.org_id);
        const { error } = await db.from('categorias').update({
          nombre:       data.nombre?.trim(),
          pts_victoria: data.pts_victoria,
          pts_empate:   data.pts_empate,
          pts_derrota:  data.pts_derrota,
        }).eq('id', data.id);
        result = error ? fail(error, 'Error al actualizar categoría') : { success: true, message: 'Categoría actualizada' };
        break;
      }

      case 'eliminarCategoria': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyCategoriaTorneo(data.id, session.org_id);
        const { error } = await db.from('categorias').update({ activo: false }).eq('id', data.id);
        result = error ? fail(error, 'Error al eliminar categoría') : { success: true, message: 'Categoría eliminada' };
        break;
      }

      // ══ EQUIPOS ══════════════════════════════════════════════════════════════

      case 'getEquiposPublic':
      case 'getEquiposCategoria': {
        const { data: equipos, error } = await db.from('equipos')
          .select('*').eq('categoria_id', data.categoria_id).eq('activo', true).order('nombre');
        result = error ? fail(error, 'Error al cargar equipos') : { success: true, data: equipos || [] };
        break;
      }

      case 'crearEquipo': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyCategoriaTorneo(data.categoria_id, session.org_id);
        const { data: eq, error } = await db.from('equipos').insert({
          categoria_id: data.categoria_id,
          nombre:       data.nombre?.trim(),
          color_local:  data.color_local  || '#1d4ed8',
          color_visita: data.color_visita || '#ffffff',
        }).select().single();
        result = error ? fail(error, 'Error al crear equipo') : { success: true, data: eq, message: 'Equipo creado' };
        break;
      }

      case 'actualizarEquipo': {
        requireOrg(session);
        if (session.rol !== 'admin') {
          // Verificar que el equipo pertenece a una categoría del org
          const { data: eq } = await db.from('equipos').select('categoria_id').eq('id', data.id).maybeSingle();
          if (!eq) throw new Error('Equipo no encontrado');
          await verifyCategoriaTorneo(eq.categoria_id, session.org_id);
        }
        const updEq = { nombre: data.nombre?.trim() };
        if (data.color_local)  updEq.color_local  = data.color_local;
        if (data.color_visita) updEq.color_visita = data.color_visita;
        const { error } = await db.from('equipos').update(updEq).eq('id', data.id);
        result = error ? fail(error, 'Error al actualizar equipo') : { success: true, message: 'Equipo actualizado' };
        break;
      }

      case 'eliminarEquipo': {
        requireOrg(session);
        if (session.rol !== 'admin') {
          const { data: eq } = await db.from('equipos').select('categoria_id').eq('id', data.id).maybeSingle();
          if (!eq) throw new Error('Equipo no encontrado');
          await verifyCategoriaTorneo(eq.categoria_id, session.org_id);
        }
        const { error } = await db.from('equipos').update({ activo: false }).eq('id', data.id);
        result = error ? fail(error, 'Error al eliminar equipo') : { success: true, message: 'Equipo eliminado' };
        break;
      }

      // ══ PARTIDOS ═════════════════════════════════════════════════════════════

      case 'getPartidosPublic':
      case 'getPartidosCategoria': {
        let q = db.from('partidos')
          .select('*, local:equipo_local(nombre,color_local), visita:equipo_visita(nombre,color_local)')
          .eq('categoria_id', data.categoria_id);
        if (data.estado) q = q.eq('estado', data.estado);
        q = q.order('nro_fecha').order('fecha').order('hora');
        const { data: pts, error } = await q;
        result = error ? fail(error, 'Error al cargar partidos') : { success: true, data: pts || [] };
        break;
      }

      case 'crearPartido': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyCategoriaTorneo(data.categoria_id, session.org_id);
        // Validar: local ≠ visita
        if (data.equipo_local === data.equipo_visita) {
          result = { success: false, message: 'El equipo local y visita no pueden ser el mismo' };
          break;
        }
        const { data: partido, error } = await db.from('partidos').insert({
          categoria_id:    data.categoria_id,
          fecha:           data.fecha || null,
          hora:            data.hora  || null,
          cancha:          data.cancha || null,
          fase:            data.fase  || 'Fase Regular',
          nro_fecha:       data.nro_fecha || 1,
          equipo_local:    data.equipo_local,
          equipo_visita:   data.equipo_visita,
          url_transmision: data.url_transmision || null,
          estado:          'programado',
        }).select().single();
        result = error ? fail(error, 'Error al crear partido') : { success: true, data: partido, message: 'Partido programado' };
        break;
      }

      case 'actualizarPartido': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyPartidoOwnership(data.id, session.org_id);
        if (data.equipo_local === data.equipo_visita) {
          result = { success: false, message: 'El equipo local y visita no pueden ser el mismo' };
          break;
        }
        const { error } = await db.from('partidos').update({
          fecha:           data.fecha || null,
          hora:            data.hora  || null,
          cancha:          data.cancha || null,
          fase:            data.fase,
          nro_fecha:       data.nro_fecha,
          equipo_local:    data.equipo_local,
          equipo_visita:   data.equipo_visita,
          url_transmision: data.url_transmision || null,
        }).eq('id', data.id);
        result = error ? fail(error, 'Error al actualizar partido') : { success: true, message: 'Partido actualizado' };
        break;
      }

      case 'actualizarResultado': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyPartidoOwnership(data.id, session.org_id);
        const update = {
          pts_local:  data.pts_local,
          pts_visita: data.pts_visita,
          estado:     'finalizado',
        };
        const { error } = await db.from('partidos').update(update).eq('id', data.id);
        result = error ? fail(error, 'Error al cargar resultado') : { success: true, message: 'Resultado cargado' };
        break;
      }

      case 'actualizarEstadoPartido': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyPartidoOwnership(data.id, session.org_id);
        const estadosValidos = ['programado', 'en_vivo', 'finalizado', 'suspendido'];
        if (!estadosValidos.includes(data.estado)) {
          result = { success: false, message: 'Estado inválido' }; break;
        }
        const { error } = await db.from('partidos').update({ estado: data.estado }).eq('id', data.id);
        result = error ? fail(error, 'Error al actualizar estado') : { success: true, message: 'Estado actualizado' };
        break;
      }

      case 'eliminarPartido': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyPartidoOwnership(data.id, session.org_id);
        const { error } = await db.from('partidos').delete().eq('id', data.id);
        result = error ? fail(error, 'Error al eliminar partido') : { success: true, message: 'Partido eliminado' };
        break;
      }

      // ══ STANDINGS ════════════════════════════════════════════════════════════

      case 'getStandings': {
        const { data: rows, error } = await db.from('standings')
          .select('*').eq('categoria_id', data.categoria_id)
          .order('pts', { ascending: false });
        result = error ? fail(error, 'Error al cargar tabla') : { success: true, data: rows || [] };
        break;
      }

      // ══ NOTICIAS ═════════════════════════════════════════════════════════════

      case 'getNoticiasPublic': {
        const { data: news, error } = await db.from('noticias')
          .select('*').eq('torneo_id', data.torneo_id).eq('publicado', true)
          .order('created_at', { ascending: false });
        result = error ? fail(error, 'Error al cargar noticias') : { success: true, data: news || [] };
        break;
      }

      case 'crearNoticia': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyTorneoOwnership(data.torneo_id, session.org_id);
        const { error } = await db.from('noticias').insert({
          torneo_id:  data.torneo_id,
          titulo:     data.titulo?.trim(),
          contenido:  data.contenido || null,
          imagen_url: data.imagen_url || null,
          publicado:  data.publicado !== false,
        });
        result = error ? fail(error, 'Error al crear noticia') : { success: true, message: 'Noticia publicada' };
        break;
      }

      case 'actualizarNoticia': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyNoticiaOwnership(data.id, session.org_id);
        const { error } = await db.from('noticias').update({
          titulo:    data.titulo?.trim(),
          contenido: data.contenido,
          publicado: data.publicado,
        }).eq('id', data.id);
        result = error ? fail(error, 'Error al actualizar noticia') : { success: true, message: 'Noticia actualizada' };
        break;
      }

      case 'eliminarNoticia': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyNoticiaOwnership(data.id, session.org_id);
        const { error } = await db.from('noticias').delete().eq('id', data.id);
        result = error ? fail(error, 'Error al eliminar noticia') : { success: true, message: 'Noticia eliminada' };
        break;
      }

      // ══ SANCIONES ════════════════════════════════════════════════════════════

      case 'getSancionesPublic':
      case 'getSancionesCategoria': {
        const { data: sancs, error } = await db.from('sanciones')
          .select('*, equipos(nombre)').eq('categoria_id', data.categoria_id)
          .order('created_at', { ascending: false });
        result = error ? fail(error, 'Error al cargar sanciones') : { success: true, data: sancs || [] };
        break;
      }

      case 'crearSancion': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifyCategoriaTorneo(data.categoria_id, session.org_id);
        const { error } = await db.from('sanciones').insert({
          categoria_id:    data.categoria_id,
          equipo_id:       data.equipo_id || null,
          jugador_nombre:  data.jugador_nombre || null,
          tipo:            data.tipo,
          descripcion:     data.descripcion || null,
          fecha_fin:       data.fecha_fin || null,
          fecha_apelacion: data.fecha_apelacion || null,
        });
        result = error ? fail(error, 'Error al crear sanción') : { success: true, message: 'Sanción registrada' };
        break;
      }

      case 'actualizarSancion': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifySancionOwnership(data.id, session.org_id);
        const { error } = await db.from('sanciones').update({
          jugador_nombre:  data.jugador_nombre,
          tipo:            data.tipo,
          descripcion:     data.descripcion || null,
          fecha_fin:       data.fecha_fin || null,
          fecha_apelacion: data.fecha_apelacion || null,
        }).eq('id', data.id);
        result = error ? fail(error, 'Error al actualizar sanción') : { success: true, message: 'Sanción actualizada' };
        break;
      }

      case 'eliminarSancion': {
        requireOrg(session);
        if (session.rol !== 'admin') await verifySancionOwnership(data.id, session.org_id);
        const { error } = await db.from('sanciones').delete().eq('id', data.id);
        result = error ? fail(error, 'Error al eliminar sanción') : { success: true, message: 'Sanción eliminada' };
        break;
      }

      // ══ MÉTRICAS ═════════════════════════════════════════════════════════════

      case 'getMetricas': {
        requireAdmin(session);
        const [rS, rO, rT, rE] = await Promise.all([
          db.from('solicitudes').select('id', { count: 'exact', head: true }),
          db.from('organizadores').select('id', { count: 'exact', head: true }).eq('activo', true),
          db.from('torneos').select('id', { count: 'exact', head: true }).neq('estado', 'eliminado'),
          db.from('equipos').select('id', { count: 'exact', head: true }).eq('activo', true),
        ]);
        result = {
          success: true,
          data: {
            solicitudes:   rS.count || 0,
            organizadores: rO.count || 0,
            torneos:       rT.count || 0,
            equipos:       rE.count || 0,
          }
        };
        break;
      }

      default:
        result = { success: false, message: 'Acción no reconocida' }; // no exponer el nombre de la acción
    }

    return ok(result);

  } catch (err) {
    console.error('[ACTIVA PLAY]', err.message);
    // Nunca exponer stack trace ni detalles internos al cliente
    return ok({ success: false, message: err.message?.includes('permiso') || err.message?.includes('encontrado')
      ? err.message  // mensajes de ownership/not-found son seguros de mostrar
      : 'Error interno del servidor'
    });
  }
};

/*
══════════════════════════════════════════════════════════════════════
SQL — Ejecutar en Supabase SQL Editor para completar la seguridad
══════════════════════════════════════════════════════════════════════

-- 1. Tabla para rate limiting
CREATE TABLE IF NOT EXISTS login_attempts (
  ip           TEXT PRIMARY KEY,
  attempts     INT DEFAULT 0,
  window_start TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Habilitar RLS en todas las tablas
ALTER TABLE torneos       ENABLE ROW LEVEL SECURITY;
ALTER TABLE categorias    ENABLE ROW LEVEL SECURITY;
ALTER TABLE equipos       ENABLE ROW LEVEL SECURITY;
ALTER TABLE partidos      ENABLE ROW LEVEL SECURITY;
ALTER TABLE sanciones     ENABLE ROW LEVEL SECURITY;
ALTER TABLE noticias      ENABLE ROW LEVEL SECURITY;
ALTER TABLE solicitudes   ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizadores ENABLE ROW LEVEL SECURITY;

-- 3. Políticas de lectura pública (anon key solo lee lo visible)
CREATE POLICY "pub_torneos" ON torneos
  FOR SELECT USING (visible = true AND estado != 'eliminado');

CREATE POLICY "pub_categorias" ON categorias
  FOR SELECT USING (activo = true AND
    EXISTS (SELECT 1 FROM torneos t WHERE t.id = categorias.torneo_id AND t.visible = true));

CREATE POLICY "pub_equipos" ON equipos
  FOR SELECT USING (activo = true AND
    EXISTS (SELECT 1 FROM torneos t WHERE t.id = equipos.torneo_id AND t.visible = true));

CREATE POLICY "pub_partidos" ON partidos
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM torneos t WHERE t.id = partidos.torneo_id AND t.visible = true));

CREATE POLICY "pub_noticias" ON noticias
  FOR SELECT USING (publicado = true AND
    EXISTS (SELECT 1 FROM torneos t WHERE t.id = noticias.torneo_id AND t.visible = true));

CREATE POLICY "pub_sanciones" ON sanciones
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM categorias c
      JOIN torneos t ON t.id = c.torneo_id
      WHERE c.id = sanciones.categoria_id AND t.visible = true));

-- solicitudes: solo insertar desde frontend, sin lectura pública
CREATE POLICY "insert_solicitudes" ON solicitudes
  FOR INSERT WITH CHECK (true);

-- organizadores y standings: solo service_role (función Netlify)
-- Sin SELECT policy = nadie con anon key puede leer estas tablas

-- 4. Índices de performance
CREATE INDEX IF NOT EXISTS idx_partidos_torneo     ON partidos(torneo_id);
CREATE INDEX IF NOT EXISTS idx_partidos_categoria  ON partidos(categoria_id);
CREATE INDEX IF NOT EXISTS idx_partidos_estado     ON partidos(estado);
CREATE INDEX IF NOT EXISTS idx_equipos_categoria   ON equipos(categoria_id);
CREATE INDEX IF NOT EXISTS idx_equipos_torneo      ON equipos(torneo_id);
CREATE INDEX IF NOT EXISTS idx_noticias_torneo     ON noticias(torneo_id);
CREATE INDEX IF NOT EXISTS idx_sanciones_categoria ON sanciones(categoria_id);
CREATE INDEX IF NOT EXISTS idx_torneos_visible     ON torneos(visible);
CREATE INDEX IF NOT EXISTS idx_categorias_torneo   ON categorias(torneo_id);

-- 5. Agregar en Netlify Environment Variables:
--    ALLOWED_ORIGIN = https://activaplay.cl
*/
