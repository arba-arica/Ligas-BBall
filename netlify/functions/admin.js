/**
 * netlify/functions/admin.js — ACTIVA PLAY v2.0
 *
 * Variables de entorno Netlify:
 *   SUPABASE_URL         = https://bhnmdkfvfpvvddqalazl.supabase.co
 *   SUPABASE_SERVICE_KEY = eyJ...service_role...
 *   ADMIN_EMAIL          = n.moraganavarro@gmail.com
 *   ADMIN_PASSWORD       = BballAdmin2026*
 *
 * Roles:
 *   admin       → control total (usa ADMIN_EMAIL + ADMIN_PASSWORD)
 *   organizador → gestiona su torneo (usa email + clave generada, org_id)
 */

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const db = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const ADMIN_EMAIL = process.env.ADMIN_EMAIL    || 'n.moraganavarro@gmail.com';
const ADMIN_PASS  = process.env.ADMIN_PASSWORD || 'BballAdmin2026*';

const CORS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const ok   = b => ({ statusCode: 200, headers: CORS, body: JSON.stringify(b) });
const fail = e => ({ success: false, message: e?.message || e?.details || String(e) });

function hashPass(pass) {
  return crypto.createHash('sha256').update(pass + 'activaplay2026').digest('hex');
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

// ─── SESIÓN ───────────────────────────────────────────────────────────────────
async function getSession(token) {
  if (!token) return null;
  // Admin principal
  if (token === ADMIN_PASS) return { rol: 'admin', org_id: null };
  // Organizador: token = "org_id:password_hash"
  if (token.startsWith('AP-')) {
    const [orgId, passHash] = token.split(':');
    const { data } = await db.from('organizadores')
      .select('org_id, nombre, email, activo')
      .eq('org_id', orgId)
      .eq('password_hash', passHash)
      .eq('activo', true)
      .maybeSingle();
    if (data) return { rol: 'organizador', org_id: data.org_id, nombre: data.nombre, email: data.email };
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

// ─── HANDLER ──────────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return ok('');

  try {
    const body = JSON.parse(event.body || '{}');
    const { action, token, ...data } = body;

    // Acciones públicas (sin token)
    const PUBLIC = ['checkLogin', 'crearSolicitud', 'getTorneos', 'getCategoriasPublic',
                    'getEquiposPublic', 'getPartidosPublic', 'getNoticiasPublic',
                    'getStandings', 'getSancionesPublic'];

    let session = null;
    if (!PUBLIC.includes(action)) {
      session = await getSession(token);
      if (!session) return ok({ success: false, message: 'Sesión inválida. Inicia sesión nuevamente.' });
    }

    let result;

    switch (action) {

      // ══ AUTH ════════════════════════════════════════════════════════════════

      case 'checkLogin': {
        // Admin
        if (data.email?.toLowerCase() === ADMIN_EMAIL.toLowerCase() && data.password === ADMIN_PASS) {
          result = {
            success: true,
            rol: 'admin',
            token: ADMIN_PASS,
            nombre: 'Administrador',
            email: ADMIN_EMAIL,
          };
          break;
        }
        // Organizador: busca por email + password
        const passHash = hashPass(data.password);
        const { data: org, error } = await db.from('organizadores')
          .select('org_id, nombre, email, ciudad, activo, password_hash')
          .eq('email', data.email?.toLowerCase())
          .maybeSingle();

        if (error || !org) {
          result = { success: false, message: 'Email o contraseña incorrectos' };
          break;
        }
        if (!org.activo) {
          result = { success: false, message: 'Tu cuenta está suspendida. Contacta al administrador.' };
          break;
        }
        if (org.password_hash !== passHash) {
          result = { success: false, message: 'Email o contraseña incorrectos' };
          break;
        }
        result = {
          success: true,
          rol: 'organizador',
          token: org.org_id + ':' + passHash,
          org_id: org.org_id,
          nombre: org.nombre,
          email: org.email,
          ciudad: org.ciudad,
        };
        break;
      }

      // ══ SOLICITUDES ══════════════════════════════════════════════════════════

      case 'crearSolicitud': {
        if (!data.nombre || !data.email || !data.ciudad) {
          result = { success: false, message: 'Nombre, email y ciudad son obligatorios' };
          break;
        }
        const { error } = await db.from('solicitudes').insert({
          nombre:          data.nombre.trim(),
          email:           data.email.toLowerCase().trim(),
          telefono:        data.telefono || null,
          ciudad:          data.ciudad.trim(),
          deporte:         data.deporte || 'Básquetbol',
          descripcion:     data.descripcion || null,
          cant_categorias: data.cant_categorias || 1,
          estado:          'pendiente',
        });
        result = error ? fail(error) : { success: true, message: '¡Solicitud enviada! Te contactaremos pronto.' };
        break;
      }

      case 'listarSolicitudes': {
        requireAdmin(session);
        const { data: sols, error } = await db.from('solicitudes')
          .select('*')
          .order('created_at', { ascending: false });
        result = error ? fail(error) : { success: true, data: sols || [] };
        break;
      }

      case 'aprobarSolicitud': {
        requireAdmin(session);
        // Obtener solicitud
        const { data: sol } = await db.from('solicitudes').select('*').eq('id', data.id).maybeSingle();
        if (!sol) { result = { success: false, message: 'Solicitud no encontrada' }; break; }

        // Generar org_id secuencial
        const { count } = await db.from('organizadores').select('id', { count: 'exact', head: true });
        const orgId = generateOrgId((count || 0) + 1);

        // Generar clave de acceso
        const claveAcceso = generatePassword();
        const passHash = hashPass(claveAcceso);

        // Crear organizador
        const { error: errOrg } = await db.from('organizadores').insert({
          org_id:           orgId,
          nombre:           sol.nombre,
          email:            sol.email,
          password_hash:    passHash,
          ciudad:           sol.ciudad,
          activo:           true,
          suscripcion_inicio: new Date().toISOString(),
        });
        if (errOrg) { result = fail(errOrg); break; }

        // Actualizar solicitud
        await db.from('solicitudes').update({
          estado:       'aprobada',
          org_id:       orgId,
          clave_acceso: claveAcceso,
          notas_admin:  data.notas || null,
        }).eq('id', data.id);

        result = {
          success:      true,
          org_id:       orgId,
          clave_acceso: claveAcceso,
          email:        sol.email,
          message:      'Solicitud aprobada — ' + orgId,
        };
        break;
      }

      case 'rechazarSolicitud': {
        requireAdmin(session);
        const { error } = await db.from('solicitudes').update({
          estado: 'rechazada',
          notas_admin: data.notas || null,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Solicitud rechazada' };
        break;
      }

      // ══ ORGANIZADORES ════════════════════════════════════════════════════════

      case 'listarOrganizadores': {
        requireAdmin(session);
        const { data: orgs, error } = await db.from('organizadores')
          .select('id, org_id, nombre, email, ciudad, activo, suscripcion_inicio, suscripcion_fin')
          .order('created_at', { ascending: false });
        // Para cada org, contar torneos activos
        const result_data = await Promise.all((orgs || []).map(async o => {
          const { count } = await db.from('torneos')
            .select('id', { count: 'exact', head: true })
            .eq('org_id', o.org_id)
            .neq('estado', 'eliminado');
          return { ...o, torneos_count: count || 0 };
        }));
        result = error ? fail(error) : { success: true, data: result_data };
        break;
      }

      case 'toggleOrganizador': {
        requireAdmin(session);
        const { error } = await db.from('organizadores')
          .update({ activo: data.activo })
          .eq('org_id', data.org_id);
        result = error ? fail(error) : { success: true, message: data.activo ? 'Organizador activado' : 'Organizador suspendido' };
        break;
      }

      case 'resetPassword': {
        requireAdmin(session);
        const nuevaClave = generatePassword();
        const { error } = await db.from('organizadores')
          .update({ password_hash: hashPass(nuevaClave) })
          .eq('org_id', data.org_id);
        if (error) { result = fail(error); break; }
        await db.from('solicitudes').update({ clave_acceso: nuevaClave }).eq('org_id', data.org_id);
        result = { success: true, clave_acceso: nuevaClave, message: 'Clave regenerada' };
        break;
      }

      // ══ TORNEOS ══════════════════════════════════════════════════════════════

      case 'getTorneos': {
        // Público: solo torneos visibles
        const { data: torneos, error } = await db.from('torneos')
          .select('id, nombre, ciudad, deporte, temporada, descripcion, estado, visible, org_id, created_at')
          .eq('visible', true)
          .neq('estado', 'eliminado')
          .order('created_at', { ascending: false });
        result = error ? fail(error) : { success: true, data: torneos || [] };
        break;
      }

      case 'getTorneosAdmin': {
        requireAdmin(session);
        const { data: torneos, error } = await db.from('torneos')
          .select('*, organizadores(nombre, email)')
          .neq('estado', 'eliminado')
          .order('created_at', { ascending: false });
        result = error ? fail(error) : { success: true, data: torneos || [] };
        break;
      }

      case 'getMiTorneo': {
        requireOrg(session);
        const { data: torneo, error } = await db.from('torneos')
          .select('*')
          .eq('org_id', session.org_id)
          .neq('estado', 'eliminado')
          .order('created_at', { ascending: false })
          .limit(1)
          .maybeSingle();
        result = error ? fail(error) : { success: true, data: torneo };
        break;
      }

      case 'crearTorneo': {
        requireOrg(session);
        const { data: torneo, error } = await db.from('torneos').insert({
          org_id:      session.org_id,
          nombre:      data.nombre,
          ciudad:      data.ciudad || session.ciudad,
          deporte:     data.deporte || 'Básquetbol',
          temporada:   data.temporada || null,
          descripcion: data.descripcion || null,
          estado:      'borrador',
          visible:     false,
        }).select().single();
        result = error ? fail(error) : { success: true, data: torneo, message: 'Torneo creado' };
        break;
      }

      case 'actualizarTorneo': {
        requireOrg(session);
        const where = session.rol === 'admin' ? { id: data.id } : { id: data.id, org_id: session.org_id };
        const { error } = await db.from('torneos').update({
          nombre:      data.nombre,
          temporada:   data.temporada,
          descripcion: data.descripcion,
          reglamento_url: data.reglamento_url,
        }).match(where);
        result = error ? fail(error) : { success: true, message: 'Torneo actualizado' };
        break;
      }

      case 'publicarTorneo': {
        requireOrg(session);
        // Admin puede publicar/ocultar cualquier torneo, organizador solo el suyo
        let qPub = db.from('torneos').update({
          visible: data.visible,
          estado:  data.visible ? 'activo' : 'borrador',
        }).eq('id', data.id);
        if (session.rol !== 'admin') qPub = qPub.eq('org_id', session.org_id);
        const { error } = await qPub;
        result = error ? fail(error) : { success: true, message: data.visible ? 'Torneo publicado' : 'Torneo ocultado' };
        break;
      }

      case 'eliminarTorneo': {
        requireAdmin(session);
        const { error } = await db.from('torneos').update({ estado: 'eliminado', visible: false }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Torneo eliminado' };
        break;
      }

      // ══ CATEGORIAS ═══════════════════════════════════════════════════════════

      case 'getCategoriasPublic': {
        const { data: cats, error } = await db.from('categorias')
          .select('*')
          .eq('torneo_id', data.torneo_id)
          .eq('activo', true)
          .order('orden');
        result = error ? fail(error) : { success: true, data: cats || [] };
        break;
      }

      case 'getMisCategorias': {
        requireOrg(session);
        const { data: cats, error } = await db.from('categorias')
          .select('*')
          .eq('torneo_id', data.torneo_id)
          .order('orden');
        result = error ? fail(error) : { success: true, data: cats || [] };
        break;
      }

      case 'crearCategoria': {
        requireOrg(session);
        const { data: cat, error } = await db.from('categorias').insert({
          torneo_id:    data.torneo_id,
          nombre:       data.nombre,
          pts_victoria: data.pts_victoria || 2,
          pts_empate:   data.pts_empate   || 0,
          pts_derrota:  data.pts_derrota  || 1,
          orden:        data.orden        || 0,
        }).select().single();
        result = error ? fail(error) : { success: true, data: cat, message: 'Categoría creada' };
        break;
      }

      case 'actualizarCategoria': {
        requireOrg(session);
        const { error } = await db.from('categorias').update({
          nombre:       data.nombre,
          pts_victoria: data.pts_victoria,
          pts_empate:   data.pts_empate,
          pts_derrota:  data.pts_derrota,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Categoría actualizada' };
        break;
      }

      case 'eliminarCategoria': {
        requireOrg(session);
        const { error } = await db.from('categorias').update({ activo: false }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Categoría eliminada' };
        break;
      }

      // ══ EQUIPOS ══════════════════════════════════════════════════════════════

      case 'getEquiposPublic':
      case 'getEquiposCategoria': {
        const { data: equipos, error } = await db.from('equipos')
          .select('*')
          .eq('categoria_id', data.categoria_id)
          .eq('activo', true)
          .order('nombre');
        result = error ? fail(error) : { success: true, data: equipos || [] };
        break;
      }

      case 'crearEquipo': {
        requireOrg(session);
        const { data: eq, error } = await db.from('equipos').insert({
          categoria_id: data.categoria_id,
          nombre:       data.nombre,
          color_local:  data.color_local  || '#1d4ed8',
          color_visita: data.color_visita || '#ffffff',
        }).select().single();
        result = error ? fail(error) : { success: true, data: eq, message: 'Equipo creado' };
        break;
      }

      case 'actualizarEquipo': {
        requireOrg(session);
        const updEq = { nombre: data.nombre };
        if (data.color_local)  updEq.color_local  = data.color_local;
        if (data.color_visita) updEq.color_visita = data.color_visita;
        const { error } = await db.from('equipos').update(updEq).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Equipo actualizado' };
        break;
      }

      case 'eliminarEquipo': {
        requireOrg(session);
        const { error } = await db.from('equipos').update({ activo: false }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Equipo eliminado' };
        break;
      }

      // ══ PARTIDOS ═════════════════════════════════════════════════════════════

      case 'getPartidosPublic':
      case 'getPartidosCategoria': {
        let qPar = db.from('partidos')
          .select('*, local:equipo_local(nombre,color_local), visita:equipo_visita(nombre,color_local)')
          .eq('categoria_id', data.categoria_id);
        if (data.estado) qPar = qPar.eq('estado', data.estado);
        qPar = qPar.order('nro_fecha').order('fecha').order('hora');
        const { data: pts, error } = await qPar;
        result = error ? fail(error) : { success: true, data: pts || [] };
        break;
      }

      case 'crearPartido': {
        requireOrg(session);
        const { data: partido, error } = await db.from('partidos').insert({
          categoria_id:   data.categoria_id,
          fecha:          data.fecha || null,
          hora:           data.hora  || null,
          cancha:         data.cancha || null,
          fase:           data.fase  || 'Fase Regular',
          nro_fecha:      data.nro_fecha || 1,
          equipo_local:   data.equipo_local,
          equipo_visita:  data.equipo_visita,
          url_transmision: data.url_transmision || null,
          estado:         'programado',
        }).select().single();
        result = error ? fail(error) : { success: true, data: partido, message: 'Partido programado' };
        break;
      }

      case 'actualizarPartido': {
        requireOrg(session);
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
        result = error ? fail(error) : { success: true, message: 'Partido actualizado' };
        break;
      }

      case 'actualizarResultado': {
        requireOrg(session);
        const update = {
          pts_local:   data.pts_local,
          pts_visita:  data.pts_visita,
          estado:      'finalizado',
        };
        // Cuartos opcionales
        if (data.q1_local  !== undefined) { update.q1_local  = data.q1_local;  update.q1_visita = data.q1_visita; }
        if (data.q2_local  !== undefined) { update.q2_local  = data.q2_local;  update.q2_visita = data.q2_visita; }
        if (data.q3_local  !== undefined) { update.q3_local  = data.q3_local;  update.q3_visita = data.q3_visita; }
        if (data.q4_local  !== undefined) { update.q4_local  = data.q4_local;  update.q4_visita = data.q4_visita; }
        const { error } = await db.from('partidos').update(update).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Resultado cargado' };
        break;
      }

      case 'actualizarEstadoPartido': {
        requireOrg(session);
        const { error } = await db.from('partidos').update({ estado: data.estado }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Estado actualizado' };
        break;
      }

      case 'eliminarPartido': {
        requireOrg(session);
        const { error } = await db.from('partidos').delete().eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Partido eliminado' };
        break;
      }

      // ══ STANDINGS ════════════════════════════════════════════════════════════

      case 'getStandings': {
        const { data: rows, error } = await db.from('standings')
          .select('*')
          .eq('categoria_id', data.categoria_id)
          .order('pts', { ascending: false });
        result = error ? fail(error) : { success: true, data: rows || [] };
        break;
      }

      // ══ NOTICIAS ═════════════════════════════════════════════════════════════

      case 'getNoticiasPublic': {
        const { data: news, error } = await db.from('noticias')
          .select('*')
          .eq('torneo_id', data.torneo_id)
          .eq('publicado', true)
          .order('created_at', { ascending: false });
        result = error ? fail(error) : { success: true, data: news || [] };
        break;
      }

      case 'crearNoticia': {
        requireOrg(session);
        const { error } = await db.from('noticias').insert({
          torneo_id:  data.torneo_id,
          titulo:     data.titulo,
          contenido:  data.contenido || null,
          imagen_url: data.imagen_url || null,
          publicado:  data.publicado !== false,
        });
        result = error ? fail(error) : { success: true, message: 'Noticia publicada' };
        break;
      }

      case 'actualizarNoticia': {
        requireOrg(session);
        const { error } = await db.from('noticias').update({
          titulo:    data.titulo,
          contenido: data.contenido,
          publicado: data.publicado,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Noticia actualizada' };
        break;
      }

      case 'eliminarNoticia': {
        requireOrg(session);
        const { error } = await db.from('noticias').delete().eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Noticia eliminada' };
        break;
      }

      // ══ SANCIONES ════════════════════════════════════════════════════════════

      case 'getSancionesPublic':
      case 'getSancionesCategoria': {
        const { data: sancs, error } = await db.from('sanciones')
          .select('*, equipos(nombre)')
          .eq('categoria_id', data.categoria_id)
          .order('created_at', { ascending: false });
        result = error ? fail(error) : { success: true, data: sancs || [] };
        break;
      }

      case 'crearSancion': {
        requireOrg(session);
        const { error } = await db.from('sanciones').insert({
          categoria_id:    data.categoria_id,
          equipo_id:       data.equipo_id || null,
          jugador_nombre:  data.jugador_nombre || null,
          tipo:            data.tipo,
          descripcion:     data.descripcion || null,
          fecha_fin:       data.fecha_fin || null,
          fecha_apelacion: data.fecha_apelacion || null,
        });
        result = error ? fail(error) : { success: true, message: 'Sanción registrada' };
        break;
      }

      case 'actualizarSancion': {
        requireOrg(session);
        const { error } = await db.from('sanciones').update({
          jugador_nombre:  data.jugador_nombre,
          tipo:            data.tipo,
          descripcion:     data.descripcion || null,
          fecha_fin:       data.fecha_fin || null,
          fecha_apelacion: data.fecha_apelacion || null,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Sanción actualizada' };
        break;
      }

      case 'eliminarSancion': {
        requireOrg(session);
        const { error } = await db.from('sanciones').delete().eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Sanción eliminada' };
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
        result = { success: false, message: 'Acción no reconocida: ' + action };
    }

    return ok(result);

  } catch (err) {
    console.error('ACTIVA PLAY error:', err.message);
    return ok({ success: false, message: err.message || 'Error interno del servidor' });
  }
};
