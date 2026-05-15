/**
 * netlify/functions/admin.js — LIGAS BBALL v1.0
 *
 * Variables de entorno en Netlify:
 *   SUPABASE_URL         = https://bhnmdkfvfpvvddqalazl.supabase.co
 *   SUPABASE_SERVICE_KEY = eyJ...service_role...
 *   SUPER_ADMIN_PASSWORD = (elige una contraseña segura)
 *   TURNSTILE_SECRET_KEY = (desde Cloudflare Turnstile dashboard)
 *
 * Roles:
 *   super_admin → acceso total
 *   sub_admin   → solo su ciudad (id_ciudad)
 *   delegado    → solo su equipo (id_equipo)
 */

const { createClient } = require('@supabase/supabase-js');

const db = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY  // service role: bypasea RLS
);

const SUPER_PWD   = process.env.SUPER_ADMIN_PASSWORD || 'BballAdmin2026*';
const SUPER_EMAIL = process.env.SUPER_ADMIN_EMAIL    || 'n.moraganavarro@gmail.com';
const TS_SECRET  = process.env.TURNSTILE_SECRET_KEY || '';

const HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// ─── HANDLER PRINCIPAL ────────────────────────────────────────────────────────
exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return res(200, '');

  try {
    const body = JSON.parse(event.body || '{}');
    const { action, adminPassword, turnstileToken, ...data } = body;

    // ── Acciones sin autenticación ───────────────────────────────────────────
    const PUBLIC_ACTIONS = ['checkLogin', 'likeNoticia', 'getCiudades', 'crearSolicitud'];

    // ── Verificar Turnstile en login ─────────────────────────────────────────
    if (action === 'checkLogin' && TS_SECRET && turnstileToken) {
      const valid = await verifyTurnstile(turnstileToken);
      if (!valid) return ok({ success: false, message: 'Verificación Turnstile fallida' });
    }

    // ── Obtener sesión del usuario ───────────────────────────────────────────
    let session = null;
    if (!PUBLIC_ACTIONS.includes(action) && adminPassword) {
      session = await getSession(adminPassword);
      if (!session && adminPassword === SUPER_PWD) {
        session = { rol: 'super_admin', id_ciudad: null, id_equipo: null };
      }
      if (!session) return ok({ success: false, message: 'Sesión inválida o expirada' });
    }

    // ── Verificar que la acción sea permitida para el rol ────────────────────
    if (!PUBLIC_ACTIONS.includes(action) && !session) {
      return ok({ success: false, message: 'No autorizado' });
    }

    let result;

    switch (action) {


      // ══════════════════════════════════════════════════════════════════════
      //  SOLICITUDES
      // ══════════════════════════════════════════════════════════════════════

      case 'crearSolicitud': {
        // Público — sin auth
        if (!data.nombre || !data.email || !data.ciudad || !data.liga) {
          result = { success: false, message: 'Faltan campos obligatorios' }; break;
        }
        const { error } = await db.from('solicitudes').insert({
          nombre:    data.nombre,
          email:     data.email.toLowerCase(),
          telefono:  data.telefono || null,
          ciudad:    data.ciudad,
          liga:      data.liga,
          categoria: data.categoria || null,
          equipos:   data.equipos || 0,
          temporada: data.temporada || null,
          plan:      data.plan || null,
          estado:    'pendiente',
          tipo:      data.tipo || 'sub_admin',
        });
        result = error ? fail(error) : { success: true, message: 'Solicitud enviada correctamente' };
        break;
      }

      case 'listarSolicitudes': {
        requireRole(session, ['super_admin']);
        const { data: sols, error } = await db.from('solicitudes')
          .select('*')
          .order('created_at', { ascending: false });
        result = error ? fail(error) : { success: true, data: sols || [] };
        break;
      }

      case 'aprobarSolicitud': {
        requireRole(session, ['super_admin']);
        const { error } = await db.from('solicitudes').update({
          estado:      'aprobada',
          notas_admin: data.notas || null,
        }).eq('id', data.id);
        // Aquí se podría crear el usuario sub_admin automáticamente
        // Por ahora solo marca como aprobada y el super_admin crea el usuario manualmente
        if (!error) {
          // Al aprobar: registrar fecha de inicio de suscripción
          await db.from('solicitudes').update({
            suscripcion_inicio: new Date().toISOString(),
            suscripcion_estado: 'activa',
          }).eq('id', data.id).catch(()=>{});
        }
        result = error ? fail(error) : { success: true, message: 'Solicitud aprobada — crea el usuario sub-admin en Configuración' };
        break;
      }

      case 'rechazarSolicitud': {
        requireRole(session, ['super_admin']);
        const { error } = await db.from('solicitudes').update({
          estado:      'rechazada',
          notas_admin: data.notas || null,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Solicitud rechazada' };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  SUSCRIPCIONES (paso 10)
      // ══════════════════════════════════════════════════════════════════════

      case 'renovarSuscripcion': {
        requireRole(session, ['super_admin']);
        const { error } = await db.from('solicitudes').update({
          suscripcion_estado: 'activa',
          suscripcion_inicio: new Date().toISOString(),
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Suscripción renovada' };
        break;
      }

      case 'cancelarSuscripcion': {
        requireRole(session, ['super_admin']);
        const { error } = await db.from('solicitudes').update({
          suscripcion_estado: 'cancelada',
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Suscripción cancelada' };
        break;
      }

      case 'expirarSuscripcion': {
        requireRole(session, ['super_admin']);
        const { error } = await db.from('solicitudes').update({
          suscripcion_estado: 'expirada',
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Suscripción marcada como expirada' };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  AUTH
      // ══════════════════════════════════════════════════════════════════════

      case 'checkLogin': {
        // 1. Super Admin por email + password fijo
        if (data.email?.toLowerCase() === SUPER_EMAIL && data.password === SUPER_PWD) {
          const token = generateToken();
          await db.from('usuarios_roles').upsert({
            user_id:    '00000000-0000-0000-0000-000000000000',
            rol:        'super_admin',
            activo:     true,
          }, { onConflict: 'user_id' });
          result = {
            success: true,
            token,
            usuario: { nombre: 'Super Admin', email: data.email || '', rol: 'super_admin' }
          };
          // Token generado — sesiones manejadas en el frontend
          break;
        }

        // 2. Sub-admin / Delegado con email+password via Supabase Auth
        const { data: authData, error: authErr } = await db.auth.signInWithPassword({
          email: data.email,
          password: data.password,
        });
        if (authErr || !authData?.user) {
          result = { success: false, message: 'Email o contraseña incorrectos' };
          break;
        }

        // Obtener rol del usuario
        const { data: rolData } = await db
          .from('usuarios_roles')
          .select('*, ciudades(nombre), equipos(NombreEquipo)')
          .eq('user_id', authData.user.id)
          .eq('activo', true)
          .maybeSingle();

        if (!rolData) {
          result = { success: false, message: 'Usuario sin rol asignado. Contacta al Super Admin.' };
          break;
        }

        result = {
          success: true,
          token: authData.session.access_token,
          usuario: {
            nombre:      authData.user.user_metadata?.nombre || authData.user.email,
            email:       authData.user.email,
            rol:         rolData.rol,
            id_ciudad:   rolData.id_ciudad,
            ciudad_nombre: rolData.ciudades?.nombre || '',
            id_equipo:   rolData.id_equipo,
            equipo_nombre: rolData.equipos?.NombreEquipo || '',
          }
        };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  CIUDADES
      // ══════════════════════════════════════════════════════════════════════

      case 'getCiudades': {
        const { data: ciudades, error } = await db
          .from('ciudades')
          .select('id, nombre, region, slug, activo')
          .order('orden');
        result = error ? fail(error) : { success: true, data: ciudades || [] };
        break;
      }

      case 'createCiudad': {
        requireRole(session, ['super_admin']);
        const { error } = await db.from('ciudades').insert({
          nombre:  data.nombre,
          region:  data.region || '',
          slug:    slugify(data.nombre),
          activo:  true,
          orden:   data.orden || 99,
        });
        result = error ? fail(error) : { success: true, message: 'Ciudad creada' };
        break;
      }

      case 'updateCiudad': {
        requireRole(session, ['super_admin']);
        const { error } = await db.from('ciudades').update({
          nombre: data.nombre,
          region: data.region,
          activo: data.activo,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Ciudad actualizada' };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  USUARIOS / ROLES (solo super_admin)
      // ══════════════════════════════════════════════════════════════════════

      case 'createUsuario': {
        requireRole(session, ['super_admin']);
        // Crear usuario en Supabase Auth
        const { data: newUser, error: errAuth } = await db.auth.admin.createUser({
          email:         data.email,
          password:      data.password,
          user_metadata: { nombre: data.nombre },
          email_confirm: true,
        });
        if (errAuth) { result = fail(errAuth); break; }

        // Asignar rol
        const { error: errRol } = await db.from('usuarios_roles').insert({
          user_id:    newUser.user.id,
          rol:        data.rol,           // 'sub_admin' o 'delegado'
          id_ciudad:  data.id_ciudad || null,
          id_equipo:  data.id_equipo || null,
          activo:     true,
        });
        result = errRol ? fail(errRol) : { success: true, message: `Usuario ${data.rol} creado` };
        break;
      }

      case 'listUsuarios': {
        requireRole(session, ['super_admin']);
        const { data: users, error } = await db
          .from('usuarios_roles')
          .select('*, ciudades(nombre), equipos(NombreEquipo)')
          .order('created_at', { ascending: false });
        result = error ? fail(error) : { success: true, data: users || [] };
        break;
      }

      case 'toggleUsuario': {
        requireRole(session, ['super_admin']);
        const { error } = await db.from('usuarios_roles')
          .update({ activo: data.activo })
          .eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Estado actualizado' };
        break;
      }

      case 'deleteUsuario': {
        requireRole(session, ['super_admin']);
        await db.from('usuarios_roles').delete().eq('id', data.id);
        result = { success: true, message: 'Usuario eliminado' };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  TEMPORADAS
      // ══════════════════════════════════════════════════════════════════════

      case 'createTemporada': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const ciudadId = session.rol === 'sub_admin' ? session.id_ciudad : data.id_ciudad;
        const { error } = await db.from('temporadas').insert({
          id_ciudad: ciudadId,
          nombre:    data.nombre,
          activo:    true,
        });
        result = error ? fail(error) : { success: true, message: 'Temporada creada' };
        break;
      }

      case 'cerrarTemporada': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('temporadas')
          .update({ activo: false })
          .eq('id', data.temporadaId);
        result = error ? fail(error) : { success: true, message: 'Temporada cerrada' };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  LIGAS
      // ══════════════════════════════════════════════════════════════════════

      case 'createLeague': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const ciudadId = session.rol === 'sub_admin' ? session.id_ciudad : data.id_ciudad;
        const { error } = await db.from('ligas').insert({
          id_ciudad:          ciudadId,
          id_temporada:       data.id_temporada || null,
          NombreFantasia:     data.nombreFantasia,
          NombreDeporte:      data.nombreDeporte || 'Básquetbol',
          Categoria:          data.categoria || 'Masculino A',
          EstadoTorneo:       data.estadoTorneo || 'Activo',
          PuntosVictoria:     data.puntosVictoria || 2,
          PuntosEmpate:       data.puntosEmpate || 0,
          PuntosDerrota:      data.puntosDerrota || 1,
          NroFechas:          data.nroFechas || 0,
        });
        result = error ? fail(error) : { success: true, message: 'Liga creada' };
        break;
      }

      case 'updateLeague': {
        requireRole(session, ['super_admin', 'sub_admin']);
        await assertCiudadAccess(session, 'ligas', data.id);
        const { error } = await db.from('ligas').update({
          NombreFantasia: data.nombreFantasia,
          Categoria:      data.categoria,
          EstadoTorneo:   data.estadoTorneo,
          NroFechas:      data.nroFechas,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Liga actualizada' };
        break;
      }

      case 'deleteLeague': {
        requireRole(session, ['super_admin', 'sub_admin']);
        await assertCiudadAccess(session, 'ligas', data.id);
        const { error } = await db.from('ligas').delete().eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Liga eliminada' };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  EQUIPOS
      // ══════════════════════════════════════════════════════════════════════

      case 'createTeam': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('equipos').insert({
          ID_Liga:              data.idLiga,
          NombreEquipo:         data.nombreEquipo,
          ColorUniformeLocal:   data.colorLocal   || '#1e3a8a',
          ColorUniformeVisita:  data.colorVisita  || '#ffffff',
          logo_url:             data.logoUrl || null,
          activo:               true,
        });
        result = error ? fail(error) : { success: true, message: 'Equipo creado' };
        break;
      }

      case 'updateTeam': {
        requireRole(session, ['super_admin', 'sub_admin', 'delegado']);
        if (session.rol === 'delegado') {
          // Delegado solo puede editar su propio equipo
          if (session.id_equipo !== data.id) return ok({ success: false, message: 'Sin acceso a este equipo' });
        }
        const { error } = await db.from('equipos').update({
          NombreEquipo:         data.nombreEquipo,
          ColorUniformeLocal:   data.colorLocal,
          ColorUniformeVisita:  data.colorVisita,
          logo_url:             data.logoUrl || null,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Equipo actualizado' };
        break;
      }

      case 'deleteTeam': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('equipos').delete().eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Equipo eliminado' };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  JUGADORES (personas)
      // ══════════════════════════════════════════════════════════════════════

      case 'createPersona': {
        requireRole(session, ['super_admin', 'sub_admin', 'delegado']);
        if (session.rol === 'delegado' && session.id_equipo !== data.idEquipo) {
          return ok({ success: false, message: 'Solo puedes agregar jugadores a tu equipo' });
        }
        const { error } = await db.from('personas').insert({
          id_equipo:        data.idEquipo,
          nombre_completo:  data.nombreCompleto,
          rut:              data.rut || null,
          numero_camiseta:  data.numeroCamiseta || null,
          posicion:         data.posicion || null,
          activo:           true,
        });
        result = error ? fail(error) : { success: true, message: 'Jugador registrado' };
        break;
      }

      case 'updatePersona': {
        requireRole(session, ['super_admin', 'sub_admin', 'delegado']);
        // Delegado: verificar que el jugador sea de su equipo
        if (session.rol === 'delegado') {
          const { data: p } = await db.from('personas').select('id_equipo').eq('id', data.id).maybeSingle();
          if (!p || p.id_equipo !== session.id_equipo) return ok({ success: false, message: 'Sin acceso' });
        }
        const { error } = await db.from('personas').update({
          nombre_completo: data.nombreCompleto,
          rut:             data.rut,
          numero_camiseta: data.numeroCamiseta,
          posicion:        data.posicion,
          id_equipo:       data.idEquipo,
          activo:          data.activo !== undefined ? data.activo : true,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Jugador actualizado' };
        break;
      }

      case 'deletePersona': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('personas').delete().eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Jugador eliminado' };
        break;
      }

      case 'transferirJugador': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('personas')
          .update({ id_equipo: data.idEquipoDestino })
          .eq('id', data.idPersona);
        result = error ? fail(error) : { success: true, message: 'Jugador transferido' };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  PARTIDOS
      // ══════════════════════════════════════════════════════════════════════

      case 'createMatch': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('partidos').insert({
          ID_Liga:         data.idLiga,
          Partidos:        data.fecha || 1,
          Fase:            data.fase || 'Fase Regular',
          Fecha:           data.fechaPartido || null,
          Hora:            data.hora || null,
          Cancha:          data.cancha || null,
          ID_EquipoLocal:  data.idEquipoLocal,
          ID_EquipoVisita: data.idEquipoVisita,
          Estado:          'Programado',
        });
        result = error ? fail(error) : { success: true, message: 'Partido programado' };
        break;
      }

      case 'updateMatchResult': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('partidos').update({
          GolesLocal:  data.puntosLocal,
          GolesVisita: data.puntosVisita,
          Estado:      'Final',
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Resultado cargado' };
        break;
      }

      case 'updateMatchStatus': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('partidos')
          .update({ Estado: data.estado })
          .eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Estado actualizado' };
        break;
      }

      case 'updateMatch': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('partidos').update({
          Fecha:           data.fechaPartido,
          Hora:            data.hora,
          Cancha:          data.cancha,
          Fase:            data.fase,
          ID_EquipoLocal:  data.idEquipoLocal,
          ID_EquipoVisita: data.idEquipoVisita,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Partido actualizado' };
        break;
      }

      case 'deleteMatch': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('partidos').delete().eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Partido eliminado' };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  STATS
      // ══════════════════════════════════════════════════════════════════════

      case 'updateStats': {
        requireRole(session, ['super_admin', 'sub_admin']);
        // Upsert stats por jugador
        const rows = (data.stats || []).map(s => ({
          id_partido:   data.idPartido,
          id_persona:   s.id_persona,
          id_equipo:    s.id_equipo,
          puntos:       s.puntos       || 0,
          rebotes:      s.rebotes      || 0,
          asistencias:  s.asistencias  || 0,
          robos:        s.robos        || 0,
          tapones:      s.tapones      || 0,
          faltas:       s.faltas       || 0,
          minutos:      s.minutos      || 0,
        }));
        const { error } = await db.from('stats').upsert(rows, { onConflict: 'id_partido,id_persona' });
        result = error ? fail(error) : { success: true, message: 'Stats actualizadas' };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  SANCIONES
      // ══════════════════════════════════════════════════════════════════════

      case 'createSanction': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('sanciones').insert({
          ID_Liga:          data.idLiga,
          ID_Equipo:        data.idEquipo || null,
          NombreJugador:    data.nombreJugador,
          TipoFalta:        data.tipoFalta,
          Sancion:          data.sancion,
          TerminoSancion:   data.terminoSancion || null,
        });
        result = error ? fail(error) : { success: true, message: 'Sanción registrada' };
        break;
      }

      case 'updateSanction': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('sanciones').update({
          NombreJugador:  data.nombreJugador,
          TipoFalta:      data.tipoFalta,
          Sancion:        data.sancion,
          TerminoSancion: data.terminoSancion,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Sanción actualizada' };
        break;
      }

      case 'deleteSanction': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('sanciones').delete().eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Sanción eliminada' };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  NOTICIAS
      // ══════════════════════════════════════════════════════════════════════

      case 'createNews': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const ciudadId = session.rol === 'sub_admin' ? session.id_ciudad : data.id_ciudad;
        const { error } = await db.from('noticias').insert({
          id_ciudad:    ciudadId,
          Titulo:       data.titulo,
          Descripcion:  data.descripcion || '',
          Fecha:        data.fecha || new Date().toISOString().split('T')[0],
          ImagenURL:    data.imagenUrl || '',
          publicado:    true,
          me_gusta:     0,
        });
        result = error ? fail(error) : { success: true, message: 'Noticia publicada' };
        break;
      }

      case 'updateNews': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('noticias').update({
          Titulo:      data.titulo,
          Descripcion: data.descripcion,
          Fecha:       data.fecha,
          ImagenURL:   data.imagenUrl,
          publicado:   data.publicado !== undefined ? data.publicado : true,
        }).eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Noticia actualizada' };
        break;
      }

      case 'deleteNews': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const { error } = await db.from('noticias').delete().eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Noticia eliminada' };
        break;
      }

      case 'likeNoticia': {
        // Público — sin auth
        try {
          await db.rpc('increment_likes', { noticia_id: data.id });
        } catch(e) {
          // rpc no existe aún, ignorar
        }
        result = { success: true };
        break;
      }

      // ══════════════════════════════════════════════════════════════════════
      //  DELETE GENÉRICO
      // ══════════════════════════════════════════════════════════════════════

      case 'deleteItem': {
        requireRole(session, ['super_admin', 'sub_admin']);
        const tablaMap = {
          ligas: 'ligas', equipos: 'equipos', partidos: 'partidos',
          sanciones: 'sanciones', noticias: 'noticias',
          personas: 'personas', temporadas: 'temporadas',
        };
        const tabla = tablaMap[data.tabla?.toLowerCase()];
        if (!tabla) { result = { success: false, message: 'Tabla no permitida' }; break; }
        const { error } = await db.from(tabla).delete().eq('id', data.id);
        result = error ? fail(error) : { success: true, message: 'Eliminado correctamente' };
        break;
      }

      default:
        result = { success: false, message: 'Acción no reconocida: ' + action };
    }

    return ok(result);

  } catch (err) {
    console.error('LIGAS BBALL admin error:', err);
    return ok({ success: false, message: err.message || 'Error interno' });
  }
};

// ─── HELPERS ─────────────────────────────────────────────────────────────────

const ok   = body => ({ statusCode: 200, headers: HEADERS, body: JSON.stringify(body) });
const res  = (s, b) => ({ statusCode: s, headers: HEADERS, body: JSON.stringify(b) });
const fail = err  => ({ success: false, message: err?.message || err?.details || 'Error BD' });

function slugify(str) {
  return str.toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}

function generateToken() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

// Verifica rol mínimo requerido — lanza error si no cumple
function requireRole(session, allowed) {
  if (!session || !allowed.includes(session.rol)) {
    throw new Error(`Acción requiere rol: ${allowed.join(' o ')}`);
  }
}

// Verifica que un sub_admin solo acceda a recursos de su ciudad
async function assertCiudadAccess(session, tabla, id) {
  if (session.rol === 'super_admin') return;
  if (session.rol !== 'sub_admin' || !session.id_ciudad) throw new Error('Sin acceso');
  const { data: row } = await db.from(tabla).select('id_ciudad').eq('id', id).maybeSingle();
  if (!row || row.id_ciudad !== session.id_ciudad) throw new Error('Sin acceso a este recurso');
}

// Obtener sesión desde token o password
async function getSession(token) {
  if (!token) return null;
  // Super admin: password directo
  if (token === SUPER_PWD) {
    return { rol: 'super_admin', id_ciudad: null, id_equipo: null };
  }
  // JWT de Supabase Auth (empieza con eyJ y tiene 2 puntos)
  if (token.startsWith('eyJ') && token.split('.').length === 3) {
    try {
      const { data: { user }, error } = await db.auth.getUser(token);
      if (error || !user) return null;
      const { data: rolData } = await db.from('usuarios_roles')
        .select('rol, id_ciudad, id_equipo')
        .eq('user_id', user.id)
        .eq('activo', true)
        .maybeSingle();
      return rolData || null;
    } catch {
      return null;
    }
  }
  return null;
}

// Verificar Cloudflare Turnstile
async function verifyTurnstile(token) {
  if (!TS_SECRET || !token) return true; // skip si no configurado
  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${TS_SECRET}&response=${token}`,
    });
    const json = await resp.json();
    return json.success === true;
  } catch {
    return false;
  }
}
