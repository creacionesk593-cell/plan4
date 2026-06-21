// ============================================================
// configuracion.js
// Archivo central: Supabase client + helpers compartidos
// Importar en TODAS las páginas HTML antes de cualquier script
// ============================================================

import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm'

// ------------------------------------------------------------
// CREDENCIALES SUPABASE
// Supabase > Settings > API > Project URL y anon public key
// La anon key es segura para el frontend — RLS protege los datos
// ------------------------------------------------------------
const SUPABASE_URL  = 'https://qzprdyvkmjnrjifgafoo.supabase.co'
const SUPABASE_ANON = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF6cHJkeXZrbWpucmppZmdhZm9vIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODIwNjI3MzUsImV4cCI6MjA5NzYzODczNX0.pFb7634WbDMLu4oPg0t2QRYtPMa8pGh7QFf-UCzmzcE'

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON)


// ============================================================
// AUTH: sesión y perfil
// ============================================================

/**
 * Devuelve el usuario autenticado actual o null
 */
export async function getUser() {
  const { data: { user } } = await supabase.auth.getUser()
  return user
}

/**
 * Devuelve el perfil completo del usuario actual desde la tabla profiles
 */
export async function getProfile(userId) {
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', userId)
    .single()
  if (error) return null
  return data
}

/**
 * Cierra sesión y redirige al login
 */
export async function logout() {
  await supabase.auth.signOut()
  window.location.href = 'login.html'
}


// ============================================================
// ACCESS GUARD
// Llama esto al inicio de CADA página protegida
//
// Uso:
//   import { guardAcceso } from './configuracion.js'
//   await guardAcceso('cliente')      // solo clientes
//   await guardAcceso('vendedor')     // solo vendedores
//   await guardAcceso('administrador') // solo admins
//   await guardAcceso(['cliente','administrador']) // varios roles
// ============================================================

export async function guardAcceso(rolesPermitidos) {
  const roles = Array.isArray(rolesPermitidos)
    ? rolesPermitidos
    : [rolesPermitidos]

  // 1. Verificar sesión activa
  const user = await getUser()
  if (!user) {
    window.location.href = 'login.html'
    return null
  }

  // 2. Obtener perfil
  const profile = await getProfile(user.id)
  if (!profile) {
    await logout()
    return null
  }

  // 3. Verificar si debe cambiar contraseña
  if (profile.must_change_password) {
    window.location.href = 'change-password.html'
    return null
  }

  // 4. Verificar rol
  if (!roles.includes(profile.rol)) {
    window.location.href = 'login.html'
    return null
  }

  // 5. Verificar cuenta activa
  if (!profile.activo) {
    mostrarError('Tu cuenta está inactiva. Contacta al administrador.')
    setTimeout(() => logout(), 3000)
    return null
  }

  // 6. Si es cliente, verificar acceso a las apps (crédito o suscripción)
  //    Solo se aplica cuando la página lo requiere explícitamente
  return profile
}

/**
 * Verifica si el cliente actual puede acceder a app1 o app2
 * Retorna { puede: bool, motivo: string }
 */
export async function verificarAccesoApp(userId) {
  const { data, error } = await supabase
    .from('vista_acceso_cliente')
    .select('puede_acceder, tiene_suscripcion_activa, tiene_creditos, suscripcion_vence_en, creditos_disponibles')
    .eq('id', userId)
    .single()

  if (error || !data) {
    return { puede: false, motivo: 'No se pudo verificar el acceso.' }
  }

  if (!data.puede_acceder) {
    if (!data.tiene_suscripcion_activa && !data.tiene_creditos) {
      return { puede: false, motivo: 'No tienes créditos ni suscripción activa.' }
    }
  }

  return {
    puede: data.puede_acceder,
    motivo: '',
    suscripcion_vence_en: data.suscripcion_vence_en,
    creditos_disponibles: data.creditos_disponibles
  }
}


// ============================================================
// LOGIN ATTEMPTS: rate limiting en el cliente
// (complementa el control en la base de datos)
// ============================================================

const MAX_INTENTOS   = 5
const BLOQUEO_MS     = 15 * 60 * 1000  // 15 minutos

/**
 * Registra un intento fallido de login en Supabase
 * Retorna true si el usuario está bloqueado
 */
export async function registrarIntentoFallido(email) {
  // Verificar si ya existe registro
  const { data: existing } = await supabase
    .from('login_attempts')
    .select('*')
    .eq('email', email.toLowerCase())
    .single()

  const ahora = new Date()

  if (existing) {
    // Si el bloqueo ya expiró, reiniciar contador
    if (existing.bloqueado_hasta && new Date(existing.bloqueado_hasta) < ahora) {
      await supabase.from('login_attempts').update({
        intentos: 1,
        ultimo_intento: ahora.toISOString(),
        bloqueado_hasta: null
      }).eq('email', email.toLowerCase())
      return false
    }

    const nuevosIntentos = (existing.intentos || 0) + 1
    const bloqueado_hasta = nuevosIntentos >= MAX_INTENTOS
      ? new Date(ahora.getTime() + BLOQUEO_MS).toISOString()
      : null

    await supabase.from('login_attempts').update({
      intentos: nuevosIntentos,
      ultimo_intento: ahora.toISOString(),
      bloqueado_hasta
    }).eq('email', email.toLowerCase())

    return nuevosIntentos >= MAX_INTENTOS
  } else {
    await supabase.from('login_attempts').insert({
      email: email.toLowerCase(),
      intentos: 1,
      ultimo_intento: ahora.toISOString()
    })
    return false
  }
}

/**
 * Verifica si un email está bloqueado por demasiados intentos
 * Retorna { bloqueado: bool, minutos_restantes: number }
 */
export async function verificarBloqueo(email) {
  const { data } = await supabase
    .from('login_attempts')
    .select('bloqueado_hasta, intentos')
    .eq('email', email.toLowerCase())
    .single()

  if (!data || !data.bloqueado_hasta) return { bloqueado: false }

  const ahora      = new Date()
  const hasta      = new Date(data.bloqueado_hasta)
  const bloqueado  = hasta > ahora

  if (!bloqueado) return { bloqueado: false }

  const minutos = Math.ceil((hasta - ahora) / 60000)
  return { bloqueado: true, minutos_restantes: minutos }
}

/**
 * Limpia los intentos fallidos de un email (login exitoso)
 */
export async function limpiarIntentos(email) {
  await supabase
    .from('login_attempts')
    .delete()
    .eq('email', email.toLowerCase())
}


// ============================================================
// AUDIT LOG
// ============================================================

/**
 * Registra una acción en el audit_log
 * Llamar desde vendedor y admin tras cualquier cambio importante
 */
export async function registrarAuditoria({ accion, tabla, registroId, datosAnteriores, datosNuevos }) {
  const user = await getUser()
  if (!user) return

  await supabase.from('audit_log').insert({
    actor_id:         user.id,
    accion,
    tabla_afectada:   tabla,
    registro_id:      registroId || null,
    datos_anteriores: datosAnteriores || null,
    datos_nuevos:     datosNuevos || null
  })
}


// ============================================================
// UTILIDADES UI (compartidas en todas las páginas)
// ============================================================

/**
 * Muestra un mensaje de error en pantalla
 * Busca un elemento con id="mensaje-error" en el HTML
 */
export function mostrarError(texto) {
  const el = document.getElementById('mensaje-error')
  if (el) {
    el.textContent = texto
    el.style.display = 'block'
  }
}

/**
 * Muestra un mensaje de éxito en pantalla
 * Busca un elemento con id="mensaje-exito" en el HTML
 */
export function mostrarExito(texto) {
  const el = document.getElementById('mensaje-exito')
  if (el) {
    el.textContent = texto
    el.style.display = 'block'
  }
}

/**
 * Oculta todos los mensajes de estado
 */
export function limpiarMensajes() {
  const error  = document.getElementById('mensaje-error')
  const exito  = document.getElementById('mensaje-exito')
  if (error) error.style.display = 'none'
  if (exito) exito.style.display = 'none'
}

/**
 * Formatea una fecha ISO a formato legible en español
 */
export function formatearFecha(isoString) {
  if (!isoString) return '—'
  return new Date(isoString).toLocaleDateString('es-ES', {
    day:   '2-digit',
    month: 'long',
    year:  'numeric'
  })
}

/**
 * Formatea un número como moneda
 */
export function formatearMoneda(numero) {
  return new Intl.NumberFormat('es-ES', {
    style:    'currency',
    currency: 'USD'
  }).format(numero)
}
