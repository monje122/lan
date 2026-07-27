const RESEND_ENDPOINT = 'https://api.resend.com/emails';
const TURNSTILE_VERIFY_ENDPOINT = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const MAX_PDF_BASE64_LENGTH = 8_000_000;

// Datos públicos ya configurados para Goldenpro.Ven.
const DEFAULT_OWNER_EMAIL = 'goldenpro.ven@gmail.com';
const DEFAULT_FROM_EMAIL = 'Goldenpro.Ven <constancias@sistemabingo75.online>';
const DEFAULT_REPLY_TO_EMAIL = 'goldenpro.ven@gmail.com';
const DEFAULT_ALLOWED_ORIGINS = 'https://sistemabingo75.online,https://www.sistemabingo75.online';
const DEFAULT_TURNSTILE_ALLOWED_HOSTNAMES = 'sistemabingo75.online,www.sistemabingo75.online';

function json(data, status = 200, origin = '') {
  const headers = {
    'Content-Type': 'application/json; charset=UTF-8',
    'Cache-Control': 'no-store',
    'Vary': 'Origin'
  };
  if (origin) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type';
  }
  return new Response(JSON.stringify(data), {status, headers});
}

function getAllowedOrigin(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = String(env.ALLOWED_ORIGINS || DEFAULT_ALLOWED_ORIGINS)
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);
  return allowed.includes(origin) ? origin : '';
}

function clean(value, max = 250) {
  return String(value || '').replace(/[<>]/g, '').trim().slice(0, max);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, character => ({
    '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;'
  })[character]);
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ''));
}

async function verifyTurnstile(request, env, token) {
  const form = new FormData();
  form.append('secret', env.TURNSTILE_SECRET_KEY);
  form.append('response', token);
  const ip = request.headers.get('CF-Connecting-IP');
  if (ip) form.append('remoteip', ip);

  const response = await fetch(TURNSTILE_VERIFY_ENDPOINT, {method:'POST', body:form});
  const result = await response.json();
  if (!result.success) return {ok:false, error:'No fue posible validar la verificación de seguridad.'};
  const allowedHostnames = String(env.TURNSTILE_ALLOWED_HOSTNAME || DEFAULT_TURNSTILE_ALLOWED_HOSTNAMES)
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);
  if (allowedHostnames.length && !allowedHostnames.includes(result.hostname)) {
    return {ok:false, error:'La verificación de seguridad proviene de un dominio no autorizado.'};
  }
  return {ok:true};
}

async function sendEmail(env, {to, subject, html, attachmentContent, filename, idempotencyKey}) {
  const fromEmail = env.FROM_EMAIL || DEFAULT_FROM_EMAIL;
  const replyToEmail = env.REPLY_TO_EMAIL || DEFAULT_REPLY_TO_EMAIL;
  const response = await fetch(RESEND_ENDPOINT, {
    method:'POST',
    headers:{
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type':'application/json',
      'Idempotency-Key': idempotencyKey
    },
    body:JSON.stringify({
      from: fromEmail,
      reply_to: replyToEmail,
      to:[to],
      subject,
      html,
      attachments:[{content:attachmentContent, filename}]
    })
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.error('Resend error', response.status, body);
    throw new Error('No se pudo enviar uno de los correos.');
  }
  return body;
}

export default {
  async fetch(request, env) {
    const origin = getAllowedOrigin(request, env);

    if (request.method === 'OPTIONS') {
      if (!origin) return json({ok:false, error:'Origen no autorizado.'}, 403);
      return new Response(null, {
        status:204,
        headers:{
          'Access-Control-Allow-Origin':origin,
          'Access-Control-Allow-Methods':'POST, OPTIONS',
          'Access-Control-Allow-Headers':'Content-Type',
          'Access-Control-Max-Age':'86400',
          'Vary':'Origin'
        }
      });
    }

    if (request.method !== 'POST') return json({ok:false, error:'Método no permitido.'}, 405, origin);
    if (!origin) return json({ok:false, error:'Origen no autorizado.'}, 403);
    if (!env.RESEND_API_KEY || !env.TURNSTILE_SECRET_KEY) {
      return json({ok:false, error:'Faltan las claves privadas de Resend o Turnstile.'}, 500, origin);
    }

    const ownerEmail = env.OWNER_EMAIL || DEFAULT_OWNER_EMAIL;

    const contentLength = Number(request.headers.get('Content-Length') || 0);
    if (contentLength > 9_000_000) return json({ok:false, error:'La constancia excede el tamaño permitido.'}, 413, origin);

    let payload;
    try {
      payload = await request.json();
    } catch {
      return json({ok:false, error:'Solicitud inválida.'}, 400, origin);
    }

    const turnstileToken = clean(payload.turnstileToken, 3000);
    if (!turnstileToken) return json({ok:false, error:'Falta la verificación de seguridad.'}, 400, origin);
    const validation = await verifyTurnstile(request, env, turnstileToken);
    if (!validation.ok) return json(validation, 400, origin);

    const data = {
      codigo:clean(payload.codigo, 80),
      nombre:clean(payload.nombre, 120),
      documento:clean(payload.documento, 80),
      telefono:clean(payload.telefono, 60),
      correo:clean(payload.correo, 160).toLowerCase(),
      planTitulo:clean(payload.planTitulo, 100),
      planDetalle:clean(payload.planDetalle, 300),
      fechaLocal:clean(payload.fechaLocal, 150),
      fechaISO:clean(payload.fechaISO, 80),
      huella:clean(payload.huella, 128),
      versionTerminos:clean(payload.versionTerminos, 80),
      pdfBase64:String(payload.pdfBase64 || '')
    };

    const required = ['codigo','nombre','documento','telefono','correo','planTitulo','planDetalle','fechaISO','huella','pdfBase64'];
    if (required.some(key => !data[key])) return json({ok:false, error:'Faltan datos obligatorios de la constancia.'}, 400, origin);
    if (!validEmail(data.correo)) return json({ok:false, error:'El correo del comprador no es válido.'}, 400, origin);
    if (!validEmail(ownerEmail)) return json({ok:false, error:'El correo administrativo no está bien configurado.'}, 500, origin);
    if (!/^[A-Za-z0-9+/=]+$/.test(data.pdfBase64) || data.pdfBase64.length > MAX_PDF_BASE64_LENGTH) {
      return json({ok:false, error:'El archivo PDF no es válido o excede el tamaño permitido.'}, 400, origin);
    }

    const safe = Object.fromEntries(Object.entries(data).filter(([key]) => key !== 'pdfBase64').map(([key, value]) => [key, escapeHtml(value)]));
    const filename = `Constancia_${data.codigo.replace(/[^A-Za-z0-9_-]/g, '')}.pdf`;
    const summary = `
      <div style="font-family:Arial,sans-serif;color:#17203b;line-height:1.55;max-width:680px;margin:auto">
        <div style="background:#07104e;color:white;padding:22px;border-radius:14px 14px 0 0">
          <div style="font-size:24px;font-weight:900;color:#ffd100">GOLDENPRO.VEN</div>
          <div>Constancia de solicitud y aceptación electrónica</div>
        </div>
        <div style="border:1px solid #d9deea;border-top:0;padding:22px;border-radius:0 0 14px 14px">
          <p>Se adjunta la misma constancia firmada que fue generada antes de continuar al pago.</p>
          <table style="width:100%;border-collapse:collapse">
            <tr><td style="padding:7px;font-weight:bold">Código</td><td style="padding:7px">${safe.codigo}</td></tr>
            <tr><td style="padding:7px;font-weight:bold">Comprador</td><td style="padding:7px">${safe.nombre}</td></tr>
            <tr><td style="padding:7px;font-weight:bold">Cédula/RIF</td><td style="padding:7px">${safe.documento}</td></tr>
            <tr><td style="padding:7px;font-weight:bold">Correo</td><td style="padding:7px">${safe.correo}</td></tr>
            <tr><td style="padding:7px;font-weight:bold">Plan</td><td style="padding:7px">${safe.planTitulo}</td></tr>
            <tr><td style="padding:7px;font-weight:bold">Condición</td><td style="padding:7px">${safe.planDetalle}</td></tr>
            <tr><td style="padding:7px;font-weight:bold">Fecha</td><td style="padding:7px">${safe.fechaLocal}</td></tr>
            <tr><td style="padding:7px;font-weight:bold">Versión de términos</td><td style="padding:7px">${safe.versionTerminos}</td></tr>
          </table>
          <p style="background:#effaf3;border-left:5px solid #1f9d55;padding:12px"><strong>Aceptación:</strong> el comprador marcó las cinco confirmaciones, asumió expresamente la responsabilidad del organizador y trazó su firma electrónica antes del pago.</p>
          <p style="font-size:12px;color:#5f6676">Esta constancia no acredita por sí sola el pago. Conserve este correo, el PDF adjunto, los comprobantes y las conversaciones relacionadas.</p>
          <p style="font-size:12px;color:#5f6676">Contacto: goldenpro.ven@gmail.com · sistemabingo75.online</p>
        </div>
      </div>`;

    const subject = `Constancia Goldenpro.Ven ${data.codigo}`;
    try {
      const [buyer, owner] = await Promise.all([
        sendEmail(env, {
          to:data.correo,
          subject,
          html:`<p>Hola ${safe.nombre},</p>${summary}`,
          attachmentContent:data.pdfBase64,
          filename,
          idempotencyKey:`goldenpro-comprador-${data.codigo}`.slice(0, 256)
        }),
        sendEmail(env, {
          to:ownerEmail,
          subject:`Nueva solicitud - ${subject}`,
          html:`<p>Se recibió una nueva solicitud firmada.</p>${summary}`,
          attachmentContent:data.pdfBase64,
          filename,
          idempotencyKey:`goldenpro-propietario-${data.codigo}`.slice(0, 256)
        })
      ]);
      return json({ok:true, buyerEmailId:buyer.id || null, ownerEmailId:owner.id || null, codigo:data.codigo}, 200, origin);
    } catch (error) {
      console.error(error);
      return json({ok:false, error:'No se pudieron entregar ambos correos. Intenta nuevamente.'}, 502, origin);
    }
  }
};
