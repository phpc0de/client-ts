export interface Env {
  CLIENT_ID: string
  CLIENT_SECRET: string
  ISSUER: string
  JWKS_KID: string
  PRIVATE_JWK_JSON: string
}

type TokenResponse = {
  access_token: string
  id_token: string
  token_type: 'Bearer'
  expires_in: number
}

type JwtPayload = Record<string, unknown> & {
  iss: string
  sub: string
  aud: string
  exp: number
  iat: number
  email?: string
  email_verified?: boolean
}

function b64url(input: ArrayBuffer | string): string {
  const raw = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input)
  let s = ''
  for (let i = 0; i < raw.length; i++) s += String.fromCharCode(raw[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

async function signJwt(payload: JwtPayload, env: Env): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT', kid: env.JWKS_KID || 'authelia-workers-key-v1' }
  const jwk = JSON.parse(env.PRIVATE_JWK_JSON)
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  )

  const encodedHeader = b64url(JSON.stringify(header))
  const encodedPayload = b64url(JSON.stringify(payload))
  const unsigned = `${encodedHeader}.${encodedPayload}`
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(unsigned))
  return `${unsigned}.${b64url(sig)}`
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000)
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
    },
  })
}

function unauthorized(msg = 'unauthorized'): Response {
  return json({ error: msg }, 401)
}

function parseBasicAuth(authHeader: string | null): { id: string; secret: string } | null {
  if (!authHeader || !authHeader.startsWith('Basic ')) return null
  try {
    const decoded = atob(authHeader.slice(6))
    const idx = decoded.indexOf(':')
    if (idx < 0) return null
    return { id: decoded.slice(0, idx), secret: decoded.slice(idx + 1) }
  } catch {
    return null
  }
}

async function handleToken(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405)

  const auth = parseBasicAuth(request.headers.get('authorization'))
  if (!auth) return unauthorized('missing_basic_auth')
  if (auth.id !== env.CLIENT_ID || auth.secret !== env.CLIENT_SECRET) return unauthorized('invalid_client')

  const form = await request.formData()
  const grantType = String(form.get('grant_type') || '')
  if (grantType !== 'client_credentials') return json({ error: 'unsupported_grant_type' }, 400)

  const subject = String(form.get('subject') || 'authelia-workers')
  const audience = String(form.get('audience') || env.CLIENT_ID)
  const email = String(form.get('email') || 'admin@local')

  const iat = nowSec()
  const exp = iat + 3600
  const payload: JwtPayload = {
    iss: env.ISSUER,
    sub: subject,
    aud: audience,
    iat,
    exp,
    email,
    email_verified: true,
  }

  const token = await signJwt(payload, env)
  const out: TokenResponse = {
    access_token: token,
    id_token: token,
    token_type: 'Bearer',
    expires_in: 3600,
  }
  return json(out)
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'authorization,content-type',
        },
      })
    }

    if (url.pathname === '/api/oidc/token') return handleToken(request, env)
    if (url.pathname === '/healthz') return json({ ok: true, mode: 'workers-jwt' })
    return json({ error: 'not_found' }, 404)
  },
}
