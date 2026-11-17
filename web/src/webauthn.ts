export function supportsPasskey() {
  return window.isSecureContext && typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials
}

function fromBase64Url(value: string) {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

function toBase64Url(buffer: ArrayBuffer) {
  const binary = Array.from(new Uint8Array(buffer), (byte) => String.fromCharCode(byte)).join('')
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function serialize(credential: Credential | null) {
  if (!(credential instanceof PublicKeyCredential)) throw new Error('验证器没有返回凭据。')
  if (typeof credential.toJSON === 'function') return credential.toJSON()
  const response = credential.response
  const clientDataJSON = toBase64Url(response.clientDataJSON)
  const common = { id: credential.id, rawId: toBase64Url(credential.rawId), type: credential.type }
  if (response instanceof AuthenticatorAttestationResponse) {
    return { ...common, response: { clientDataJSON, attestationObject: toBase64Url(response.attestationObject) } }
  }
  if (response instanceof AuthenticatorAssertionResponse) {
    return { ...common, response: {
      clientDataJSON,
      authenticatorData: toBase64Url(response.authenticatorData),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle === null ? null : toBase64Url(response.userHandle),
    } }
  }
  throw new Error('验证器返回了未知凭据。')
}

export async function createPasskey(options: PublicKeyCredentialCreationOptionsJSON) {
  if (!supportsPasskey()) throw new Error('当前浏览器或地址不支持 Passkey。')
  const publicKey = typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function'
    ? PublicKeyCredential.parseCreationOptionsFromJSON(options)
    : {
      rp: options.rp,
      user: { ...options.user, id: fromBase64Url(options.user.id) },
      challenge: fromBase64Url(options.challenge),
      pubKeyCredParams: options.pubKeyCredParams,
      excludeCredentials: options.excludeCredentials?.map(({ id }) => ({ id: fromBase64Url(id), type: 'public-key' as const })),
      authenticatorSelection: options.authenticatorSelection,
      timeout: options.timeout,
      attestation: 'none' as const,
    }
  return serialize(await navigator.credentials.create({ publicKey }))
}

export async function getPasskey(options: PublicKeyCredentialRequestOptionsJSON) {
  if (!supportsPasskey()) throw new Error('当前浏览器或地址不支持 Passkey。')
  const publicKey = typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function'
    ? PublicKeyCredential.parseRequestOptionsFromJSON(options)
    : {
      challenge: fromBase64Url(options.challenge),
      rpId: options.rpId,
      timeout: options.timeout,
      userVerification: 'required' as const,
    }
  return serialize(await navigator.credentials.get({ publicKey }))
}
