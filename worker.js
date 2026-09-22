/**
 * worker.js
 * ----------------------------------------------------------------------------
 * Pure-JS/WebCrypto verification core for a client-side ZIP password
 * recovery prototype. Runs inside a Web Worker so the main thread never
 * blocks. Contains no ZIP decompression — it only performs the cheap
 * cryptographic *check* that lets a candidate be accepted/rejected without
 * inflating the stream.
 *
 * Message protocol (structured-clone friendly):
 *
 *   -> { type: 'init', scheme: 'zipcrypto'|'aes', header, aes? }
 *        header.passwordVerification : ArrayBuffer  (1B zipcrypto | 2B aes)
 *        header.zipCryptoHeader       : ArrayBuffer  (12B, zipcrypto only)
 *        header.useTimeByteCheck      : boolean
 *        header._lastModTimeHighByte  : number
 *        aes.salt                     : ArrayBuffer  (8/12/16B, aes only)
 *        aes.keyBytes                 : 16|24|32
 *
 *   -> { type: 'batch', mode: 'dictionary'|'mask', candidates: string[] }
 *        For 'mask' mode, `candidates` is a pre-expanded batch of concrete
 *        strings produced by the caller's mask-expansion generator; this
 *        module stays generator-agnostic and only ever tests flat batches.
 *
 *   <- { type: 'match', password: string }
 *   <- { type: 'rate',  testedCount: number, elapsedMs: number, hashRate: number }
 *   <- { type: 'done' }  // batch exhausted, no match
 */

// ============================================================================
// Shared hot-path scratch buffers (allocated once, reused every candidate —
// V8/JIT hates allocation churn inside a tight loop far more than it minds
// mutation of pre-sized typed arrays).
// ============================================================================

const textEncoder = new TextEncoder();

/** @type {Uint8Array} reusable UTF-8 encode scratch, grown on demand only */
let encodeScratch = new Uint8Array(64);

/**
 * Encodes `str` as UTF-8 into the shared scratch buffer without allocating,
 * unless the string is longer than the current scratch capacity.
 * @param {string} str
 * @returns {{buf: Uint8Array, len: number}} view into encodeScratch[0..len)
 */
function encodeInPlace(str) {
  // Fast path estimate; UTF-8 worst case is 3x UTF-16 code unit count.
  const worstCase = str.length * 3;
  if (worstCase > encodeScratch.length) {
    encodeScratch = new Uint8Array(worstCase);
  }
  const { written } = textEncoder.encodeInto(str, encodeScratch);
  return { buf: encodeScratch, len: written };
}

// ============================================================================
// CRC32 table (used both as the CRC-update primitive inside ZipCrypto's
// keystream, and, if ever validating full-stream CRC, standalone).
// ============================================================================

/** @type {Uint32Array} precomputed CRC32 lookup table (poly 0xEDB88320) */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

/**
 * Single-byte CRC32 update step: crc' = table[(crc ^ byte) & 0xFF] ^ (crc >>> 8)
 * This exact primitive is reused, unmodified, as ZipCrypto's Key0 update
 * function (PKWARE APPNOTE §6.1.5, "crc32(crc, byte)").
 * @param {number} crc  current CRC32 accumulator (uint32)
 * @param {number} byte input byte (0-255)
 * @returns {number} updated CRC32 accumulator (uint32)
 */
function crc32Update(crc, byte) {
  return (CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8)) >>> 0;
}

// ============================================================================
// ZipCrypto (Traditional PKWARE encryption) — PKWARE APPNOTE.TXT §6.1
//
// Internal state: three 32-bit registers Key0, Key1, Key2, updated per
// plaintext byte via a CRC32 shift (Key0, Key2) and a linear congruential
// multiply-add (Key1). This is a stream cipher: keystream byte is derived
// from Key2, XORed with ciphertext to recover plaintext.
//
//   Key0 = crc32(Key0, P)
//   Key1 = (Key1 + (Key0 & 0xFF)) * 134775813 + 1        (mod 2^32, LCG)
//   Key2 = crc32(Key2, Key1 >>> 24)
//   keystreamByte = ((Key2 | 2) * (Key2 ^ (Key2-1))) >>> 8  & 0xFF   ("decrypt byte")
//
// Verification exploits the 12-byte encryption header prepended to every
// ZipCrypto stream: after decrypting all 12 header bytes with a candidate
// key schedule, the LAST decrypted byte must equal either:
//   - the high byte of the entry's CRC32 (flag bit 3 clear), or
//   - the high byte of the DOS last-mod-time field (flag bit 3 set,
//     i.e. a trailing data descriptor was used instead of a known CRC).
// A 1-in-256 false-positive rate is expected and acceptable for a fast
// pre-filter; a full decompress+CRC check on genuine candidates is the
// caller's responsibility outside the hot loop.
// ============================================================================

const LCG_MULTIPLIER = 134775813;

/**
 * Derives the initial ZipCrypto 3-key state from a password, per
 * APPNOTE §6.1.4. Constant per candidate; O(password length).
 * @param {Uint8Array} passwordBytes
 * @returns {[number, number, number]} [Key0, Key1, Key2]
 */
function zipCryptoInitKeys(passwordBytes) {
  let key0 = 0x12345678;
  let key1 = 0x23456789;
  let key2 = 0x34567890;

  for (let i = 0; i < passwordBytes.length; i++) {
    const b = passwordBytes[i];
    key0 = crc32Update(key0, b);
    key1 = (Math.imul((key1 + (key0 & 0xff)) >>> 0, LCG_MULTIPLIER) + 1) >>> 0;
    key2 = crc32Update(key2, key1 >>> 24);
  }
  return [key0, key1, key2];
}

/**
 * Computes the next ZipCrypto keystream byte from Key2, then advances all
 * three keys using the just-decrypted plaintext byte `p` (APPNOTE §6.1.5).
 * Mutates and returns the updated key triple in-place via the passed array
 * to avoid per-call allocation.
 * @param {[number, number, number]} keys  [Key0, Key1, Key2], mutated in place
 * @param {number} cipherByte              ciphertext byte to decrypt (0-255)
 * @returns {number} decrypted plaintext byte (0-255)
 */
function zipCryptoDecryptByte(keys, cipherByte) {
  let [key0, key1, key2] = keys;

  const temp = (key2 | 2) >>> 0;
  const keystream = (Math.imul(temp, temp ^ 1) >>> 8) & 0xff;
  const plainByte = cipherByte ^ keystream;

  key0 = crc32Update(key0, plainByte);
  key1 = (Math.imul((key1 + (key0 & 0xff)) >>> 0, LCG_MULTIPLIER) + 1) >>> 0;
  key2 = crc32Update(key2, key1 >>> 24);

  keys[0] = key0;
  keys[1] = key1;
  keys[2] = key2;

  return plainByte;
}

/**
 * Tests one candidate password against a ZipCrypto encryption header.
 * Only decrypts the 12-byte header (never touches the ciphertext body),
 * making this an O(password length + 12) check per candidate.
 *
 * @param {Uint8Array} passwordBytes
 * @param {Uint8Array} encHeader12          the 12-byte ZipCrypto encryption header
 * @param {number} expectedCheckByte        high byte of CRC32, or DOS-time high byte
 * @returns {boolean} true if the last decrypted header byte matches
 */
function zipCryptoCheck(passwordBytes, encHeader12, expectedCheckByte) {
  const keys = zipCryptoInitKeys(passwordBytes);
  let lastByte = 0;
  // Header is always exactly 12 bytes; unrolled-friendly fixed loop.
  for (let i = 0; i < 12; i++) {
    lastByte = zipCryptoDecryptByte(keys, encHeader12[i]);
  }
  return lastByte === expectedCheckByte;
}

// ============================================================================
// WinZip AES (AE-1/AE-2) — WinZip AES Encryption Information spec
//
// Key material is derived via PBKDF2-HMAC-SHA1 over the UTF-8 password,
// salted with the per-file random salt, for 1000 iterations, producing:
//   keyBytes            -> AES decryption key (16/24/32 bytes)
//   keyBytes            -> HMAC-SHA1 authentication key (same length)
//   2 bytes              -> password verification value
// i.e. derivedLength = 2*keyBytes + 2, taken from a single PBKDF2 call.
//
// Verification compares the trailing 2 derived bytes against the 2-byte
// "password verification value" stored immediately after the salt in the
// file data — a fast, allocation-light rejection test that avoids ever
// running full AES-CTR decryption or HMAC-SHA1-96 stream authentication
// on wrong candidates (1-in-65536 false-positive rate, which is why a
// genuine hit should still be confirmed via the full HMAC trailer at the
// application layer before being reported as final).
// ============================================================================

/**
 * Derives PBKDF2(password, salt, 1000, SHA-1, 2*keyBytes+2) via WebCrypto
 * and returns only the trailing 2-byte password verification value.
 * WebCrypto's PBKDF2 is used instead of a hand-rolled HMAC loop because
 * it is natively implemented (fast) and this is the one part of the hot
 * loop that legitimately benefits from being async/offloaded internally.
 *
 * @param {Uint8Array} passwordBytes
 * @param {ArrayBuffer} salt
 * @param {number} keyBytes  16 | 24 | 32
 * @returns {Promise<Uint8Array>} 2-byte verifier
 */
async function aesDeriveVerifier(passwordBytes, salt, keyBytes) {
  const derivedBits = (2 * keyBytes + 2) * 8;

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: 1000,
      hash: 'SHA-1',
    },
    keyMaterial,
    derivedBits
  );

  // Verifier is the final 2 bytes of the derived block.
  return new Uint8Array(derived, derived.byteLength - 2, 2);
}

/**
 * Tests one candidate password against an AES entry's stored 2-byte
 * verification value.
 * @param {Uint8Array} passwordBytes
 * @param {ArrayBuffer} salt
 * @param {number} keyBytes
 * @param {Uint8Array} expectedVerifier  2 bytes, from the ZIP entry
 * @returns {Promise<boolean>}
 */
async function aesCheck(passwordBytes, salt, keyBytes, expectedVerifier) {
  const derivedVerifier = await aesDeriveVerifier(passwordBytes, salt, keyBytes);
  return derivedVerifier[0] === expectedVerifier[0] && derivedVerifier[1] === expectedVerifier[1];
}

// ============================================================================
// RAR3 — Pure-JS SHA-1 (incremental, cloneable) for custom KDF
// ============================================================================

function _sha1Block(H, buf) {
  const W = new Uint32Array(80);
  for (let i = 0; i < 16; i++)
    W[i] = (buf[i*4]<<24)|(buf[i*4+1]<<16)|(buf[i*4+2]<<8)|buf[i*4+3];
  for (let i = 16; i < 80; i++) {
    const x = W[i-3]^W[i-8]^W[i-14]^W[i-16];
    W[i] = (x<<1)|(x>>>31);
  }
  let [a,b,c,d,e] = H;
  for (let t = 0; t < 80; t++) {
    const s = t < 20 ? 0 : t < 40 ? 1 : t < 60 ? 2 : 3;
    const K = [0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xCA62C1D6][s];
    const f = s===0 ? (b&c)|(~b&d) : s===2 ? (b&c)|(b&d)|(c&d) : b^c^d;
    const T = (((a<<5)|(a>>>27))+f+e+K+W[t])>>>0;
    e=d; d=c; c=(b<<30)|(b>>>2); b=a; a=T;
  }
  H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0;
  H[3]=(H[3]+d)>>>0; H[4]=(H[4]+e)>>>0;
}

class Sha1 {
  constructor() {
    this.H = new Uint32Array([0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]);
    this._buf = new Uint8Array(64); this._len = 0; this._total = 0;
  }
  update(data) {
    let off = 0;
    while (off < data.length) {
      const n = Math.min(64 - this._len, data.length - off);
      this._buf.set(data.subarray(off, off + n), this._len);
      this._len += n; this._total += n; off += n;
      if (this._len === 64) { _sha1Block(this.H, this._buf); this._len = 0; }
    }
  }
  clone() {
    const c = new Sha1(); c.H.set(this.H); c._buf.set(this._buf); c._len=this._len; c._total=this._total; return c;
  }
  digest() { return this.clone()._fin(); }
  _fin() {
    this._buf[this._len++] = 0x80;
    if (this._len > 56) { while (this._len<64) this._buf[this._len++]=0; _sha1Block(this.H,this._buf); this._len=0; }
    while (this._len < 56) this._buf[this._len++] = 0;
    const bits = this._total * 8;
    const hi = Math.floor(bits / 0x100000000) >>> 0, lo = bits >>> 0;
    this._buf[56]=(hi>>>24)&0xFF; this._buf[57]=(hi>>>16)&0xFF; this._buf[58]=(hi>>>8)&0xFF; this._buf[59]=hi&0xFF;
    this._buf[60]=(lo>>>24)&0xFF; this._buf[61]=(lo>>>16)&0xFF; this._buf[62]=(lo>>>8)&0xFF; this._buf[63]=lo&0xFF;
    _sha1Block(this.H, this._buf);
    const out = new Uint8Array(20);
    for (let i=0;i<5;i++) { out[i*4]=(this.H[i]>>>24)&0xFF; out[i*4+1]=(this.H[i]>>>16)&0xFF; out[i*4+2]=(this.H[i]>>>8)&0xFF; out[i*4+3]=this.H[i]&0xFF; }
    return out;
  }
}

/**
 * RAR3 key derivation: custom SHA-1 KDF (262144 iterations).
 * Password is UTF-16LE encoded. Produces {key:Uint8Array(16), iv:Uint8Array(16)}.
 * @param {string} password
 * @param {Uint8Array} salt8
 */
function rar3DeriveKey(password, salt8) {
  const pwBuf = new Uint8Array(password.length * 2);
  for (let i = 0; i < password.length; i++) {
    const c = password.charCodeAt(i);
    pwBuf[i*2] = c & 0xFF; pwBuf[i*2+1] = (c >> 8) & 0xFF;
  }
  const sha = new Sha1();
  const iv  = new Uint8Array(16);
  const ctr = new Uint8Array(3);
  for (let i = 0; i < 0x40000; i++) {
    sha.update(pwBuf); sha.update(salt8);
    ctr[0]=i&0xFF; ctr[1]=(i>>8)&0xFF; ctr[2]=(i>>16)&0xFF;
    sha.update(ctr);
    if ((i & 0x3FFF) === 0x3FFF) iv[i >>> 14] = sha.digest()[19];
  }
  const key = sha.digest().slice(0, 16);
  return { key, iv };
}

// ============================================================================
// RAR3 — Pure-JS AES-128 ECB decrypt (for CBC first-block verification)
// AES S-boxes and key schedule — avoids WebCrypto PKCS#7 padding rejection
// ============================================================================

/* jshint ignore:start */
const _SB = new Uint8Array([99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22]);
const _IS = new Uint8Array([82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125]);
const _RC = new Uint8Array([1,2,4,8,16,32,64,128,27,54]);
/* jshint ignore:end */

function _gfm(a,b) { let r=0; while(b){if(b&1)r^=a; a=((a<<1)^(a&0x80?0x1b:0))&0xFF; b>>>=1;} return r; }

function _aesKS(k) {
  const w = new Uint32Array(44);
  for (let i=0;i<4;i++) w[i]=(k[i*4]<<24)|(k[i*4+1]<<16)|(k[i*4+2]<<8)|k[i*4+3];
  for (let i=4;i<44;i++) {
    let t=w[i-1];
    if (i%4===0) {
      t=((t<<8)|(t>>>24))>>>0;
      t=((_SB[(t>>>24)&0xFF]<<24)|(_SB[(t>>>16)&0xFF]<<16)|(_SB[(t>>>8)&0xFF]<<8)|_SB[t&0xFF])>>>0;
      t^=(_RC[i/4-1]<<24)>>>0;
    }
    w[i]=(w[i-4]^t)>>>0;
  }
  return w;
}

/** AES-128 ECB decrypt one 16-byte block (column-major state). */
function _aesEcbDec(ct, w) {
  const s = new Uint8Array(ct); // copy
  // Initial AddRoundKey (round 10)
  for (let c=0;c<4;c++) { const rk=w[40+c]; s[c*4]^=(rk>>>24)&0xFF; s[c*4+1]^=(rk>>>16)&0xFF; s[c*4+2]^=(rk>>>8)&0xFF; s[c*4+3]^=rk&0xFF; }
  for (let r=9;r>=1;r--) {
    // InvShiftRows
    let t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
    // InvSubBytes
    for (let i=0;i<16;i++) s[i]=_IS[s[i]];
    // AddRoundKey
    for (let c=0;c<4;c++) { const rk=w[r*4+c]; s[c*4]^=(rk>>>24)&0xFF; s[c*4+1]^=(rk>>>16)&0xFF; s[c*4+2]^=(rk>>>8)&0xFF; s[c*4+3]^=rk&0xFF; }
    // InvMixColumns
    for (let c=0;c<4;c++) {
      const [a,b,cv,d]=[s[c*4],s[c*4+1],s[c*4+2],s[c*4+3]];
      s[c*4]  =_gfm(a,14)^_gfm(b,11)^_gfm(cv,13)^_gfm(d,9);
      s[c*4+1]=_gfm(a,9)^_gfm(b,14)^_gfm(cv,11)^_gfm(d,13);
      s[c*4+2]=_gfm(a,13)^_gfm(b,9)^_gfm(cv,14)^_gfm(d,11);
      s[c*4+3]=_gfm(a,11)^_gfm(b,13)^_gfm(cv,9)^_gfm(d,14);
    }
  }
  // Final round
  let t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
  t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
  t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
  for (let i=0;i<16;i++) s[i]=_IS[s[i]];
  for (let c=0;c<4;c++) { const rk=w[c]; s[c*4]^=(rk>>>24)&0xFF; s[c*4+1]^=(rk>>>16)&0xFF; s[c*4+2]^=(rk>>>8)&0xFF; s[c*4+3]^=rk&0xFF; }
  return s;
}

/**
 * Check one RAR3 password candidate against a 16-byte encrypted block.
 * Decrypts first block using AES-128-CBC (pure-JS) and validates the
 * decrypted header block type (RAR3 block types 0x72–0x7B).
 * False-positive rate ≈ 10/256 ≈ 4%; caller should confirm matches.
 *
 * @param {string}     password
 * @param {Uint8Array} salt8
 * @param {Uint8Array} firstBlock16
 * @returns {boolean}
 */
function rar3Check(password, salt8, firstBlock16) {
  const { key, iv } = rar3DeriveKey(password, salt8);
  const rk = _aesKS(key);
  const ecb = _aesEcbDec(firstBlock16, rk);
  // CBC XOR with IV
  const plain = new Uint8Array(16);
  for (let i = 0; i < 16; i++) plain[i] = ecb[i] ^ iv[i];
  // Validate: byte[2] must be a valid RAR3 block type
  const t = plain[2];
  return t >= 0x72 && t <= 0x7B;
}

// ============================================================================
// RAR5 — WebCrypto PBKDF2-SHA-256 password check
// Derived key layout: [0..31]=AES key, [32..63]=HMAC key, [64..71]=pw check
// ============================================================================

/**
 * Check one RAR5 password candidate against the 8-byte check value.
 * Uses PBKDF2-HMAC-SHA-256 with 2^kdfCount iterations, derives 72 bytes.
 * Bytes [64..71] are the stored password verification value.
 *
 * @param {Uint8Array}       passwordBytes  UTF-8 encoded
 * @param {ArrayBuffer}      salt16
 * @param {number}           kdfCount       iterations = 2^kdfCount
 * @param {Uint8Array}       expected8      8-byte check value from header
 * @returns {Promise<boolean>}
 */
async function rar5Check(passwordBytes, salt16, kdfCount, expected8) {
  const iterations = Math.max(1, 1 << kdfCount);
  const km = await crypto.subtle.importKey('raw', passwordBytes, { name: 'PBKDF2' }, false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt16, iterations, hash: 'SHA-256' },
    km,
    72 * 8 // 72 bytes = 576 bits
  );
  const d = new Uint8Array(derived);
  for (let i = 0; i < 8; i++) if (d[64 + i] !== expected8[i]) return false;
  return true;
}

// ============================================================================
// Worker state + message loop
// ============================================================================

/** @type {'zipcrypto'|'aes'|'rar3'|'rar5'|null} */
let scheme = null;

// ZipCrypto session state
let zcHeader = null;          // Uint8Array(12)
let zcExpectedCheckByte = 0;  // number

// ZIP-AES session state
let aesSalt = null;           // ArrayBuffer
let aesKeyBytes = 0;          // number
let aesExpectedVerifier = null; // Uint8Array(2)

// RAR3 session state
let rar3Salt = null;          // Uint8Array(8)
let rar3FirstBlock = null;    // Uint8Array(16)

// RAR5 session state
let rar5Salt = null;          // ArrayBuffer
let rar5KdfCount = 0;         // number
let rar5Check8 = null;        // Uint8Array(8)

const RATE_REPORT_INTERVAL_MS = 250;

self.onmessage = async function handleMessage(event) {
  const msg = event.data;

  if (msg.type === 'init') {
    scheme = msg.scheme;

    if (scheme === 'zipcrypto') {
      zcHeader = new Uint8Array(msg.header.zipCryptoHeader);
      zcExpectedCheckByte = msg.header.useTimeByteCheck
        ? msg.header._lastModTimeHighByte
        : new Uint8Array(msg.header.passwordVerification)[0];
    } else if (scheme === 'aes') {
      aesSalt = msg.aes.salt;
      aesKeyBytes = msg.aes.keyBytes;
      aesExpectedVerifier = new Uint8Array(msg.header.passwordVerification);
    } else if (scheme === 'rar3') {
      rar3Salt       = new Uint8Array(msg.rar3.salt);
      rar3FirstBlock = new Uint8Array(msg.rar3.firstBlock);
    } else if (scheme === 'rar5') {
      rar5Salt     = msg.rar5.salt;
      rar5KdfCount = msg.rar5.kdfCount;
      rar5Check8   = new Uint8Array(msg.rar5.checkValue);
    } else {
      throw new Error(`Unknown scheme: ${scheme}`);
    }
    return;
  }

  if (msg.type === 'batch') {
    await runBatch(msg.candidates);
    return;
  }
};

/**
 * Runs a flat batch of candidate strings through the appropriate checker.
 * @param {string[]} candidates
 */
async function runBatch(candidates) {
  const startTime = performance.now();
  let lastReportTime = startTime;
  let testedSinceReport = 0;
  let totalTested = 0;

  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i];
    const { buf, len } = encodeInPlace(candidate);
    const passwordBytes = buf.subarray(0, len);

    let isMatch;
    if (scheme === 'zipcrypto') {
      isMatch = zipCryptoCheck(passwordBytes, zcHeader, zcExpectedCheckByte);
    } else if (scheme === 'aes') {
      isMatch = await aesCheck(passwordBytes, aesSalt, aesKeyBytes, aesExpectedVerifier);
    } else if (scheme === 'rar3') {
      // RAR3 KDF is CPU-intensive; not async but still yields via rate reports
      isMatch = rar3Check(candidate, rar3Salt, rar3FirstBlock);
    } else if (scheme === 'rar5') {
      isMatch = await rar5Check(passwordBytes, rar5Salt, rar5KdfCount, rar5Check8);
    } else {
      isMatch = false;
    }

    totalTested++;
    testedSinceReport++;

    if (isMatch) {
      self.postMessage({ type: 'match', password: candidate });
    }

    const now = performance.now();
    if (now - lastReportTime >= RATE_REPORT_INTERVAL_MS) {
      const elapsedMs = now - lastReportTime;
      self.postMessage({
        type: 'rate',
        testedCount: totalTested,
        elapsedMs,
        hashRate: (testedSinceReport / elapsedMs) * 1000,
      });
      lastReportTime = now;
      testedSinceReport = 0;
    }
  }

  const totalElapsedMs = performance.now() - startTime;
  self.postMessage({
    type: 'rate',
    testedCount: totalTested,
    elapsedMs: totalElapsedMs,
    hashRate: (totalTested / totalElapsedMs) * 1000,
  });
  self.postMessage({ type: 'done' });
}

export {
  crc32Update,
  zipCryptoInitKeys,
  zipCryptoDecryptByte,
  zipCryptoCheck,
  aesDeriveVerifier,
  aesCheck,
  rar3DeriveKey,
  rar3Check,
  rar5Check,
};
