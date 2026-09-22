/**
 * zip-parser.js
 * ----------------------------------------------------------------------------
 * Parses a ZIP "Local File Header" (LFH) directly from an ArrayBuffer to
 * determine the encryption scheme in use and extract the exact byte ranges
 * needed for offline password verification (no external calls, no full
 * decompression).
 *
 * ZIP Local File Header layout (PKWARE APPNOTE.TXT §4.3.7), all fields LE:
 *
 *   offset  size  field
 *   0       4     signature (0x04034b50)
 *   4       2     version needed
 *   6       2     general purpose bit flag   <- bit 0 = encrypted
 *   8       2     compression method          20 (0x14) => AES-encrypted stub
 *   10      2     last mod time
 *   12      2     last mod date
 *   14      4     crc32                       (0 if bit 3 set: data descriptor)
 *   18      4     compressed size
 *   22      4     uncompressed size
 *   26      2     file name length (n)
 *   28      2     extra field length (m)
 *   30      n     file name
 *   30+n    m     extra field                 <- 0x9901 AES extra block lives here
 *   30+n+m  ...    file data (encryption header + ciphertext)
 *
 * Traditional PKWARE (ZipCrypto) file data:
 *   [0..11]  12-byte encryption header (last byte is a 1-byte password check)
 *   [12..]   ciphertext
 *
 * WinZip AES (AE-1 / AE-2) file data (APPNOTE §strong encryption / WinZip spec):
 *   [0..S-1]     salt, S = 8 (AES-128) | 12 (AES-192) | 16 (AES-256)
 *   [S..S+1]     2-byte password verification value
 *   [S+2..]      ciphertext
 *   [end-10..]   10-byte HMAC-SHA1-96 authentication code (trailer, not header)
 */

const LFH_SIGNATURE = 0x04034b50;

/** @typedef {'none'|'zipcrypto'|'aes'} EncryptionScheme */

/**
 * @typedef {Object} ParsedEntry
 * @property {EncryptionScheme} scheme
 * @property {number} compressionMethod        - raw method field (99 = AES stub)
 * @property {number} aesStrength               - 1=128,2=192,3=256 (aes only)
 * @property {number} aesKeyBytes                - 16/24/32 (aes only)
 * @property {number} aesSaltBytes                - 8/12/16 (aes only)
 * @property {ArrayBuffer} salt                  - AES salt (aes only)
 * @property {ArrayBuffer} passwordVerification   - 2-byte AES verifier, OR
 *                                                   1-byte ZipCrypto check byte
 * @property {ArrayBuffer} zipCryptoHeader        - full 12-byte encryption
 *                                                   header (zipcrypto only)
 * @property {number} dataOffset                  - byte offset of ciphertext
 *                                                   start, relative to buffer
 * @property {number} crc32                       - header CRC32 (validation
 *                                                   fallback for ZipCrypto
 *                                                   when bit 3 is unset)
 * @property {boolean} useTimeByteCheck            - true if ZipCrypto's 1-byte
 *                                                   check must use the high
 *                                                   byte of DOS time instead
 *                                                   of CRC32 high byte (bit 3)
 */

/**
 * Maps AES extra-field "strength" byte -> {keyBytes, saltBytes}.
 * WinZip AE-x spec ties key length directly to salt length.
 */
const AES_STRENGTH_TABLE = {
  1: { keyBytes: 16, saltBytes: 8 },  // AES-128
  2: { keyBytes: 24, saltBytes: 12 }, // AES-192
  3: { keyBytes: 32, saltBytes: 16 }, // AES-256
};

/**
 * Parses a single Local File Header beginning at `offset` in `buffer`.
 *
 * @param {ArrayBuffer} buffer  - raw bytes containing at least one LFH
 * @param {number} [offset=0]  - byte offset of the LFH signature
 * @returns {ParsedEntry}
 */
function parseLocalFileHeader(buffer, offset = 0) {
  const view = new DataView(buffer);

  const signature = view.getUint32(offset + 0, true);
  if (signature !== LFH_SIGNATURE) {
    throw new Error(
      `Invalid local file header signature at offset ${offset}: 0x${signature.toString(16)}`
    );
  }

  const flags = view.getUint16(offset + 6, true);
  const compressionMethod = view.getUint16(offset + 8, true);
  const lastModTime = view.getUint16(offset + 10, true);
  const crc32 = view.getUint32(offset + 14, true);
  const fileNameLen = view.getUint16(offset + 26, true);
  const extraLen = view.getUint16(offset + 28, true);

  const isEncrypted = (flags & 0x0001) !== 0;
  const hasDataDescriptor = (flags & 0x0008) !== 0;

  if (!isEncrypted) {
    return {
      scheme: /** @type {EncryptionScheme} */ ('none'),
      compressionMethod,
      dataOffset: offset + 30 + fileNameLen + extraLen,
      crc32,
      useTimeByteCheck: false,
    };
  }

  const extraStart = offset + 30 + fileNameLen;
  const extraEnd = extraStart + extraLen;

  // AES is signaled by compressionMethod === 99, with real method + strength
  // living in the 0x9901 extra field.
  if (compressionMethod === 99) {
    const aesExtra = findExtraField(view, extraStart, extraEnd, 0x9901);
    if (!aesExtra) {
      throw new Error('AES compression method flagged but 0x9901 extra field missing');
    }
    // 0x9901 extra field body: version(2) | vendor "AE"(2) | strength(1) | actualCompressionMethod(2)
    const strength = view.getUint8(aesExtra.bodyOffset + 4);
    const dims = AES_STRENGTH_TABLE[strength];
    if (!dims) throw new Error(`Unrecognized AES strength byte: ${strength}`);

    const fileDataStart = extraEnd;
    const saltStart = fileDataStart;
    const verifierStart = saltStart + dims.saltBytes;
    const cipherStart = verifierStart + 2;

    return {
      scheme: 'aes',
      compressionMethod,
      aesStrength: strength,
      aesKeyBytes: dims.keyBytes,
      aesSaltBytes: dims.saltBytes,
      salt: buffer.slice(saltStart, verifierStart),
      passwordVerification: buffer.slice(verifierStart, cipherStart),
      dataOffset: cipherStart,
      crc32,
      useTimeByteCheck: false,
    };
  }

  // Traditional PKWARE (ZipCrypto): fixed 12-byte encryption header precedes
  // the compressed stream.
  const headerStart = extraEnd;
  const headerEnd = headerStart + 12;

  return {
    scheme: 'zipcrypto',
    compressionMethod,
    zipCryptoHeader: buffer.slice(headerStart, headerEnd),
    // Last header byte is the check byte; compared against either
    // CRC32's high byte, or (when a trailing data descriptor is used,
    // flag bit 3) the high byte of the DOS last-mod-time field.
    passwordVerification: buffer.slice(headerEnd - 1, headerEnd),
    dataOffset: headerEnd,
    crc32,
    useTimeByteCheck: hasDataDescriptor,
    _lastModTimeHighByte: (lastModTime >> 8) & 0xff,
  };
}

/**
 * Linear scan of the extra-field record chain (id(2) | size(2) | body) for
 * a specific field id.
 *
 * @param {DataView} view
 * @param {number} start
 * @param {number} end
 * @param {number} targetId
 * @returns {{bodyOffset: number, size: number} | null}
 */
function findExtraField(view, start, end, targetId) {
  let p = start;
  while (p + 4 <= end) {
    const id = view.getUint16(p, true);
    const size = view.getUint16(p + 2, true);
    if (id === targetId) {
      return { bodyOffset: p + 4, size };
    }
    p += 4 + size;
  }
  return null;
}

export { parseLocalFileHeader, LFH_SIGNATURE, AES_STRENGTH_TABLE };
