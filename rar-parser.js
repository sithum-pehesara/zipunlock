/**
 * rar-parser.js
 * Parses RAR3 and RAR5 archive headers to extract encryption parameters
 * needed for offline password verification. No decompression performed.
 *
 * RAR5 (sig: 52 61 72 21 1A 07 01 00):
 *   Blocks: CRC32(4) | headerSize(vint) | headerType(vint) | headerFlags(vint) | ...
 *   Block type 4 = Archive Encryption Header (created with WinRAR -hp flag)
 *     → kdfCount(1), salt(16), [checkValue(8), checkCrc(1)]
 *   Block type 2 = File Header → extra area may contain encryption record (type 1)
 *
 * RAR3 (sig: 52 61 72 21 1A 07 00):
 *   Blocks: CRC16(2) | type(1) | flags(2) | size(2) | body...
 *   MAIN_HEAD (0x73) flags bit 0x0080 = ENCHEADERS; salt follows MAIN_HEAD
 *   FILE_HEAD  (0x74) flags bit 0x0004 = encrypted; salt at end of header
 */

const RAR5_SIG = [0x52,0x61,0x72,0x21,0x1A,0x07,0x01,0x00];
const RAR3_SIG = [0x52,0x61,0x72,0x21,0x1A,0x07,0x00];

/**
 * @typedef {Object} RarEntry
 * @property {'rar3'|'rar5'} version
 * @property {'none'|'rar3'|'rar5'} scheme
 * @property {boolean} headerEncrypted   true when -hp flag was used
 * @property {ArrayBuffer|null} salt     8B (RAR3) or 16B (RAR5)
 * @property {number} kdfCount           RAR5: iterations = 2^kdfCount
 * @property {ArrayBuffer|null} checkValue  RAR5: 8-byte pw check value
 * @property {number} checkCrc           RAR5: 1-byte CRC of checkValue
 * @property {ArrayBuffer|null} firstBlock  RAR3: first 16B of encrypted stream
 */

function hasSig(view, sig) {
  if (view.byteLength < sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (view.getUint8(i) !== sig[i]) return false;
  return true;
}

/** RAR5 variable-length integer (7-bit groups, little-endian) */
function vint(view, pos) {
  let val = 0, shift = 0, n = 0;
  while (n < 8 && pos + n < view.byteLength) {
    const b = view.getUint8(pos + n++);
    val |= (b & 0x7F) << shift;
    shift += 7;
    if (!(b & 0x80)) break;
  }
  return { val, n };
}

// ── RAR5 ─────────────────────────────────────────────────────────────────────

function parseRar5(buffer) {
  const view = new DataView(buffer);
  let pos = 8; // skip 8-byte signature

  while (pos + 5 < buffer.byteLength) {
    pos += 4; // skip CRC32

    const { val: hSize, n: hsSz } = vint(view, pos);
    const hBodyEnd = pos + hsSz + hSize;
    pos += hsSz;

    const bodyStart = pos;

    const { val: hType, n: htSz } = vint(view, pos); pos += htSz;
    const { val: hFlags, n: hfSz } = vint(view, pos); pos += hfSz;

    // ── Archive Encryption Header (type 4) ──────────────────────────────────
    if (hType === 4) {
      // For this block type, bit 0x0001 = "password check present" (type-specific)
      const hasPwCheck = (hFlags & 0x0001) !== 0;
      const kdfCount = view.getUint8(pos); pos += 1;
      const salt = buffer.slice(pos, pos + 16); pos += 16;
      let checkValue = null, checkCrc = 0;
      if (hasPwCheck && pos + 9 <= buffer.byteLength) {
        checkValue = buffer.slice(pos, pos + 8); pos += 8;
        checkCrc = view.getUint8(pos);
      }
      return {
        version: 'rar5', scheme: 'rar5', headerEncrypted: true,
        salt, kdfCount, checkValue, checkCrc, firstBlock: null,
      };
    }

    if (hType === 5) break; // End of Archive Header

    // ── File Header (type 2) ─────────────────────────────────────────────────
    let dataAreaSize = 0;
    if (hType === 2) {
      let extraAreaSize = 0;
      if (hFlags & 0x0001) { const r = vint(view, pos); extraAreaSize = r.val; pos += r.n; }
      if (hFlags & 0x0002) { const r = vint(view, pos); dataAreaSize = r.val; pos += r.n; }

      // Skip file-specific fields to reach the extra area
      const r1 = vint(view, pos); const fileFlags = r1.val; pos += r1.n; // file flags
      const r2 = vint(view, pos); pos += r2.n;  // unpack size
      const r3 = vint(view, pos); pos += r3.n;  // attributes
      if (fileFlags & 0x0002) pos += 4;          // mtime
      if (fileFlags & 0x0004) pos += 4;          // data CRC32
      const r4 = vint(view, pos); pos += r4.n;  // compression info
      const r5 = vint(view, pos); pos += r5.n;  // host OS
      const r6 = vint(view, pos); pos += r6.n + r6.val; // name length + name (skip both)
      // Correct: r6.val = name length bytes to skip
      // But r6.n is bytes used by the vint, r6.val is the name length
      // We already added r6.n and r6.val above — but wait, we only did pos += r6.n + r6.val
      // That's correct: advance past the vint bytes AND past the name bytes

      if (extraAreaSize > 0) {
        const extraEnd = Math.min(pos + extraAreaSize, buffer.byteLength);
        let ep = pos;
        while (ep + 1 < extraEnd) {
          const rs = vint(view, ep);
          const rBodyStart = ep + rs.n;
          const rEnd = rBodyStart + rs.val;
          if (rEnd > extraEnd || rEnd > buffer.byteLength) break;

          const rt = vint(view, rBodyStart);
          if (rt.val === 1) {
            // Encryption extra record
            let ep2 = rBodyStart + rt.n;
            const rv = vint(view, ep2); ep2 += rv.n;                    // version
            const ef = vint(view, ep2); const encFlags = ef.val; ep2 += ef.n;
            const kdfCount = view.getUint8(ep2); ep2 += 1;
            const salt = buffer.slice(ep2, ep2 + 16); ep2 += 16;
            const hasPwCheck = (encFlags & 0x0001) !== 0;
            let checkValue = null, checkCrc = 0;
            if (hasPwCheck && ep2 + 9 <= buffer.byteLength) {
              checkValue = buffer.slice(ep2, ep2 + 8); ep2 += 8;
              checkCrc = view.getUint8(ep2);
            }
            return {
              version: 'rar5', scheme: 'rar5', headerEncrypted: false,
              salt, kdfCount, checkValue, checkCrc, firstBlock: null,
            };
          }
          ep = rEnd;
        }
      }
    } else {
      // Other block types: honour common extra/data area flags
      if (hFlags & 0x0001) { const r = vint(view, pos); pos += r.n; }         // extra area size
      if (hFlags & 0x0002) { const r = vint(view, pos); dataAreaSize = r.val; pos += r.n; }
    }

    pos = hBodyEnd + dataAreaSize;
  }

  return {
    version: 'rar5', scheme: 'none', headerEncrypted: false,
    salt: null, kdfCount: 0, checkValue: null, checkCrc: 0, firstBlock: null,
  };
}

// ── RAR3 ─────────────────────────────────────────────────────────────────────

function parseRar3(buffer) {
  const view = new DataView(buffer);
  let pos = 7; // skip 7-byte signature

  if (pos + 7 > buffer.byteLength) throw new Error('RAR3 archive too small');

  // MAIN_HEAD: CRC16(2) | type(1) | flags(2) | size(2)  — 7-byte prefix
  const mainType  = view.getUint8(pos + 2);
  if (mainType !== 0x73) throw new Error('Expected RAR3 MAIN_HEAD block at offset 7');
  const mainFlags = view.getUint16(pos + 3, true);
  const mainSize  = view.getUint16(pos + 5, true); // total block size including prefix
  pos += mainSize; // advance past entire MAIN_HEAD

  const encHeaders = (mainFlags & 0x0080) !== 0;

  if (encHeaders) {
    // Header-encrypted (-hp): 8-byte salt follows immediately after MAIN_HEAD
    if (pos + 8 > buffer.byteLength) throw new Error('RAR3 -hp: salt not found after MAIN_HEAD');
    const salt       = buffer.slice(pos, pos + 8);
    const firstBlock = (pos + 24 <= buffer.byteLength)
      ? buffer.slice(pos + 8, pos + 24)
      : null;
    return {
      version: 'rar3', scheme: 'rar3', headerEncrypted: true,
      salt, kdfCount: 0, checkValue: null, checkCrc: 0, firstBlock,
    };
  }

  // Per-file encryption: scan blocks for first encrypted FILE_HEAD (0x74)
  while (pos + 7 < buffer.byteLength) {
    const blkStart = pos;
    const blkType  = view.getUint8(pos + 2);
    const blkFlags = view.getUint16(pos + 3, true);
    const blkSize  = view.getUint16(pos + 5, true);

    if (blkType === 0x7B) break; // ENDARC_HEAD

    if (blkType === 0x74 && (blkFlags & 0x0004)) {
      // Encrypted FILE_HEAD — parse header fields after the 7-byte prefix
      let fp = pos + 7;
      if (fp + 25 > buffer.byteLength) break;

      const packSizeLo = view.getUint32(fp, true); fp += 4; // PackSize
      fp += 4;                                               // UnpSize
      fp += 1;                                               // HostOS
      fp += 4;                                               // FileCRC
      fp += 4;                                               // FileTime
      fp += 1;                                               // UnpVer
      const method   = view.getUint8(fp); fp += 1;
      const nameSize = view.getUint16(fp, true); fp += 2;
      fp += 4;                                               // Attr
      if (blkFlags & 0x0100) fp += 8;                       // Hi{Pack,Unp}Size
      fp += nameSize;                                        // FileName

      if (fp + 8 > buffer.byteLength) break;
      const salt       = buffer.slice(fp, fp + 8); fp += 8;
      const firstBlock = (fp + 16 <= buffer.byteLength) ? buffer.slice(fp, fp + 16) : null;

      return {
        version: 'rar3', scheme: 'rar3', headerEncrypted: false,
        salt, kdfCount: 0, checkValue: null, checkCrc: 0,
        firstBlock, compressionMethod: method,
      };
    }

    // Advance past this block (header + packed data)
    let packData = 0;
    if (blkType === 0x74 && pos + 11 <= buffer.byteLength) {
      packData = view.getUint32(pos + 7, true);
      if ((blkFlags & 0x0100) && pos + 15 <= buffer.byteLength) {
        packData += view.getUint32(pos + 11, true) * 0x100000000;
      }
    }
    pos = blkStart + blkSize + packData;
  }

  return {
    version: 'rar3', scheme: 'none', headerEncrypted: false,
    salt: null, kdfCount: 0, checkValue: null, checkCrc: 0, firstBlock: null,
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Parse a RAR archive buffer and return encryption parameters.
 * @param {ArrayBuffer} buffer
 * @returns {RarEntry}
 */
function parseRarEntry(buffer) {
  const view = new DataView(buffer);
  if (buffer.byteLength < 8) throw new Error('File too small to be a valid RAR archive');
  if (hasSig(view, RAR5_SIG)) return parseRar5(buffer);
  if (hasSig(view, RAR3_SIG)) return parseRar3(buffer);
  throw new Error('Not a valid RAR file (unrecognised signature)');
}

export { parseRarEntry };
