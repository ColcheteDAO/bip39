"use strict";
const bip32 = require("bip32");



var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// node_modules/@noble/hashes/src/sha2.ts
var sha2_exports = {};
__export(sha2_exports, {
  SHA224: () => SHA224,
  SHA256: () => SHA256,
  SHA384: () => SHA384,
  SHA512: () => SHA512,
  SHA512_224: () => SHA512_224,
  SHA512_256: () => SHA512_256,
  sha224: () => sha224,
  sha256: () => sha256,
  sha384: () => sha384,
  sha512: () => sha512,
  sha512_224: () => sha512_224,
  sha512_256: () => sha512_256
});
module.exports = __toCommonJS(sha2_exports);
var Hash = class {
};



var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  4089235720,
  3144134277,
  2227873595,
  1013904242,
  4271175723,
  2773480762,
  1595750129,
  1359893119,
  2917565137,
  2600822924,
  725511199,
  528734635,
  4215389547,
  1541459225,
  327033209
]);

var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function sha512_1FromBig(n, le = false) {
  if (le) return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function sha512_1Split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = sha512_1FromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}



var K512 = /* @__PURE__ */ (() => sha512_1Split([
  "0x428a2f98d728ae22",
  "0x7137449123ef65cd",
  "0xb5c0fbcfec4d3b2f",
  "0xe9b5dba58189dbbc",
  "0x3956c25bf348b538",
  "0x59f111f1b605d019",
  "0x923f82a4af194f9b",
  "0xab1c5ed5da6d8118",
  "0xd807aa98a3030242",
  "0x12835b0145706fbe",
  "0x243185be4ee4b28c",
  "0x550c7dc3d5ffb4e2",
  "0x72be5d74f27b896f",
  "0x80deb1fe3b1696b1",
  "0x9bdc06a725c71235",
  "0xc19bf174cf692694",
  "0xe49b69c19ef14ad2",
  "0xefbe4786384f25e3",
  "0x0fc19dc68b8cd5b5",
  "0x240ca1cc77ac9c65",
  "0x2de92c6f592b0275",
  "0x4a7484aa6ea6e483",
  "0x5cb0a9dcbd41fbd4",
  "0x76f988da831153b5",
  "0x983e5152ee66dfab",
  "0xa831c66d2db43210",
  "0xb00327c898fb213f",
  "0xbf597fc7beef0ee4",
  "0xc6e00bf33da88fc2",
  "0xd5a79147930aa725",
  "0x06ca6351e003826f",
  "0x142929670a0e6e70",
  "0x27b70a8546d22ffc",
  "0x2e1b21385c26c926",
  "0x4d2c6dfc5ac42aed",
  "0x53380d139d95b3df",
  "0x650a73548baf63de",
  "0x766a0abb3c77b2a8",
  "0x81c2c92e47edaee6",
  "0x92722c851482353b",
  "0xa2bfe8a14cf10364",
  "0xa81a664bbc423001",
  "0xc24b8b70d0f89791",
  "0xc76c51a30654be30",
  "0xd192e819d6ef5218",
  "0xd69906245565a910",
  "0xf40e35855771202a",
  "0x106aa07032bbd1b8",
  "0x19a4c116b8d2d0c8",
  "0x1e376c085141ab53",
  "0x2748774cdf8eeb99",
  "0x34b0bcb5e19b48a8",
  "0x391c0cb3c5c95a63",
  "0x4ed8aa4ae3418acb",
  "0x5b9cca4f7763e373",
  "0x682e6ff3d6b2b8a3",
  "0x748f82ee5defb2fc",
  "0x78a5636f43172f60",
  "0x84c87814a1f0ab72",
  "0x8cc702081a6439ec",
  "0x90befffa23631e28",
  "0xa4506cebde82bde9",
  "0xbef9a3f7b2c67915",
  "0xc67178f2e372532b",
  "0xca273eceea26619c",
  "0xd186b8c721c0c207",
  "0xeada7dd6cde0eb1e",
  "0xf57d4f7fee6ed178",
  "0x06f067aa72176fba",
  "0x0a637dc5a2c898a6",
  "0x113f9804bef90dae",
  "0x1b710b35131c471b",
  "0x28db77f523047d84",
  "0x32caab7b40c72493",
  "0x3c9ebe0a15c9bebc",
  "0x431d67c49c100d4c",
  "0x4cc5d4becb3e42b6",
  "0x597f299cfc657e2a",
  "0x5fcb6fab3ad6faec",
  "0x6c44198c4a475817"
].map((n) => BigInt(n))))();
var SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
var SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);







var sha512_1Add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
var sha512_1Add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
var sha512_1RotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
var sha512_1RotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
var sha512_1ShrSL = (h, l, s) => h << 32 - s | l >>> s;
var sha512_1ShrSH = (h, _l, s) => h >>> s;
var sha512_1RotrSL = (h, l, s) => h << 32 - s | l >>> s;
var sha512_1RotrSH = (h, l, s) => h >>> s | l << 32 - s;
var sha512_1Add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
var sha512_1Add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
var sha512_1Add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
var sha512_1Add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;

function sha512_1Utf8ToBytes(str) {
  if (typeof str !== "string") throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}

function sha512_1Aoutput(out, instance) {
  sha512_1Abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}

function sha512_1IsBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}

function sha512_1Abytes(b, ...lengths) {
  if (!sha512_1IsBytes(b)) throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}

function sha512_1Add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}

function sha512_1Clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}

function sha512_1ToBytes(data) {
  if (typeof data === "string") data = sha512_1Utf8ToBytes(data);
  sha512_1Abytes(data);
  return data;
}

function sha512_1Aexists(instance, checkFinished = true) {
  if (instance.destroyed) throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished) throw new Error("Hash#digest() has already been called");
}

function sha512_1CreateView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}

var Hash = class {
};

function sha512_1CreateHasher(hashCons) {
  const hashC = (msg) => hashCons().update(sha512_1ToBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}

function sha512_1SetBigUint64(view, byteOffset, value, isLE) {
  if (typeof view.setBigUint64 === "function") return view.setBigUint64(byteOffset, value, isLE);
  const _32n2 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n2 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE ? 4 : 0;
  const l = isLE ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE);
  view.setUint32(byteOffset + l, wl, isLE);
}

var HashMD = class extends Hash {
  blockLen;
  outputLen;
  padOffset;
  isLE;
  // For partial updates less than block size
  buffer;
  view;
  finished = false;
  length = 0;
  pos = 0;
  destroyed = false;
  constructor(blockLen, outputLen, padOffset, isLE) {
    super();
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE;
    this.buffer = new Uint8Array(blockLen);
    this.view = sha512_1CreateView(this.buffer);
  }
  update(data) {
    sha512_1Aexists(this);
    data = sha512_1ToBytes(data);
    sha512_1Abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = sha512_1CreateView(data);
        for (; blockLen <= len - pos; pos += blockLen) this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    sha512_1Aexists(this);
    sha512_1Aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    sha512_1Clean(this.buffer.subarray(pos));
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++) buffer[i] = 0;
    sha512_1SetBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
    this.process(view, 0);
    const oview = sha512_1CreateView(out);
    const len = this.outputLen;
    if (len % 4) throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length) throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++) oview.setUint32(4 * i, state[i], isLE);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to ||= new this.constructor();
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (length % blockLen) to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};

var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  4089235720,
  3144134277,
  2227873595,
  1013904242,
  4271175723,
  2773480762,
  1595750129,
  1359893119,
  2917565137,
  2600822924,
  725511199,
  528734635,
  4215389547,
  1541459225,
  327033209
]);

var SHA512 = class extends HashMD {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  // h -- high 32 bits, l -- low 32 bits
  Ah = SHA512_IV[0] | 0;
  Al = SHA512_IV[1] | 0;
  Bh = SHA512_IV[2] | 0;
  Bl = SHA512_IV[3] | 0;
  Ch = SHA512_IV[4] | 0;
  Cl = SHA512_IV[5] | 0;
  Dh = SHA512_IV[6] | 0;
  Dl = SHA512_IV[7] | 0;
  Eh = SHA512_IV[8] | 0;
  El = SHA512_IV[9] | 0;
  Fh = SHA512_IV[10] | 0;
  Fl = SHA512_IV[11] | 0;
  Gh = SHA512_IV[12] | 0;
  Gl = SHA512_IV[13] | 0;
  Hh = SHA512_IV[14] | 0;
  Hl = SHA512_IV[15] | 0;
  constructor(outputLen = 64) {
    super(128, outputLen, 16, false);
  }
  // prettier-ignore
  get() {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA512_W_H[i] = view.getUint32(offset);
      SHA512_W_L[i] = view.getUint32(offset += 4);
    }
    for (let i = 16; i < 80; i++) {
      const W15h = SHA512_W_H[i - 15] | 0;
      const W15l = SHA512_W_L[i - 15] | 0;
      const s0h = sha512_1RotrSH(W15h, W15l, 1) ^ sha512_1RotrSH(W15h, W15l, 8) ^ sha512_1ShrSH(W15h, W15l, 7);
      const s0l = sha512_1RotrSL(W15h, W15l, 1) ^ sha512_1RotrSL(W15h, W15l, 8) ^ sha512_1ShrSL(W15h, W15l, 7);
      const W2h = SHA512_W_H[i - 2] | 0;
      const W2l = SHA512_W_L[i - 2] | 0;
      const s1h = sha512_1RotrSH(W2h, W2l, 19) ^ sha512_1RotrBH(W2h, W2l, 61) ^ sha512_1ShrSH(W2h, W2l, 6);
      const s1l = sha512_1RotrSL(W2h, W2l, 19) ^ sha512_1RotrBL(W2h, W2l, 61) ^ sha512_1ShrSL(W2h, W2l, 6);
      const SUMl = sha512_1Add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
      const SUMh = sha512_1Add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
      SHA512_W_H[i] = SUMh | 0;
      SHA512_W_L[i] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    for (let i = 0; i < 80; i++) {
      const sigma1h = sha512_1RotrSH(Eh, El, 14) ^ sha512_1RotrSH(Eh, El, 18) ^ sha512_1RotrBH(Eh, El, 41);
      const sigma1l = sha512_1RotrSL(Eh, El, 14) ^ sha512_1RotrSL(Eh, El, 18) ^ sha512_1RotrBL(Eh, El, 41);
      const CHIh = Eh & Fh ^ ~Eh & Gh;
      const CHIl = El & Fl ^ ~El & Gl;
      const T1ll = sha512_1Add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
      const T1h = sha512_1Add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
      const T1l = T1ll | 0;
      const sigma0h = sha512_1RotrSH(Ah, Al, 28) ^ sha512_1RotrBH(Ah, Al, 34) ^ sha512_1RotrBH(Ah, Al, 39);
      const sigma0l = sha512_1RotrSL(Ah, Al, 28) ^ sha512_1RotrBL(Ah, Al, 34) ^ sha512_1RotrBL(Ah, Al, 39);
      const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
      const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = sha512_1Add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = sha512_1Add3L(T1l, sigma0l, MAJl);
      Ah = sha512_1Add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    ({ h: Ah, l: Al } = sha512_1Add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = sha512_1Add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = sha512_1Add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = sha512_1Add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = sha512_1Add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = sha512_1Add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = sha512_1Add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = sha512_1Add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  roundClean() {
    sha512_1Clean(SHA512_W_H, SHA512_W_L);
  }
  destroy() {
    sha512_1Clean(this.buffer);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
var sha512_1Sha512 = /* @__PURE__ */ sha512_1CreateHasher(() => new SHA512());

class HMAC extends Hash {
    constructor(hash, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        pbkdf2_1Ahash(hash);
        const key = sha512_1ToBytes(_key);
        this.iHash = hash.create();
        if (typeof this.iHash.update !== 'function')
            throw new Error('Expected instance of class which extends utils.Hash');
        this.blockLen = this.iHash.blockLen;
        this.outputLen = this.iHash.outputLen;
        const blockLen = this.blockLen;
        const pad = new Uint8Array(blockLen);
        // blockLen can be bigger than outputLen
        pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36;
        this.iHash.update(pad);
        // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
        this.oHash = hash.create();
        // Undo internal XOR && apply outer XOR
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36 ^ 0x5c;
        this.oHash.update(pad);
        pbkdf2_1Clean(pad);
    }
    update(buf) {
        sha512_1Aexists(this);
        this.iHash.update(buf);
        return this;
    }
    digestInto(out) {
        sha512_1Aexists(this);
        pbkdf2_1Abytes(out, this.outputLen);
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
    }
    digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
    }
    _cloneInto(to) {
        // Create new instance without calling constructor since key already in state and we don't know it.
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
    }
    clone() {
        return this._cloneInto();
    }
    destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
    }
}

const hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
hmac.create = (hash, key) => new HMAC(hash, key);

function pbkdf2_1Clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
}

function pbkdf2_1Pbkdf2Output(PRF, PRFSalt, DK, prfW, u) {
    PRF.destroy();
    PRFSalt.destroy();
    if (prfW)
        prfW.destroy();
    pbkdf2_1Clean(u);
    return DK;
}

const pbkdf2_1NextTick = async () => { };

async function pbkdf2_1AsyncLoop(iters, tick, cb) {
    let ts = Date.now();
    for (let i = 0; i < iters; i++) {
        cb(i);
        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
            continue;
        await pbkdf2_1NextTick();
        ts += diff;
    }
}

function pbkdf2_1IsBytes(a) {
    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}

function pbkdf2_1Abytes(b, ...lengths) {
    if (!pbkdf2_1IsBytes(b))
        throw new Error('Uint8Array expected');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error('Uint8Array expected of length ' + lengths + ', got length=' + b.length);
}

function pbkdf2_1CheckOpts(defaults, opts) {
    if (opts !== undefined && {}.toString.call(opts) !== '[object Object]')
        throw new Error('options should be object or undefined');
    const merged = Object.assign(defaults, opts);
    return merged;
}

function pbkdf2_1KdfInputToBytes(data) {
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    pbkdf2_1Abytes(data);
    return data;
}

function pbkdf2_1Anumber(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error('positive integer expected, got ' + n);
}

function pbkdf2_1Ahash(h) {
    if (typeof h !== 'function' || typeof h.create !== 'function')
        throw new Error('Hash should be wrapped by utils.createHasher');
    pbkdf2_1Anumber(h.outputLen);
    pbkdf2_1Anumber(h.blockLen);
}

function pbkdf2_1Pbkdf2Init(hash, _password, _salt, _opts) {
    pbkdf2_1Ahash(hash);
    const opts = pbkdf2_1CheckOpts({ dkLen: 32, asyncTick: 10 }, _opts);
    const { c, dkLen, asyncTick } = opts;
    pbkdf2_1Anumber(c);
    pbkdf2_1Anumber(dkLen);
    pbkdf2_1Anumber(asyncTick);
    if (c < 1)
        throw new Error('iterations (c) should be >= 1');
    const password = pbkdf2_1KdfInputToBytes(_password);
    const salt = pbkdf2_1KdfInputToBytes(_salt);
    // DK = PBKDF2(PRF, Password, Salt, c, dkLen);
    const DK = new Uint8Array(dkLen);
    // U1 = PRF(Password, Salt + INT_32_BE(i))
    const PRF = hmac.create(hash, password);
    const PRFSalt = PRF._cloneInto().update(salt);
    return { c, dkLen, asyncTick, DK, PRF, PRFSalt };
}

function pbkdf2_1CreateView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}

async function pbkdf2_1Pbkdf2Async(hash, password, salt, opts) {
    const { c, dkLen, asyncTick, DK, PRF, PRFSalt } = pbkdf2_1Pbkdf2Init(hash, password, salt, opts);
    let prfW; // Working copy
    const arr = new Uint8Array(4);
    const view = pbkdf2_1CreateView(arr);
    const u = new Uint8Array(PRF.outputLen);
    // DK = T1 + T2 + ⋯ + Tdklen/hlen
    for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
        // Ti = F(Password, Salt, c, i)
        const Ti = DK.subarray(pos, pos + PRF.outputLen);
        view.setInt32(0, ti, false);
        // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
        // U1 = PRF(Password, Salt + INT_32_BE(i))
        (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
        Ti.set(u.subarray(0, Ti.length));
        await pbkdf2_1AsyncLoop(c - 1, asyncTick, () => {
            // Uc = PRF(Password, Uc−1)
            PRF._cloneInto(prfW).update(u).digestInto(u);
            for (let i = 0; i < Ti.length; i++)
                Ti[i] ^= u[i];
        });
    }
    return pbkdf2_1Pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
}


function basexBase (ALPHABET) {
  if (ALPHABET.length >= 255) { throw new TypeError('Alphabet too long') }
  var BASE_MAP = new Uint8Array(256)
  for (var j = 0; j < BASE_MAP.length; j++) {
    BASE_MAP[j] = 255
  }
  for (var i = 0; i < ALPHABET.length; i++) {
    var x = ALPHABET.charAt(i)
    var xc = x.charCodeAt(0)
    if (BASE_MAP[xc] !== 255) { throw new TypeError(x + ' is ambiguous') }
    BASE_MAP[xc] = i
  }
  var BASE = ALPHABET.length
  var LEADER = ALPHABET.charAt(0)
  var FACTOR = Math.log(BASE) / Math.log(256) // log(BASE) / log(256), rounded up
  var iFACTOR = Math.log(256) / Math.log(BASE) // log(256) / log(BASE), rounded up
  function encode (source) {
    if (Array.isArray(source) || source instanceof Uint8Array) { source = Buffer.from(source) }
    if (!Buffer.isBuffer(source)) { throw new TypeError('Expected Buffer') }
    if (source.length === 0) { return '' }
        // Skip & count leading zeroes.
    var zeroes = 0
    var length = 0
    var pbegin = 0
    var pend = source.length
    while (pbegin !== pend && source[pbegin] === 0) {
      pbegin++
      zeroes++
    }
        // Allocate enough space in big-endian base58 representation.
    var size = ((pend - pbegin) * iFACTOR + 1) >>> 0
    var b58 = new Uint8Array(size)
        // Process the bytes.
    while (pbegin !== pend) {
      var carry = source[pbegin]
            // Apply "b58 = b58 * 256 + ch".
      var i = 0
      for (var it1 = size - 1; (carry !== 0 || i < length) && (it1 !== -1); it1--, i++) {
        carry += (256 * b58[it1]) >>> 0
        b58[it1] = (carry % BASE) >>> 0
        carry = (carry / BASE) >>> 0
      }
      if (carry !== 0) { throw new Error('Non-zero carry') }
      length = i
      pbegin++
    }
        // Skip leading zeroes in base58 result.
    var it2 = size - length
    while (it2 !== size && b58[it2] === 0) {
      it2++
    }
        // Translate the result into a string.
    var str = LEADER.repeat(zeroes)
    for (; it2 < size; ++it2) { str += ALPHABET.charAt(b58[it2]) }
    return str
  }
  function decodeUnsafe (source) {
    if (typeof source !== 'string') { throw new TypeError('Expected String') }
    if (source.length === 0) { return _Buffer.alloc(0) }
    var psz = 0
        // Skip and count leading '1's.
    var zeroes = 0
    var length = 0
    while (source[psz] === LEADER) {
      zeroes++
      psz++
    }
        // Allocate enough space in big-endian base256 representation.
    var size = (((source.length - psz) * FACTOR) + 1) >>> 0 // log(58) / log(256), rounded up.
    var b256 = new Uint8Array(size)
        // Process the characters.
    while (psz < source.length) {
            // Find code of next character
      var charCode = source.charCodeAt(psz)
            // Base map can not be indexed using char code
      if (charCode > 255) { return }
            // Decode character
      var carry = BASE_MAP[charCode]
            // Invalid character
      if (carry === 255) { return }
      var i = 0
      for (var it3 = size - 1; (carry !== 0 || i < length) && (it3 !== -1); it3--, i++) {
        carry += (BASE * b256[it3]) >>> 0
        b256[it3] = (carry % 256) >>> 0
        carry = (carry / 256) >>> 0
      }
      if (carry !== 0) { throw new Error('Non-zero carry') }
      length = i
      psz++
    }
        // Skip leading zeroes in b256.
    var it4 = size - length
    while (it4 !== size && b256[it4] === 0) {
      it4++
    }
    var vch = _Buffer.allocUnsafe(zeroes + (size - it4))
    vch.fill(0x00, 0, zeroes)
    var j = zeroes
    while (it4 !== size) {
      vch[j++] = b256[it4++]
    }
    return vch
  }
  function decode (string) {
    var buffer = decodeUnsafe(string)
    if (buffer) { return buffer }
    throw new Error('Non-base' + BASE + ' character')
  }
  return {
    encode: encode,
    decodeUnsafe: decodeUnsafe,
    decode: decode
  }
}
var ALPHABETbs58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
var ALPHABETrs58 = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'
const bs58 = basexBase(ALPHABETbs58)
const rs58 = basexBase(ALPHABETrs58)

function bip39Salt(password) {
    return 'mnemonic' + (password || '');
}

function bip39Normalize(str) {
    return (str || '').normalize('NFKD');
}

function bip39MnemonicToSeed(mnemonic, password) {
    const mnemonicBuffer = Uint8Array.from(Buffer.from(bip39Normalize(mnemonic), 'utf8'));
    const saltBuffer = Uint8Array.from(Buffer.from(bip39Salt(bip39Normalize(password)), 'utf8'));
    return pbkdf2_1Pbkdf2Async(sha512_1Sha512, mnemonicBuffer, saltBuffer, {
        c: 2048,
        dkLen: 64,
    }).then((res) => Buffer.from(res));
}

function bs58checkEncode (payload) {
    var checksum = checksumFn(payload)

    return base58.encode(Buffer.concat([
      payload,
      checksum
    ], payload.length + 4))
  }

  function bs58checkDecodeRaw (buffer) {
    var payload = buffer.slice(0, -4)
    var checksum = buffer.slice(-4)
    var newChecksum = checksumFn(payload)

    if (checksum[0] ^ newChecksum[0] |
        checksum[1] ^ newChecksum[1] |
        checksum[2] ^ newChecksum[2] |
        checksum[3] ^ newChecksum[3]) return

    return payload
  }


  function bs58checkDecode (string) {
    var buffer = base58.decode(string)
    var payload = bs58checkDecodeRaw(buffer, checksumFn)
    if (!payload) throw new Error('Invalid checksum')
    return payload
  }

function wifDecodeRaw (buffer, version) {
  // check version only if defined
  if (version !== undefined && buffer[0] !== version) throw new Error('Invalid network version')

  // uncompressed
  if (buffer.length === 33) {
    return {
      version: buffer[0],
      privateKey: buffer.slice(1, 33),
      compressed: false
    }
  }

  // invalid length
  if (buffer.length !== 34) throw new Error('Invalid WIF length')

  // invalid compression flag
  if (buffer[33] !== 0x01) throw new Error('Invalid compression flag')

  return {
    version: buffer[0],
    privateKey: buffer.slice(1, 33),
    compressed: true
  }
}

function wifEncodeRaw (version, privateKey, compressed) {
  var result = new Buffer(compressed ? 34 : 33)

  result.writeUInt8(version, 0)
  privateKey.copy(result, 1)

  if (compressed) {
    result[33] = 0x01
  }

  return result
}

function wifDecode (string, version) {
  return wifDecodeRaw(bs58checkDecode(string), version)
}

function wifEncode (version, privateKey, compressed) {
  if (typeof version === 'number') return bs58checkEncode(wifEncodeRaw(version, privateKey, compressed))

  return bs58checkEncode(
    wifEncodeRaw(
      version.version,
      version.privateKey,
      version.compressed
    )
  )
}


function hmacsha512(message) {
  return Buffer.from(hmac(sha512_1Sha512, "bip-entropy-from-k",message))
}

function bip32XPRVToEntropy(path, xprvString) {
  const xprv = bip32.fromBase58(xprvString);
  const child = xprv.derivePath(path);
  return hmacsha512(child.privateKey);
}

async function bip39MnemonicToEntropy(path, mnemonic, passphrase) {
  const bip39Seed = await bip39MnemonicToSeed(mnemonic, passphrase);
  const xprv = await bip32.fromSeed(bip39Seed);
  const child = xprv.derivePath(path);
  return hmacsha512(child.privateKey);
}

function entropyToBIP39(entropy, words, language = "english") {
  const width = Math.floor(((words - 1) * 11) / 8 + 1);
  return bip39.entropyToMnemonic(entropy.slice(0, width));
}

function entropyToWif(entropy) {
  const privateKey = Buffer.from(entropy.slice(0, 32));
  return wifEncode(128, privateKey, true);
}

function entropyFromWif(key) {
  return wifDecode(key).privateKey;
}

function calculateChecksum(extendedKey) {
  let hash = crypto.createHash("sha256");
  hash.update(extendedKey);
  let data = hash.digest();
  hash = crypto.createHash("sha256");
  hash.update(data);
  return hash.digest().slice(0, 4);
}

function bip32XPRVToXPRV(path, xprvString) {
  const ent = bip32XPRVToEntropy(path, xprvString);

  const prefix = Buffer.from("0488ade4", "hex");
  const depth = Buffer.from("00", "hex");
  const parentFingerprint = Buffer.from("00".repeat(4), "hex");
  const childNum = Buffer.from("00".repeat(4), "hex");
  const chainCode = ent.slice(0, 32);
  const privateKey = Buffer.concat(
    [Buffer.from("00", "hex"), Buffer.from(ent.slice(32, ent.length), "hex")],
    ent.length + 1
  );
  const extendedKey = Buffer.concat(
    [prefix, depth, parentFingerprint, childNum, chainCode, privateKey],
    78
  );
  const checksum = calculateChecksum(extendedKey);

  const bytes = Buffer.concat(
    [extendedKey, checksum],
    extendedKey.length + checksum.length
  );
  return bs58.encode(bytes);
}

async function bip32XPRVToHex(path, width, xprvString) {
  const entropy = await bip32XPRVToEntropy(path, xprvString);
  return entropy.slice(0, width).toString("hex");
}

function languageIdxOf(language) {
  const languages = [
    "english",
    "japanese",
    "korean",
    "spanish",
    "chinese_simplified",
    "chinese_traditional",
    "french",
    "italian",
    "czech",
  ];

  return languages.indexOf(language);
}

const app = {
  bip39: async function (xprvString, language, words, index) {
    const languageIdx = languageIdxOf(language);
    const path = `m/83696968'/39'/${languageIdx}'/${words}'/${index}'`;
    const entropy = await bip32XPRVToEntropy(path, xprvString);
    const res = await entropyToBIP39(entropy, words, language);
    return res;
  },
  xprv: function (xprvString, index) {
    const path = `83696968'/32'/${index}'`;
    return bip32XPRVToXPRV(path, xprvString);
  },
  wif: async function (xprvString, index) {
    const path = `m/83696968'/2'/${index}'`;
    const entropy = await bip32XPRVToEntropy(path, xprvString);
    return entropyToWif(entropy);
  },
  hex: async function (xprvString, index, width) {
    const path = `m/83696968'/128169'/${width}'/${index}'`;
    const res = await bip32XPRVToHex(path, width, xprvString);
    return res;
  },
};

function entropyToCrippleSeed(entropy) {
  const key = Buffer.concat(
    [Buffer.from("21", "hex"), entropy.slice(0, 16)],
    17
  );
  const checksum = calculateChecksum(key);
  const rawSeed = Buffer.concat([key, checksum], key.length + checksum.length);
  return rs58.encode(rawSeed);
}

async function bip32ToCrippleSeed(path, xprvString) {
  const entropy = await bip32XPRVToEntropy(path, xprvString);
  return entropyToCrippleSeed(entropy);
}

const extras = {
  entropyToCrippleSeed: entropyToCrippleSeed,
  bip32ToCrippleSeed: bip32ToCrippleSeed,
};

module.exports = {
  bip32XPRVToEntropy: bip32XPRVToEntropy,
  bip39MnemonicToEntropy: bip39MnemonicToEntropy,
  entropyToBIP39: entropyToBIP39,
  entropyToWif: entropyToWif,
  entropyFromWif: entropyFromWif,
  bip32XPRVToXPRV: bip32XPRVToXPRV,
  bip32XPRVToHex: bip32XPRVToHex,
  app: app,
  extras: extras,
};


