"use strict";
var RIPEMD160 = require('ripemd160')
const sha256 = require('./node_modules/sha.js/sha256')
var MD5 = require('md5.js')

var isEncoding = Buffer.isEncoding || function (encoding) {
  encoding = '' + encoding;
  switch (encoding && encoding.toLowerCase()) {
    case 'hex':case 'utf8':case 'utf-8':case 'ascii':case 'binary':case 'base64':case 'ucs2':case 'ucs-2':case 'utf16le':case 'utf-16le':case 'raw':
      return true;
    default:
      return false;
  }
};

function _normalizeEncoding(enc) {
  if (!enc) return 'utf8';
  var retried;
  while (true) {
    switch (enc) {
      case 'utf8':
      case 'utf-8':
        return 'utf8';
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return 'utf16le';
      case 'latin1':
      case 'binary':
        return 'latin1';
      case 'base64':
      case 'ascii':
      case 'hex':
        return enc;
      default:
        if (retried) return; // undefined
        enc = ('' + enc).toLowerCase();
        retried = true;
    }
  }
};

// Do not cache `Buffer.isEncoding` when checking encoding names as some
// modules monkey-patch it to support additional encodings
function normalizeEncoding(enc) {
  var nenc = _normalizeEncoding(enc);
  if (typeof nenc !== 'string' && (Buffer.isEncoding === isEncoding || !isEncoding(enc))) throw new Error('Unknown encoding: ' + enc);
  return nenc || enc;
}

// StringDecoder provides an interface for efficiently splitting a series of
// buffers into a series of JS strings without breaking apart multi-byte
// characters.
exports.StringDecoder = StringDecoder;
function StringDecoder(encoding) {
  this.encoding = normalizeEncoding(encoding);
  var nb;
  switch (this.encoding) {
    case 'utf16le':
      this.text = utf16Text;
      this.end = utf16End;
      nb = 4;
      break;
    case 'utf8':
      this.fillLast = utf8FillLast;
      nb = 4;
      break;
    case 'base64':
      this.text = base64Text;
      this.end = base64End;
      nb = 3;
      break;
    default:
      this.write = simpleWrite;
      this.end = simpleEnd;
      return;
  }
  this.lastNeed = 0;
  this.lastTotal = 0;
  this.lastChar = Buffer.allocUnsafe(nb);
}

StringDecoder.prototype.write = function (buf) {
  if (buf.length === 0) return '';
  var r;
  var i;
  if (this.lastNeed) {
    r = this.fillLast(buf);
    if (r === undefined) return '';
    i = this.lastNeed;
    this.lastNeed = 0;
  } else {
    i = 0;
  }
  if (i < buf.length) return r ? r + this.text(buf, i) : this.text(buf, i);
  return r || '';
};

StringDecoder.prototype.end = utf8End;

// Returns only complete characters in a Buffer
StringDecoder.prototype.text = utf8Text;

// Attempts to complete a partial non-UTF-8 character using bytes from a Buffer
StringDecoder.prototype.fillLast = function (buf) {
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, buf.length);
  this.lastNeed -= buf.length;
};

// Checks the type of a UTF-8 byte, whether it's ASCII, a leading byte, or a
// continuation byte. If an invalid byte is detected, -2 is returned.
function utf8CheckByte(byte) {
  if (byte <= 0x7F) return 0;else if (byte >> 5 === 0x06) return 2;else if (byte >> 4 === 0x0E) return 3;else if (byte >> 3 === 0x1E) return 4;
  return byte >> 6 === 0x02 ? -1 : -2;
}

// Checks at most 3 bytes at the end of a Buffer in order to detect an
// incomplete multi-byte UTF-8 character. The total number of bytes (2, 3, or 4)
// needed to complete the UTF-8 character (if applicable) are returned.
function utf8CheckIncomplete(self, buf, i) {
  var j = buf.length - 1;
  if (j < i) return 0;
  var nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 1;
    return nb;
  }
  if (--j < i || nb === -2) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 2;
    return nb;
  }
  if (--j < i || nb === -2) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) {
      if (nb === 2) nb = 0;else self.lastNeed = nb - 3;
    }
    return nb;
  }
  return 0;
}

// Validates as many continuation bytes for a multi-byte UTF-8 character as
// needed or are available. If we see a non-continuation byte where we expect
// one, we "replace" the validated continuation bytes we've seen so far with
// a single UTF-8 replacement character ('\ufffd'), to match v8's UTF-8 decoding
// behavior. The continuation byte check is included three times in the case
// where all of the continuation bytes for a character exist in the same buffer.
// It is also done this way as a slight performance increase instead of using a
// loop.
function utf8CheckExtraBytes(self, buf, p) {
  if ((buf[0] & 0xC0) !== 0x80) {
    self.lastNeed = 0;
    return '\ufffd';
  }
  if (self.lastNeed > 1 && buf.length > 1) {
    if ((buf[1] & 0xC0) !== 0x80) {
      self.lastNeed = 1;
      return '\ufffd';
    }
    if (self.lastNeed > 2 && buf.length > 2) {
      if ((buf[2] & 0xC0) !== 0x80) {
        self.lastNeed = 2;
        return '\ufffd';
      }
    }
  }
}

// Attempts to complete a multi-byte UTF-8 character using bytes from a Buffer.
function utf8FillLast(buf) {
  var p = this.lastTotal - this.lastNeed;
  var r = utf8CheckExtraBytes(this, buf, p);
  if (r !== undefined) return r;
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, p, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, p, 0, buf.length);
  this.lastNeed -= buf.length;
}

// Returns all complete UTF-8 characters in a Buffer. If the Buffer ended on a
// partial character, the character's bytes are buffered until the required
// number of bytes are available.
function utf8Text(buf, i) {
  var total = utf8CheckIncomplete(this, buf, i);
  if (!this.lastNeed) return buf.toString('utf8', i);
  this.lastTotal = total;
  var end = buf.length - (total - this.lastNeed);
  buf.copy(this.lastChar, 0, end);
  return buf.toString('utf8', i, end);
}

// For UTF-8, a replacement character is added when ending on a partial
// character.
function utf8End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + '\ufffd';
  return r;
}

// UTF-16LE typically needs two bytes per character, but even if we have an even
// number of bytes available, we need to check if we end on a leading/high
// surrogate. In that case, we need to wait for the next two bytes in order to
// decode the last character properly.
function utf16Text(buf, i) {
  if ((buf.length - i) % 2 === 0) {
    var r = buf.toString('utf16le', i);
    if (r) {
      var c = r.charCodeAt(r.length - 1);
      if (c >= 0xD800 && c <= 0xDBFF) {
        this.lastNeed = 2;
        this.lastTotal = 4;
        this.lastChar[0] = buf[buf.length - 2];
        this.lastChar[1] = buf[buf.length - 1];
        return r.slice(0, -1);
      }
    }
    return r;
  }
  this.lastNeed = 1;
  this.lastTotal = 2;
  this.lastChar[0] = buf[buf.length - 1];
  return buf.toString('utf16le', i, buf.length - 1);
}

// For UTF-16LE we do not explicitly append special replacement characters if we
// end on a partial character, we simply let v8 handle that.
function utf16End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) {
    var end = this.lastTotal - this.lastNeed;
    return r + this.lastChar.toString('utf16le', 0, end);
  }
  return r;
}

function base64Text(buf, i) {
  var n = (buf.length - i) % 3;
  if (n === 0) return buf.toString('base64', i);
  this.lastNeed = 3 - n;
  this.lastTotal = 3;
  if (n === 1) {
    this.lastChar[0] = buf[buf.length - 1];
  } else {
    this.lastChar[0] = buf[buf.length - 2];
    this.lastChar[1] = buf[buf.length - 1];
  }
  return buf.toString('base64', i, buf.length - n);
}

function base64End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + this.lastChar.toString('base64', 0, 3 - this.lastNeed);
  return r;
}

// Pass bytes on through for single-byte encodings (e.g. ascii, latin1, hex)
function simpleWrite(buf) {
  return buf.toString(this.encoding);
}

function simpleEnd(buf) {
  return buf && buf.length ? this.write(buf) : '';
}

function toBuffer(data, encoding) {
	if (Buffer.isBuffer(data)) {
		if (data.constructor && !('isBuffer' in data)) {
			// probably a SlowBuffer
			return Buffer.from(data);
		}
		return data;
	}

	if (typeof data === 'string') {
		return Buffer.from(data, encoding);
	}

	/*
	 * Wrap any TypedArray instances and DataViews
	 * Makes sense only on engines with full TypedArray support -- let Buffer detect that
	 */
	if (useArrayBuffer && isView(data)) {
		// Bug in Node.js <6.3.1, which treats this as out-of-bounds
		if (data.byteLength === 0) {
			return Buffer.alloc(0);
		}

		// When Buffer is based on Uint8Array, we can just construct it from ArrayBuffer
		if (useFromArrayBuffer) {
			var res = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
			/*
			 * Recheck result size, as offset/length doesn't work on Node.js <5.10
			 * We just go to Uint8Array case if this fails
			 */
			if (res.byteLength === data.byteLength) {
				return res;
			}
		}

		// Convert to Uint8Array bytes and then to Buffer
		var uint8 = data instanceof Uint8Array ? data : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
		var result = Buffer.from(uint8);

		/*
		 * Let's recheck that conversion succeeded
		 * We have .length but not .byteLength when useFromArrayBuffer is false
		 */
		if (result.length === data.byteLength) {
			return result;
		}
	}

	/*
	 * Uint8Array in engines where Buffer.from might not work with ArrayBuffer, just copy over
	 * Doesn't make sense with other TypedArray instances
	 */
	if (useUint8Array && data instanceof Uint8Array) {
		return Buffer.from(data);
	}

	var isArr = isArray(data);
	if (isArr) {
		for (var i = 0; i < data.length; i += 1) {
			var x = data[i];
			if (
				typeof x !== 'number'
				|| x < 0
				|| x > 255
				|| ~~x !== x // NaN and integer check
			) {
				throw new RangeError('Array items must be numbers in the range 0-255.');
			}
		}
	}

	/*
	 * Old Buffer polyfill on an engine that doesn't have TypedArray support
	 * Also, this is from a different Buffer polyfill implementation then we have, as instanceof check failed
	 * Convert to our current Buffer implementation
	 */
	if (
		isArr || (
			Buffer.isBuffer(data)
			&& data.constructor
			&& typeof data.constructor.isBuffer === 'function'
			&& data.constructor.isBuffer(data)
		)
	) {
		return Buffer.from(data);
	}

	throw new TypeError('The "data" argument must be a string, an Array, a Buffer, a Uint8Array, or a DataView.');
}

// --- START OF COMPATIBLE POLYFILL ---
// We define Transform as a FUNCTION (not a class) so .call(this) works

// 1. EventEmitter Polyfill (Function Style)
function EventEmitter() {
  this._events = {};
}
EventEmitter.prototype.on = function(type, listener) {
  const list = this._events[type] || (this._events[type] = []);
  list.push(listener);
  return this;
};
EventEmitter.prototype.emit = function(type, ...args) {
  const list = this._events[type];
  if (list) list.forEach(fn => fn.apply(this, args));
};

// 2. Transform Polyfill (Function Style)
function Transform(options) {
  // This allows the legacy code to run Transform.call(this) successfully
  EventEmitter.call(this); 
  
  this._readableState = { objectMode: false, ended: false, destroyed: false };
  this._writableState = { objectMode: false, ended: false, destroyed: false };
}

// 3. Setup Inheritance manually
Transform.prototype = Object.create(EventEmitter.prototype);
Transform.prototype.constructor = Transform;

// 4. Add required methods
Transform.prototype.push = function(chunk) {
  this.emit('data', chunk);
  return true;
};
Transform.prototype.write = function(chunk, encoding, cb) {
  // Handle optional arguments
  if (typeof encoding === 'function') { cb = encoding; encoding = 'utf8'; }
  
  // Mock the internal _transform call
  if (this._transform) {
    this._transform(chunk, encoding || 'utf8', (err, data) => {
      if (data) this.push(data);
      if (cb) cb(err);
    });
  }
  return true;
};
Transform.prototype.end = function(chunk, encoding, cb) {
  if (chunk) this.write(chunk, encoding, cb);
  this.emit('end');
};
// --- END OF COMPATIBLE POLYFILL ---
function fBase() {

  function CipherBase(hashMode) {
    Transform.call(this);
    this.hashMode = typeof hashMode === 'string';
    if (this.hashMode) {
      this[hashMode] = this._finalOrDigest;
    } else {
      this['final'] = this._finalOrDigest;
    }
    if (this._final) {
      this.__final = this._final;
      this._final = null;
    }
    this._decoder = null;
    this._encoding = null;
  }
  inherits(CipherBase, Transform);

  CipherBase.prototype.update = function(data, inputEnc, outputEnc) {
    var bufferData = toBuffer(data, inputEnc); // asserts correct input type
    var outData = this._update(bufferData);
    if (this.hashMode) {
      return this;
    }

    if (outputEnc) {
      outData = this._toString(outData, outputEnc);
    }

    return outData;
  };

  CipherBase.prototype.setAutoPadding = function() { };
  CipherBase.prototype.getAuthTag = function() {
    throw new Error('trying to get auth tag in unsupported state');
  };

  CipherBase.prototype.setAuthTag = function() {
    throw new Error('trying to set auth tag in unsupported state');
  };

  CipherBase.prototype.setAAD = function() {
    throw new Error('trying to set aad in unsupported state');
  };

  CipherBase.prototype._transform = function(data, _, next) {
    var err;
    try {
      if (this.hashMode) {
        this._update(data);
      } else {
        this.push(this._update(data));
      }
    } catch (e) {
      err = e;
    } finally {
      next(err);
    }
  };
  CipherBase.prototype._flush = function(done) {
    var err;
    try {
      this.push(this.__final());
    } catch (e) {
      err = e;
    }

    done(err);
  };
  CipherBase.prototype._finalOrDigest = function(outputEnc) {
    var outData = this.__final() || Buffer.alloc(0);
    if (outputEnc) {
      outData = this._toString(outData, outputEnc, true);
    }
    return outData;
  };

  CipherBase.prototype._toString = function(value, enc, fin) {
    if (!this._decoder) {
      this._decoder = new StringDecoder(enc);
      this._encoding = enc;
    }

    if (this._encoding !== enc) {
      throw new Error('can’t switch encodings');
    }

    var out = this._decoder.write(value);
    if (fin) {
      out += this._decoder.end();
    }

    return out;
  };

  return CipherBase;
}

var Base = fBase()



function fLegacy() {
  var ZEROS = Buffer.alloc(128)
  var blocksize = 64

  function Hmac(alg, key) {
    Base.call(this, 'digest')
    if (typeof key === 'string') {
      key = Buffer.from(key)
    }

    this._alg = alg
    this._key = key

    if (key.length > blocksize) {
      key = alg(key)
    } else if (key.length < blocksize) {
      key = Buffer.concat([key, ZEROS], blocksize)
    }

    var ipad = this._ipad = Buffer.allocUnsafe(blocksize)
    var opad = this._opad = Buffer.allocUnsafe(blocksize)

    for (var i = 0; i < blocksize; i++) {
      ipad[i] = key[i] ^ 0x36
      opad[i] = key[i] ^ 0x5C
    }

    this._hash = [ipad]
  }

  inherits(Hmac, Base)

  Hmac.prototype._update = function(data) {
    this._hash.push(data)
  }

  Hmac.prototype._final = function() {
    var h = this._alg(Buffer.concat(this._hash))
    return this._alg(Buffer.concat([this._opad, h]))
  }
  return Hmac
}

var Legacy = fLegacy()



function fERROS() {
  function getTypeName(fn) {
    return fn.name || fn.toString().match(/function (.*?)\s*\(/)[1]
  }

  function getValueTypeName(value) {
    return native.Nil(value) ? '' : getTypeName(value.constructor)
  }

  function getValue(value) {
    if (native.Function(value)) return ''
    if (native.String(value)) return JSON.stringify(value)
    if (value && native.Object(value)) return ''
    return value
  }

  function captureStackTrace(e, t) {
    if (Error.captureStackTrace) {
      Error.captureStackTrace(e, t)
    }
  }

  function tfJSON(type) {
    if (native.Function(type)) return type.toJSON ? type.toJSON() : getTypeName(type)
    if (native.Array(type)) return 'Array'
    if (type && native.Object(type)) return 'Object'

    return type !== undefined ? type : ''
  }

  function tfErrorString(type, value, valueTypeName) {
    var valueJson = getValue(value)

    return 'Expected ' + tfJSON(type) + ', got' +
      (valueTypeName !== '' ? ' ' + valueTypeName : '') +
      (valueJson !== '' ? ' ' + valueJson : '')
  }

  function TfTypeError(type, value, valueTypeName) {
    valueTypeName = valueTypeName || getValueTypeName(value)
    this.message = tfErrorString(type, value, valueTypeName)

    captureStackTrace(this, TfTypeError)
    this.__type = type
    this.__value = value
    this.__valueTypeName = valueTypeName
  }

  TfTypeError.prototype = Object.create(Error.prototype)
  TfTypeError.prototype.constructor = TfTypeError

  function tfPropertyErrorString(type, label, name, value, valueTypeName) {
    var description = '" of type '
    if (label === 'key') description = '" with key type '

    return tfErrorString('property "' + tfJSON(name) + description + tfJSON(type), value, valueTypeName)
  }

  function TfPropertyTypeError(type, property, label, value, valueTypeName) {
    if (type) {
      valueTypeName = valueTypeName || getValueTypeName(value)
      this.message = tfPropertyErrorString(type, label, property, value, valueTypeName)
    } else {
      this.message = 'Unexpected property "' + property + '"'
    }

    captureStackTrace(this, TfTypeError)
    this.__label = label
    this.__property = property
    this.__type = type
    this.__value = value
    this.__valueTypeName = valueTypeName
  }

  TfPropertyTypeError.prototype = Object.create(Error.prototype)
  TfPropertyTypeError.prototype.constructor = TfTypeError

  function tfCustomError(expected, actual) {
    return new TfTypeError(expected, {}, actual)
  }

  function tfSubError(e, property, label) {
    // sub child?
    if (e instanceof TfPropertyTypeError) {
      property = property + '.' + e.__property

      e = new TfPropertyTypeError(
        e.__type, property, e.__label, e.__value, e.__valueTypeName
      )

      // child?
    } else if (e instanceof TfTypeError) {
      e = new TfPropertyTypeError(
        e.__type, property, label, e.__value, e.__valueTypeName
      )
    }

    captureStackTrace(e)
    return e
  }

  return {
    TfTypeError: TfTypeError,
    TfPropertyTypeError: TfPropertyTypeError,
    tfCustomError: tfCustomError,
    tfSubError: tfSubError,
    tfJSON: tfJSON,
    getValueTypeName: getValueTypeName
  }
}

var ERRORS = fERROS()

function fNATIVE() {
  var types = {
    Array: function(value) { return value !== null && value !== undefined && value.constructor === Array },
    Boolean: function(value) { return typeof value === 'boolean' },
    Function: function(value) { return typeof value === 'function' },
    Nil: function(value) { return value === undefined || value === null },
    Number: function(value) { return typeof value === 'number' },
    Object: function(value) { return typeof value === 'object' },
    String: function(value) { return typeof value === 'string' },
    '': function() { return true }
  }

  types.Null = types.Nil

  for (var typeName in types) {
    types[typeName].toJSON = function(t) {
      return t
    }.bind(null, typeName)
  }
  return types
}

var NATIVE = fNATIVE()


function fEXTRA() {
  function _Buffer(value) {
    return Buffer.isBuffer(value)
  }

  function Hex(value) {
    return typeof value === 'string' && /^([0-9a-f]{2})+$/i.test(value)
  }

  function _LengthN(type, length) {
    var name = type.toJSON()

    function Length(value) {
      if (!type(value)) return false
      if (value.length === length) return true

      throw ERRORS.tfCustomError(name + '(Length: ' + length + ')', name + '(Length: ' + value.length + ')')
    }
    Length.toJSON = function() { return name }

    return Length
  }

  var _ArrayN = _LengthN.bind(null, NATIVE.Array)
  var _BufferN = _LengthN.bind(null, _Buffer)
  var _HexN = _LengthN.bind(null, Hex)
  var _StringN = _LengthN.bind(null, NATIVE.String)

  function Range(a, b, f) {
    f = f || NATIVE.Number
    function _range(value, strict) {
      return f(value, strict) && (value > a) && (value < b)
    }
    _range.toJSON = function() {
      return `${f.toJSON()} between [${a}, ${b}]`
    }
    return _range
  }

  var INT53_MAX = Math.pow(2, 53) - 1

  function Finite(value) {
    return typeof value === 'number' && isFinite(value)
  }
  function Int8(value) { return ((value << 24) >> 24) === value }
  function Int16(value) { return ((value << 16) >> 16) === value }
  function Int32(value) { return (value | 0) === value }
  function Int53(value) {
    return typeof value === 'number' &&
      value >= -INT53_MAX &&
      value <= INT53_MAX &&
      Math.floor(value) === value
  }
  function UInt8(value) { return (value & 0xff) === value }
  function UInt16(value) { return (value & 0xffff) === value }
  function UInt32(value) { return (value >>> 0) === value }
  function UInt53(value) {
    return typeof value === 'number' &&
      value >= 0 &&
      value <= INT53_MAX &&
      Math.floor(value) === value
  }

  var types = {
    ArrayN: _ArrayN,
    Buffer: _Buffer,
    BufferN: _BufferN,
    Finite: Finite,
    Hex: Hex,
    HexN: _HexN,
    Int8: Int8,
    Int16: Int16,
    Int32: Int32,
    Int53: Int53,
    Range: Range,
    StringN: _StringN,
    UInt8: UInt8,
    UInt16: UInt16,
    UInt32: UInt32,
    UInt53: UInt53
  }

  for (var typeName in types) {
    types[typeName].toJSON = function(t) {
      return t
    }.bind(null, typeName)
  }
  return types
}

let EXTRA = fEXTRA()
// short-hand
var tfJSON = ERRORS.tfJSON
var TfTypeError = ERRORS.TfTypeError
var TfPropertyTypeError = ERRORS.TfPropertyTypeError
var tfSubError = ERRORS.tfSubError
var getValueTypeName = ERRORS.getValueTypeName

var TYPES = {
  arrayOf: function arrayOf(type, options) {
    type = compile(type)
    options = options || {}

    function _arrayOf(array, strict) {
      if (!NATIVE.Array(array)) return false
      if (NATIVE.Nil(array)) return false
      if (options.minLength !== undefined && array.length < options.minLength) return false
      if (options.maxLength !== undefined && array.length > options.maxLength) return false
      if (options.length !== undefined && array.length !== options.length) return false

      return array.every(function(value, i) {
        try {
          return typeforce(type, value, strict)
        } catch (e) {
          throw tfSubError(e, i)
        }
      })
    }
    _arrayOf.toJSON = function() {
      var str = '[' + tfJSON(type) + ']'
      if (options.length !== undefined) {
        str += '{' + options.length + '}'
      } else if (options.minLength !== undefined || options.maxLength !== undefined) {
        str += '{' +
          (options.minLength === undefined ? 0 : options.minLength) + ',' +
          (options.maxLength === undefined ? Infinity : options.maxLength) + '}'
      }
      return str
    }

    return _arrayOf
  },

  maybe: function maybe(type) {
    type = compile(type)

    function _maybe(value, strict) {
      return NATIVE.Nil(value) || type(value, strict, maybe)
    }
    _maybe.toJSON = function() { return '?' + tfJSON(type) }

    return _maybe
  },

  map: function map(propertyType, propertyKeyType) {
    propertyType = compile(propertyType)
    if (propertyKeyType) propertyKeyType = compile(propertyKeyType)

    function _map(value, strict) {
      if (!NATIVE.Object(value)) return false
      if (NATIVE.Nil(value)) return false

      for (var propertyName in value) {
        try {
          if (propertyKeyType) {
            typeforce(propertyKeyType, propertyName, strict)
          }
        } catch (e) {
          throw tfSubError(e, propertyName, 'key')
        }

        try {
          var propertyValue = value[propertyName]
          typeforce(propertyType, propertyValue, strict)
        } catch (e) {
          throw tfSubError(e, propertyName)
        }
      }

      return true
    }

    if (propertyKeyType) {
      _map.toJSON = function() {
        return '{' + tfJSON(propertyKeyType) + ': ' + tfJSON(propertyType) + '}'
      }
    } else {
      _map.toJSON = function() { return '{' + tfJSON(propertyType) + '}' }
    }

    return _map
  },

  object: function object(uncompiled) {
    var type = {}

    for (var typePropertyName in uncompiled) {
      type[typePropertyName] = compile(uncompiled[typePropertyName])
    }

    function _object(value, strict) {
      if (!NATIVE.Object(value)) return false
      if (NATIVE.Nil(value)) return false

      var propertyName

      try {
        for (propertyName in type) {
          var propertyType = type[propertyName]
          var propertyValue = value[propertyName]

          typeforce(propertyType, propertyValue, strict)
        }
      } catch (e) {
        throw tfSubError(e, propertyName)
      }

      if (strict) {
        for (propertyName in value) {
          if (type[propertyName]) continue

          throw new TfPropertyTypeError(undefined, propertyName)
        }
      }

      return true
    }
    _object.toJSON = function() { return tfJSON(type) }

    return _object
  },

  anyOf: function anyOf() {
    var types = [].slice.call(arguments).map(compile)

    function _anyOf(value, strict) {
      return types.some(function(type) {
        try {
          return typeforce(type, value, strict)
        } catch (e) {
          return false
        }
      })
    }
    _anyOf.toJSON = function() { return types.map(tfJSON).join('|') }

    return _anyOf
  },

  allOf: function allOf() {
    var types = [].slice.call(arguments).map(compile)

    function _allOf(value, strict) {
      return types.every(function(type) {
        try {
          return typeforce(type, value, strict)
        } catch (e) {
          return false
        }
      })
    }
    _allOf.toJSON = function() { return types.map(tfJSON).join(' & ') }

    return _allOf
  },

  quacksLike: function quacksLike(type) {
    function _quacksLike(value) {
      return type === getValueTypeName(value)
    }
    _quacksLike.toJSON = function() { return type }

    return _quacksLike
  },

  tuple: function tuple() {
    var types = [].slice.call(arguments).map(compile)

    function _tuple(values, strict) {
      if (NATIVE.Nil(values)) return false
      if (NATIVE.Nil(values.length)) return false
      if (strict && (values.length !== types.length)) return false

      return types.every(function(type, i) {
        try {
          return typeforce(type, values[i], strict)
        } catch (e) {
          throw tfSubError(e, i)
        }
      })
    }
    _tuple.toJSON = function() { return '(' + types.map(tfJSON).join(', ') + ')' }

    return _tuple
  },

  value: function value(expected) {
    function _value(actual) {
      return actual === expected
    }
    _value.toJSON = function() { return expected }

    return _value
  }
}

// TODO: deprecate
TYPES.oneOf = TYPES.anyOf

function compile(type) {
  if (NATIVE.String(type)) {
    if (type[0] === '?') return TYPES.maybe(type.slice(1))

    return NATIVE[type] || TYPES.quacksLike(type)
  } else if (type && NATIVE.Object(type)) {
    if (NATIVE.Array(type)) {
      if (type.length !== 1) throw new TypeError('Expected compile() parameter of type Array of length 1')
      return TYPES.arrayOf(type[0])
    }

    return TYPES.object(type)
  } else if (NATIVE.Function(type)) {
    return type
  }

  return TYPES.value(type)
}

function typeforce(type, value, strict, surrogate) {
  if (NATIVE.Function(type)) {
    if (type(value, strict)) return true

    throw new TfTypeError(surrogate || type, value)
  }

  // JIT
  return typeforce(compile(type), value, strict)
}

// assign types to typeforce function
for (var typeName in NATIVE) {
  typeforce[typeName] = NATIVE[typeName]
}

for (typeName in TYPES) {
  typeforce[typeName] = TYPES[typeName]
}

for (typeName in EXTRA) {
  typeforce[typeName] = EXTRA[typeName]
}

typeforce.compile = compile
typeforce.TfTypeError = TfTypeError
typeforce.TfPropertyTypeError = TfPropertyTypeError

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

var Hash = class {
};

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
    for (let pos = 0; pos < len;) {
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


var K = [
  0x428a2f98,
  0xd728ae22,
  0x71374491,
  0x23ef65cd,
  0xb5c0fbcf,
  0xec4d3b2f,
  0xe9b5dba5,
  0x8189dbbc,
  0x3956c25b,
  0xf348b538,
  0x59f111f1,
  0xb605d019,
  0x923f82a4,
  0xaf194f9b,
  0xab1c5ed5,
  0xda6d8118,
  0xd807aa98,
  0xa3030242,
  0x12835b01,
  0x45706fbe,
  0x243185be,
  0x4ee4b28c,
  0x550c7dc3,
  0xd5ffb4e2,
  0x72be5d74,
  0xf27b896f,
  0x80deb1fe,
  0x3b1696b1,
  0x9bdc06a7,
  0x25c71235,
  0xc19bf174,
  0xcf692694,
  0xe49b69c1,
  0x9ef14ad2,
  0xefbe4786,
  0x384f25e3,
  0x0fc19dc6,
  0x8b8cd5b5,
  0x240ca1cc,
  0x77ac9c65,
  0x2de92c6f,
  0x592b0275,
  0x4a7484aa,
  0x6ea6e483,
  0x5cb0a9dc,
  0xbd41fbd4,
  0x76f988da,
  0x831153b5,
  0x983e5152,
  0xee66dfab,
  0xa831c66d,
  0x2db43210,
  0xb00327c8,
  0x98fb213f,
  0xbf597fc7,
  0xbeef0ee4,
  0xc6e00bf3,
  0x3da88fc2,
  0xd5a79147,
  0x930aa725,
  0x06ca6351,
  0xe003826f,
  0x14292967,
  0x0a0e6e70,
  0x27b70a85,
  0x46d22ffc,
  0x2e1b2138,
  0x5c26c926,
  0x4d2c6dfc,
  0x5ac42aed,
  0x53380d13,
  0x9d95b3df,
  0x650a7354,
  0x8baf63de,
  0x766a0abb,
  0x3c77b2a8,
  0x81c2c92e,
  0x47edaee6,
  0x92722c85,
  0x1482353b,
  0xa2bfe8a1,
  0x4cf10364,
  0xa81a664b,
  0xbc423001,
  0xc24b8b70,
  0xd0f89791,
  0xc76c51a3,
  0x0654be30,
  0xd192e819,
  0xd6ef5218,
  0xd6990624,
  0x5565a910,
  0xf40e3585,
  0x5771202a,
  0x106aa070,
  0x32bbd1b8,
  0x19a4c116,
  0xb8d2d0c8,
  0x1e376c08,
  0x5141ab53,
  0x2748774c,
  0xdf8eeb99,
  0x34b0bcb5,
  0xe19b48a8,
  0x391c0cb3,
  0xc5c95a63,
  0x4ed8aa4a,
  0xe3418acb,
  0x5b9cca4f,
  0x7763e373,
  0x682e6ff3,
  0xd6b2b8a3,
  0x748f82ee,
  0x5defb2fc,
  0x78a5636f,
  0x43172f60,
  0x84c87814,
  0xa1f0ab72,
  0x8cc70208,
  0x1a6439ec,
  0x90befffa,
  0x23631e28,
  0xa4506ceb,
  0xde82bde9,
  0xbef9a3f7,
  0xb2c67915,
  0xc67178f2,
  0xe372532b,
  0xca273ece,
  0xea26619c,
  0xd186b8c7,
  0x21c0c207,
  0xeada7dd6,
  0xcde0eb1e,
  0xf57d4f7f,
  0xee6ed178,
  0x06f067aa,
  0x72176fba,
  0x0a637dc5,
  0xa2c898a6,
  0x113f9804,
  0xbef90dae,
  0x1b710b35,
  0x131c471b,
  0x28db77f5,
  0x23047d84,
  0x32caab7b,
  0x40c72493,
  0x3c9ebe0a,
  0x15c9bebc,
  0x431d67c4,
  0x9c100d4c,
  0x4cc5d4be,
  0xcb3e42b6,
  0x597f299c,
  0xfc657e2a,
  0x5fcb6fab,
  0x3ad6faec,
  0x6c44198c,
  0x4a475817
];

var W = new Array(160);

function sha512() {
  this.init();
  this._w = W;

  shaHashHash.call(this, 128, 112);
}

inherits(sha512, shaHashHash);

sha512.prototype.init = function() {
  this._ah = 0x6a09e667;
  this._bh = 0xbb67ae85;
  this._ch = 0x3c6ef372;
  this._dh = 0xa54ff53a;
  this._eh = 0x510e527f;
  this._fh = 0x9b05688c;
  this._gh = 0x1f83d9ab;
  this._hh = 0x5be0cd19;

  this._al = 0xf3bcc908;
  this._bl = 0x84caa73b;
  this._cl = 0xfe94f82b;
  this._dl = 0x5f1d36f1;
  this._el = 0xade682d1;
  this._fl = 0x2b3e6c1f;
  this._gl = 0xfb41bd6b;
  this._hl = 0x137e2179;

  return this;
};

function Ch(x, y, z) {
  return z ^ (x & (y ^ z));
}

function maj(x, y, z) {
  return (x & y) | (z & (x | y));
}

function sigma0(x, xl) {
  return ((x >>> 28) | (xl << 4)) ^ ((xl >>> 2) | (x << 30)) ^ ((xl >>> 7) | (x << 25));
}

function sigma1(x, xl) {
  return ((x >>> 14) | (xl << 18)) ^ ((x >>> 18) | (xl << 14)) ^ ((xl >>> 9) | (x << 23));
}

function Gamma0(x, xl) {
  return ((x >>> 1) | (xl << 31)) ^ ((x >>> 8) | (xl << 24)) ^ (x >>> 7);
}

function Gamma0l(x, xl) {
  return ((x >>> 1) | (xl << 31)) ^ ((x >>> 8) | (xl << 24)) ^ ((x >>> 7) | (xl << 25));
}

function Gamma1(x, xl) {
  return ((x >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (x << 3)) ^ (x >>> 6);
}

function Gamma1l(x, xl) {
  return ((x >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (x << 3)) ^ ((x >>> 6) | (xl << 26));
}

function getCarry(a, b) {
  return (a >>> 0) < (b >>> 0) ? 1 : 0;
}

sha512.prototype._update = function(M) {
  var w = this._w;

  var ah = this._ah | 0;
  var bh = this._bh | 0;
  var ch = this._ch | 0;
  var dh = this._dh | 0;
  var eh = this._eh | 0;
  var fh = this._fh | 0;
  var gh = this._gh | 0;
  var hh = this._hh | 0;

  var al = this._al | 0;
  var bl = this._bl | 0;
  var cl = this._cl | 0;
  var dl = this._dl | 0;
  var el = this._el | 0;
  var fl = this._fl | 0;
  var gl = this._gl | 0;
  var hl = this._hl | 0;

  for (var i = 0; i < 32; i += 2) {
    w[i] = M.readInt32BE(i * 4);
    w[i + 1] = M.readInt32BE((i * 4) + 4);
  }
  for (; i < 160; i += 2) {
    var xh = w[i - (15 * 2)];
    var xl = w[i - (15 * 2) + 1];
    var gamma0 = Gamma0(xh, xl);
    var gamma0l = Gamma0l(xl, xh);

    xh = w[i - (2 * 2)];
    xl = w[i - (2 * 2) + 1];
    var gamma1 = Gamma1(xh, xl);
    var gamma1l = Gamma1l(xl, xh);

    // w[i] = gamma0 + w[i - 7] + gamma1 + w[i - 16]
    var Wi7h = w[i - (7 * 2)];
    var Wi7l = w[i - (7 * 2) + 1];

    var Wi16h = w[i - (16 * 2)];
    var Wi16l = w[i - (16 * 2) + 1];

    var Wil = (gamma0l + Wi7l) | 0;
    var Wih = (gamma0 + Wi7h + getCarry(Wil, gamma0l)) | 0;
    Wil = (Wil + gamma1l) | 0;
    Wih = (Wih + gamma1 + getCarry(Wil, gamma1l)) | 0;
    Wil = (Wil + Wi16l) | 0;
    Wih = (Wih + Wi16h + getCarry(Wil, Wi16l)) | 0;

    w[i] = Wih;
    w[i + 1] = Wil;
  }

  for (var j = 0; j < 160; j += 2) {
    Wih = w[j];
    Wil = w[j + 1];

    var majh = maj(ah, bh, ch);
    var majl = maj(al, bl, cl);

    var sigma0h = sigma0(ah, al);
    var sigma0l = sigma0(al, ah);
    var sigma1h = sigma1(eh, el);
    var sigma1l = sigma1(el, eh);

    // t1 = h + sigma1 + ch + K[j] + w[j]
    var Kih = K[j];
    var Kil = K[j + 1];

    var chh = Ch(eh, fh, gh);
    var chl = Ch(el, fl, gl);

    var t1l = (hl + sigma1l) | 0;
    var t1h = (hh + sigma1h + getCarry(t1l, hl)) | 0;
    t1l = (t1l + chl) | 0;
    t1h = (t1h + chh + getCarry(t1l, chl)) | 0;
    t1l = (t1l + Kil) | 0;
    t1h = (t1h + Kih + getCarry(t1l, Kil)) | 0;
    t1l = (t1l + Wil) | 0;
    t1h = (t1h + Wih + getCarry(t1l, Wil)) | 0;

    // t2 = sigma0 + maj
    var t2l = (sigma0l + majl) | 0;
    var t2h = (sigma0h + majh + getCarry(t2l, sigma0l)) | 0;

    hh = gh;
    hl = gl;
    gh = fh;
    gl = fl;
    fh = eh;
    fl = el;
    el = (dl + t1l) | 0;
    eh = (dh + t1h + getCarry(el, dl)) | 0;
    dh = ch;
    dl = cl;
    ch = bh;
    cl = bl;
    bh = ah;
    bl = al;
    al = (t1l + t2l) | 0;
    ah = (t1h + t2h + getCarry(al, t1l)) | 0;
  }

  this._al = (this._al + al) | 0;
  this._bl = (this._bl + bl) | 0;
  this._cl = (this._cl + cl) | 0;
  this._dl = (this._dl + dl) | 0;
  this._el = (this._el + el) | 0;
  this._fl = (this._fl + fl) | 0;
  this._gl = (this._gl + gl) | 0;
  this._hl = (this._hl + hl) | 0;

  this._ah = (this._ah + ah + getCarry(this._al, al)) | 0;
  this._bh = (this._bh + bh + getCarry(this._bl, bl)) | 0;
  this._ch = (this._ch + ch + getCarry(this._cl, cl)) | 0;
  this._dh = (this._dh + dh + getCarry(this._dl, dl)) | 0;
  this._eh = (this._eh + eh + getCarry(this._el, el)) | 0;
  this._fh = (this._fh + fh + getCarry(this._fl, fl)) | 0;
  this._gh = (this._gh + gh + getCarry(this._gl, gl)) | 0;
  this._hh = (this._hh + hh + getCarry(this._hl, hl)) | 0;
};

sha512.prototype._hash = function() {
  var H = Buffer.allocUnsafe(64);

  function writeInt64BE(h, l, offset) {
    H.writeInt32BE(h, offset);
    H.writeInt32BE(l, offset + 4);
  }

  writeInt64BE(this._ah, this._al, 0);
  writeInt64BE(this._bh, this._bl, 8);
  writeInt64BE(this._ch, this._cl, 16);
  writeInt64BE(this._dh, this._dl, 24);
  writeInt64BE(this._eh, this._el, 32);
  writeInt64BE(this._fh, this._fl, 40);
  writeInt64BE(this._gh, this._gl, 48);
  writeInt64BE(this._hh, this._hl, 56);

  return H;
};


function createHmac(alg, key) {

  var md5 = MD5

  var ZEROS = Buffer.alloc(128)

  function Hmac(alg, key) {
    Base.call(this, 'digest')
    if (typeof key === 'string') {
      key = Buffer.from(key)
    }

    var blocksize = (alg === 'sha512' || alg === 'sha384') ? 128 : 64

    this._alg = alg
    this._key = key
    if (key.length > blocksize) {
      var hash = alg === 'rmd160' ? new RIPEMD160() : sha(alg)
      key = hash.update(key).digest()
    } else if (key.length < blocksize) {
      key = Buffer.concat([key, ZEROS], blocksize)
    }

    var ipad = this._ipad = Buffer.allocUnsafe(blocksize)
    var opad = this._opad = Buffer.allocUnsafe(blocksize)

    for (var i = 0; i < blocksize; i++) {
      ipad[i] = key[i] ^ 0x36
      opad[i] = key[i] ^ 0x5C
    }
    this._hash = alg === 'rmd160' ? new RIPEMD160() : sha(alg)
    this._hash.update(ipad)
  }

  inherits(Hmac, Base)

  Hmac.prototype._update = function(data) {
    this._hash.update(data)
  }

  Hmac.prototype._final = function() {
    var h = this._hash.digest()
    var hash = this._alg === 'rmd160' ? new RIPEMD160() : sha(this._alg)
    return hash.update(this._opad).update(Buffer.from(h)).digest()
  }

  function createHmac(alg, key) {
    alg = alg.toLowerCase()
    if (alg === 'rmd160' || alg === 'ripemd160') {
      return new Hmac('rmd160', key)
    }
    if (alg === 'md5') {
      return new Legacy(md5, key)
    }
    return new Hmac(alg, key)
  }
  return createHmac(alg, key)
}

// Utils
function assert(val, msg) {
  if (!val) throw new Error(msg || 'Assertion failed');
}

// Could use `inherits` module, but don't want to move from single file
// architecture yet.
function inherits(ctor, superCtor) {
  ctor.super_ = superCtor;
  var TempCtor = function() { };
  TempCtor.prototype = superCtor.prototype;
  ctor.prototype = new TempCtor();
  ctor.prototype.constructor = ctor;
}

// BN

function BN(number, base, endian) {
  if (BN.isBN(number)) {
    return number;
  }

  this.negative = 0;
  this.words = null;
  this.length = 0;

  // Reduction context
  this.red = null;

  if (number !== null) {
    if (base === 'le' || base === 'be') {
      endian = base;
      base = 10;
    }

    this._init(number || 0, base || 10, endian || 'be');
  }
}
if (typeof module === 'object') {
  module.exports = BN;
} else {
  exports.BN = BN;
}

BN.BN = BN;
BN.wordSize = 26;

try {
  if (typeof window !== 'undefined' && typeof window.Buffer !== 'undefined') {
    Buffer = window.Buffer;
  }
} catch (e) {
}

BN.isBN = function isBN(num) {
  if (num instanceof BN) {
    return true;
  }

  return num !== null && typeof num === 'object' &&
    num.constructor.wordSize === BN.wordSize && Array.isArray(num.words);
};

BN.max = function max(left, right) {
  if (left.cmp(right) > 0) return left;
  return right;
};

BN.min = function min(left, right) {
  if (left.cmp(right) < 0) return left;
  return right;
};

BN.prototype._init = function init(number, base, endian) {
  if (typeof number === 'number') {
    return this._initNumber(number, base, endian);
  }

  if (typeof number === 'object') {
    return this._initArray(number, base, endian);
  }

  if (base === 'hex') {
    base = 16;
  }
  assert(base === (base | 0) && base >= 2 && base <= 36);

  number = number.toString().replace(/\s+/g, '');
  var start = 0;
  if (number[0] === '-') {
    start++;
    this.negative = 1;
  }

  if (start < number.length) {
    if (base === 16) {
      this._parseHex(number, start, endian);
    } else {
      this._parseBase(number, base, start);
      if (endian === 'le') {
        this._initArray(this.toArray(), base, endian);
      }
    }
  }
};

BN.prototype._initNumber = function _initNumber(number, base, endian) {
  if (number < 0) {
    this.negative = 1;
    number = -number;
  }
  if (number < 0x4000000) {
    this.words = [number & 0x3ffffff];
    this.length = 1;
  } else if (number < 0x10000000000000) {
    this.words = [
      number & 0x3ffffff,
      (number / 0x4000000) & 0x3ffffff
    ];
    this.length = 2;
  } else {
    assert(number < 0x20000000000000); // 2 ^ 53 (unsafe)
    this.words = [
      number & 0x3ffffff,
      (number / 0x4000000) & 0x3ffffff,
      1
    ];
    this.length = 3;
  }

  if (endian !== 'le') return;

  // Reverse the bytes
  this._initArray(this.toArray(), base, endian);
};

BN.prototype._initArray = function _initArray(number, base, endian) {
  // Perhaps a Uint8Array
  assert(typeof number.length === 'number');
  if (number.length <= 0) {
    this.words = [0];
    this.length = 1;
    return this;
  }

  this.length = Math.ceil(number.length / 3);
  this.words = new Array(this.length);
  for (var i = 0; i < this.length; i++) {
    this.words[i] = 0;
  }

  var j, w;
  var off = 0;
  if (endian === 'be') {
    for (i = number.length - 1, j = 0; i >= 0; i -= 3) {
      w = number[i] | (number[i - 1] << 8) | (number[i - 2] << 16);
      this.words[j] |= (w << off) & 0x3ffffff;
      this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;
      off += 24;
      if (off >= 26) {
        off -= 26;
        j++;
      }
    }
  } else if (endian === 'le') {
    for (i = 0, j = 0; i < number.length; i += 3) {
      w = number[i] | (number[i + 1] << 8) | (number[i + 2] << 16);
      this.words[j] |= (w << off) & 0x3ffffff;
      this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;
      off += 24;
      if (off >= 26) {
        off -= 26;
        j++;
      }
    }
  }
  return this.strip();
};

function parseHex4Bits(string, index) {
  var c = string.charCodeAt(index);
  // 'A' - 'F'
  if (c >= 65 && c <= 70) {
    return c - 55;
    // 'a' - 'f'
  } else if (c >= 97 && c <= 102) {
    return c - 87;
    // '0' - '9'
  } else {
    return (c - 48) & 0xf;
  }
}

function parseHexByte(string, lowerBound, index) {
  var r = parseHex4Bits(string, index);
  if (index - 1 >= lowerBound) {
    r |= parseHex4Bits(string, index - 1) << 4;
  }
  return r;
}

BN.prototype._parseHex = function _parseHex(number, start, endian) {
  // Create possibly bigger array to ensure that it fits the number
  this.length = Math.ceil((number.length - start) / 6);
  this.words = new Array(this.length);
  for (var i = 0; i < this.length; i++) {
    this.words[i] = 0;
  }

  // 24-bits chunks
  var off = 0;
  var j = 0;

  var w;
  if (endian === 'be') {
    for (i = number.length - 1; i >= start; i -= 2) {
      w = parseHexByte(number, start, i) << off;
      this.words[j] |= w & 0x3ffffff;
      if (off >= 18) {
        off -= 18;
        j += 1;
        this.words[j] |= w >>> 26;
      } else {
        off += 8;
      }
    }
  } else {
    var parseLength = number.length - start;
    for (i = parseLength % 2 === 0 ? start + 1 : start; i < number.length; i += 2) {
      w = parseHexByte(number, start, i) << off;
      this.words[j] |= w & 0x3ffffff;
      if (off >= 18) {
        off -= 18;
        j += 1;
        this.words[j] |= w >>> 26;
      } else {
        off += 8;
      }
    }
  }

  this.strip();
};

function parseBase(str, start, end, mul) {
  var r = 0;
  var len = Math.min(str.length, end);
  for (var i = start; i < len; i++) {
    var c = str.charCodeAt(i) - 48;

    r *= mul;

    // 'a'
    if (c >= 49) {
      r += c - 49 + 0xa;

      // 'A'
    } else if (c >= 17) {
      r += c - 17 + 0xa;

      // '0' - '9'
    } else {
      r += c;
    }
  }
  return r;
}

BN.prototype._parseBase = function _parseBase(number, base, start) {
  // Initialize as zero
  this.words = [0];
  this.length = 1;

  // Find length of limb in base
  for (var limbLen = 0, limbPow = 1; limbPow <= 0x3ffffff; limbPow *= base) {
    limbLen++;
  }
  limbLen--;
  limbPow = (limbPow / base) | 0;

  var total = number.length - start;
  var mod = total % limbLen;
  var end = Math.min(total, total - mod) + start;

  var word = 0;
  for (var i = start; i < end; i += limbLen) {
    word = parseBase(number, i, i + limbLen, base);

    this.imuln(limbPow);
    if (this.words[0] + word < 0x4000000) {
      this.words[0] += word;
    } else {
      this._iaddn(word);
    }
  }

  if (mod !== 0) {
    var pow = 1;
    word = parseBase(number, i, number.length, base);

    for (i = 0; i < mod; i++) {
      pow *= base;
    }

    this.imuln(pow);
    if (this.words[0] + word < 0x4000000) {
      this.words[0] += word;
    } else {
      this._iaddn(word);
    }
  }

  this.strip();
};

BN.prototype.copy = function copy(dest) {
  dest.words = new Array(this.length);
  for (var i = 0; i < this.length; i++) {
    dest.words[i] = this.words[i];
  }
  dest.length = this.length;
  dest.negative = this.negative;
  dest.red = this.red;
};

BN.prototype.clone = function clone() {
  var r = new BN(null);
  this.copy(r);
  return r;
};

BN.prototype._expand = function _expand(size) {
  while (this.length < size) {
    this.words[this.length++] = 0;
  }
  return this;
};

// Remove leading `0` from `this`
BN.prototype.strip = function strip() {
  while (this.length > 1 && this.words[this.length - 1] === 0) {
    this.length--;
  }
  return this._normSign();
};

BN.prototype._normSign = function _normSign() {
  // -0 = 0
  if (this.length === 1 && this.words[0] === 0) {
    this.negative = 0;
  }
  return this;
};

BN.prototype.inspect = function inspect() {
  return (this.red ? '<BN-R: ' : '<BN: ') + this.toString(16) + '>';
};

/*

var zeros = [];
var groupSizes = [];
var groupBases = [];

var s = '';
var i = -1;
while (++i < BN.wordSize) {
  zeros[i] = s;
  s += '0';
}
groupSizes[0] = 0;
groupSizes[1] = 0;
groupBases[0] = 0;
groupBases[1] = 0;
var base = 2 - 1;
while (++base < 36 + 1) {
  var groupSize = 0;
  var groupBase = 1;
  while (groupBase < (1 << BN.wordSize) / base) {
    groupBase *= base;
    groupSize += 1;
  }
  groupSizes[base] = groupSize;
  groupBases[base] = groupBase;
}

*/

var zeros = [
  '',
  '0',
  '00',
  '000',
  '0000',
  '00000',
  '000000',
  '0000000',
  '00000000',
  '000000000',
  '0000000000',
  '00000000000',
  '000000000000',
  '0000000000000',
  '00000000000000',
  '000000000000000',
  '0000000000000000',
  '00000000000000000',
  '000000000000000000',
  '0000000000000000000',
  '00000000000000000000',
  '000000000000000000000',
  '0000000000000000000000',
  '00000000000000000000000',
  '000000000000000000000000',
  '0000000000000000000000000'
];

var groupSizes = [
  0, 0,
  25, 16, 12, 11, 10, 9, 8,
  8, 7, 7, 7, 7, 6, 6,
  6, 6, 6, 6, 6, 5, 5,
  5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5
];

var groupBases = [
  0, 0,
  33554432, 43046721, 16777216, 48828125, 60466176, 40353607, 16777216,
  43046721, 10000000, 19487171, 35831808, 62748517, 7529536, 11390625,
  16777216, 24137569, 34012224, 47045881, 64000000, 4084101, 5153632,
  6436343, 7962624, 9765625, 11881376, 14348907, 17210368, 20511149,
  24300000, 28629151, 33554432, 39135393, 45435424, 52521875, 60466176
];

BN.prototype.toString = function toString(base, padding) {
  base = base || 10;
  padding = padding | 0 || 1;

  var out;
  if (base === 16 || base === 'hex') {
    out = '';
    var off = 0;
    var carry = 0;
    for (var i = 0; i < this.length; i++) {
      var w = this.words[i];
      var word = (((w << off) | carry) & 0xffffff).toString(16);
      carry = (w >>> (24 - off)) & 0xffffff;
      off += 2;
      if (off >= 26) {
        off -= 26;
        i--;
      }
      if (carry !== 0 || i !== this.length - 1) {
        out = zeros[6 - word.length] + word + out;
      } else {
        out = word + out;
      }
    }
    if (carry !== 0) {
      out = carry.toString(16) + out;
    }
    while (out.length % padding !== 0) {
      out = '0' + out;
    }
    if (this.negative !== 0) {
      out = '-' + out;
    }
    return out;
  }

  if (base === (base | 0) && base >= 2 && base <= 36) {
    // var groupSize = Math.floor(BN.wordSize * Math.LN2 / Math.log(base));
    var groupSize = groupSizes[base];
    // var groupBase = Math.pow(base, groupSize);
    var groupBase = groupBases[base];
    out = '';
    var c = this.clone();
    c.negative = 0;
    while (!c.isZero()) {
      var r = c.modn(groupBase).toString(base);
      c = c.idivn(groupBase);

      if (!c.isZero()) {
        out = zeros[groupSize - r.length] + r + out;
      } else {
        out = r + out;
      }
    }
    if (this.isZero()) {
      out = '0' + out;
    }
    while (out.length % padding !== 0) {
      out = '0' + out;
    }
    if (this.negative !== 0) {
      out = '-' + out;
    }
    return out;
  }

  assert(false, 'Base should be between 2 and 36');
};

BN.prototype.toNumber = function toNumber() {
  var ret = this.words[0];
  if (this.length === 2) {
    ret += this.words[1] * 0x4000000;
  } else if (this.length === 3 && this.words[2] === 0x01) {
    // NOTE: at this stage it is known that the top bit is set
    ret += 0x10000000000000 + (this.words[1] * 0x4000000);
  } else if (this.length > 2) {
    assert(false, 'Number can only safely store up to 53 bits');
  }
  return (this.negative !== 0) ? -ret : ret;
};

BN.prototype.toJSON = function toJSON() {
  return this.toString(16);
};

BN.prototype.toBuffer = function toBuffer(endian, length) {
  assert(typeof Buffer !== 'undefined');
  return this.toArrayLike(Buffer, endian, length);
};

BN.prototype.toArray = function toArray(endian, length) {
  return this.toArrayLike(Array, endian, length);
};

BN.prototype.toArrayLike = function toArrayLike(ArrayType, endian, length) {
  var byteLength = this.byteLength();
  var reqLength = length || Math.max(1, byteLength);
  assert(byteLength <= reqLength, 'byte array longer than desired length');
  assert(reqLength > 0, 'Requested array length <= 0');

  this.strip();
  var littleEndian = endian === 'le';
  var res = new ArrayType(reqLength);

  var b, i;
  var q = this.clone();
  if (!littleEndian) {
    // Assume big-endian
    for (i = 0; i < reqLength - byteLength; i++) {
      res[i] = 0;
    }

    for (i = 0; !q.isZero(); i++) {
      b = q.andln(0xff);
      q.iushrn(8);

      res[reqLength - i - 1] = b;
    }
  } else {
    for (i = 0; !q.isZero(); i++) {
      b = q.andln(0xff);
      q.iushrn(8);

      res[i] = b;
    }

    for (; i < reqLength; i++) {
      res[i] = 0;
    }
  }

  return res;
};

if (Math.clz32) {
  BN.prototype._countBits = function _countBits(w) {
    return 32 - Math.clz32(w);
  };
} else {
  BN.prototype._countBits = function _countBits(w) {
    var t = w;
    var r = 0;
    if (t >= 0x1000) {
      r += 13;
      t >>>= 13;
    }
    if (t >= 0x40) {
      r += 7;
      t >>>= 7;
    }
    if (t >= 0x8) {
      r += 4;
      t >>>= 4;
    }
    if (t >= 0x02) {
      r += 2;
      t >>>= 2;
    }
    return r + t;
  };
}

BN.prototype._zeroBits = function _zeroBits(w) {
  // Short-cut
  if (w === 0) return 26;

  var t = w;
  var r = 0;
  if ((t & 0x1fff) === 0) {
    r += 13;
    t >>>= 13;
  }
  if ((t & 0x7f) === 0) {
    r += 7;
    t >>>= 7;
  }
  if ((t & 0xf) === 0) {
    r += 4;
    t >>>= 4;
  }
  if ((t & 0x3) === 0) {
    r += 2;
    t >>>= 2;
  }
  if ((t & 0x1) === 0) {
    r++;
  }
  return r;
};

// Return number of used bits in a BN
BN.prototype.bitLength = function bitLength() {
  var w = this.words[this.length - 1];
  var hi = this._countBits(w);
  return (this.length - 1) * 26 + hi;
};

function toBitArray(num) {
  var w = new Array(num.bitLength());

  for (var bit = 0; bit < w.length; bit++) {
    var off = (bit / 26) | 0;
    var wbit = bit % 26;

    w[bit] = (num.words[off] & (1 << wbit)) >>> wbit;
  }

  return w;
}

// Number of trailing zero bits
BN.prototype.zeroBits = function zeroBits() {
  if (this.isZero()) return 0;

  var r = 0;
  for (var i = 0; i < this.length; i++) {
    var b = this._zeroBits(this.words[i]);
    r += b;
    if (b !== 26) break;
  }
  return r;
};

BN.prototype.byteLength = function byteLength() {
  return Math.ceil(this.bitLength() / 8);
};

BN.prototype.toTwos = function toTwos(width) {
  if (this.negative !== 0) {
    return this.abs().inotn(width).iaddn(1);
  }
  return this.clone();
};

BN.prototype.fromTwos = function fromTwos(width) {
  if (this.testn(width - 1)) {
    return this.notn(width).iaddn(1).ineg();
  }
  return this.clone();
};

BN.prototype.isNeg = function isNeg() {
  return this.negative !== 0;
};

// Return negative clone of `this`
BN.prototype.neg = function neg() {
  return this.clone().ineg();
};

BN.prototype.ineg = function ineg() {
  if (!this.isZero()) {
    this.negative ^= 1;
  }

  return this;
};

// Or `num` with `this` in-place
BN.prototype.iuor = function iuor(num) {
  while (this.length < num.length) {
    this.words[this.length++] = 0;
  }

  for (var i = 0; i < num.length; i++) {
    this.words[i] = this.words[i] | num.words[i];
  }

  return this.strip();
};

BN.prototype.ior = function ior(num) {
  assert((this.negative | num.negative) === 0);
  return this.iuor(num);
};

// Or `num` with `this`
BN.prototype.or = function or(num) {
  if (this.length > num.length) return this.clone().ior(num);
  return num.clone().ior(this);
};

BN.prototype.uor = function uor(num) {
  if (this.length > num.length) return this.clone().iuor(num);
  return num.clone().iuor(this);
};

// And `num` with `this` in-place
BN.prototype.iuand = function iuand(num) {
  // b = min-length(num, this)
  var b;
  if (this.length > num.length) {
    b = num;
  } else {
    b = this;
  }

  for (var i = 0; i < b.length; i++) {
    this.words[i] = this.words[i] & num.words[i];
  }

  this.length = b.length;

  return this.strip();
};

BN.prototype.iand = function iand(num) {
  assert((this.negative | num.negative) === 0);
  return this.iuand(num);
};

// And `num` with `this`
BN.prototype.and = function and(num) {
  if (this.length > num.length) return this.clone().iand(num);
  return num.clone().iand(this);
};

BN.prototype.uand = function uand(num) {
  if (this.length > num.length) return this.clone().iuand(num);
  return num.clone().iuand(this);
};

// Xor `num` with `this` in-place
BN.prototype.iuxor = function iuxor(num) {
  // a.length > b.length
  var a;
  var b;
  if (this.length > num.length) {
    a = this;
    b = num;
  } else {
    a = num;
    b = this;
  }

  for (var i = 0; i < b.length; i++) {
    this.words[i] = a.words[i] ^ b.words[i];
  }

  if (this !== a) {
    for (; i < a.length; i++) {
      this.words[i] = a.words[i];
    }
  }

  this.length = a.length;

  return this.strip();
};

BN.prototype.ixor = function ixor(num) {
  assert((this.negative | num.negative) === 0);
  return this.iuxor(num);
};

// Xor `num` with `this`
BN.prototype.xor = function xor(num) {
  if (this.length > num.length) return this.clone().ixor(num);
  return num.clone().ixor(this);
};

BN.prototype.uxor = function uxor(num) {
  if (this.length > num.length) return this.clone().iuxor(num);
  return num.clone().iuxor(this);
};

// Not ``this`` with ``width`` bitwidth
BN.prototype.inotn = function inotn(width) {
  assert(typeof width === 'number' && width >= 0);

  var bytesNeeded = Math.ceil(width / 26) | 0;
  var bitsLeft = width % 26;

  // Extend the buffer with leading zeroes
  this._expand(bytesNeeded);

  if (bitsLeft > 0) {
    bytesNeeded--;
  }

  // Handle complete words
  for (var i = 0; i < bytesNeeded; i++) {
    this.words[i] = ~this.words[i] & 0x3ffffff;
  }

  // Handle the residue
  if (bitsLeft > 0) {
    this.words[i] = ~this.words[i] & (0x3ffffff >> (26 - bitsLeft));
  }

  // And remove leading zeroes
  return this.strip();
};

BN.prototype.notn = function notn(width) {
  return this.clone().inotn(width);
};

// Set `bit` of `this`
BN.prototype.setn = function setn(bit, val) {
  assert(typeof bit === 'number' && bit >= 0);

  var off = (bit / 26) | 0;
  var wbit = bit % 26;

  this._expand(off + 1);

  if (val) {
    this.words[off] = this.words[off] | (1 << wbit);
  } else {
    this.words[off] = this.words[off] & ~(1 << wbit);
  }

  return this.strip();
};

// Add `num` to `this` in-place
BN.prototype.iadd = function iadd(num) {
  var r;

  // negative + positive
  if (this.negative !== 0 && num.negative === 0) {
    this.negative = 0;
    r = this.isub(num);
    this.negative ^= 1;
    return this._normSign();

    // positive + negative
  } else if (this.negative === 0 && num.negative !== 0) {
    num.negative = 0;
    r = this.isub(num);
    num.negative = 1;
    return r._normSign();
  }

  // a.length > b.length
  var a, b;
  if (this.length > num.length) {
    a = this;
    b = num;
  } else {
    a = num;
    b = this;
  }

  var carry = 0;
  for (var i = 0; i < b.length; i++) {
    r = (a.words[i] | 0) + (b.words[i] | 0) + carry;
    this.words[i] = r & 0x3ffffff;
    carry = r >>> 26;
  }
  for (; carry !== 0 && i < a.length; i++) {
    r = (a.words[i] | 0) + carry;
    this.words[i] = r & 0x3ffffff;
    carry = r >>> 26;
  }

  this.length = a.length;
  if (carry !== 0) {
    this.words[this.length] = carry;
    this.length++;
    // Copy the rest of the words
  } else if (a !== this) {
    for (; i < a.length; i++) {
      this.words[i] = a.words[i];
    }
  }

  return this;
};

// Add `num` to `this`
BN.prototype.add = function add(num) {
  var res;
  if (num.negative !== 0 && this.negative === 0) {
    num.negative = 0;
    res = this.sub(num);
    num.negative ^= 1;
    return res;
  } else if (num.negative === 0 && this.negative !== 0) {
    this.negative = 0;
    res = num.sub(this);
    this.negative = 1;
    return res;
  }

  if (this.length > num.length) return this.clone().iadd(num);

  return num.clone().iadd(this);
};

// Subtract `num` from `this` in-place
BN.prototype.isub = function isub(num) {
  // this - (-num) = this + num
  if (num.negative !== 0) {
    num.negative = 0;
    var r = this.iadd(num);
    num.negative = 1;
    return r._normSign();

    // -this - num = -(this + num)
  } else if (this.negative !== 0) {
    this.negative = 0;
    this.iadd(num);
    this.negative = 1;
    return this._normSign();
  }

  // At this point both numbers are positive
  var cmp = this.cmp(num);

  // Optimization - zeroify
  if (cmp === 0) {
    this.negative = 0;
    this.length = 1;
    this.words[0] = 0;
    return this;
  }

  // a > b
  var a, b;
  if (cmp > 0) {
    a = this;
    b = num;
  } else {
    a = num;
    b = this;
  }

  var carry = 0;
  for (var i = 0; i < b.length; i++) {
    r = (a.words[i] | 0) - (b.words[i] | 0) + carry;
    carry = r >> 26;
    this.words[i] = r & 0x3ffffff;
  }
  for (; carry !== 0 && i < a.length; i++) {
    r = (a.words[i] | 0) + carry;
    carry = r >> 26;
    this.words[i] = r & 0x3ffffff;
  }

  // Copy rest of the words
  if (carry === 0 && i < a.length && a !== this) {
    for (; i < a.length; i++) {
      this.words[i] = a.words[i];
    }
  }

  this.length = Math.max(this.length, i);

  if (a !== this) {
    this.negative = 1;
  }

  return this.strip();
};

// Subtract `num` from `this`
BN.prototype.sub = function sub(num) {
  return this.clone().isub(num);
};

function smallMulTo(self, num, out) {
  out.negative = num.negative ^ self.negative;
  var len = (self.length + num.length) | 0;
  out.length = len;
  len = (len - 1) | 0;

  // Peel one iteration (compiler can't do it, because of code complexity)
  var a = self.words[0] | 0;
  var b = num.words[0] | 0;
  var r = a * b;

  var lo = r & 0x3ffffff;
  var carry = (r / 0x4000000) | 0;
  out.words[0] = lo;

  for (var k = 1; k < len; k++) {
    // Sum all words with the same `i + j = k` and accumulate `ncarry`,
    // note that ncarry could be >= 0x3ffffff
    var ncarry = carry >>> 26;
    var rword = carry & 0x3ffffff;
    var maxJ = Math.min(k, num.length - 1);
    for (var j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
      var i = (k - j) | 0;
      a = self.words[i] | 0;
      b = num.words[j] | 0;
      r = a * b + rword;
      ncarry += (r / 0x4000000) | 0;
      rword = r & 0x3ffffff;
    }
    out.words[k] = rword | 0;
    carry = ncarry | 0;
  }
  if (carry !== 0) {
    out.words[k] = carry | 0;
  } else {
    out.length--;
  }

  return out.strip();
}

// TODO(indutny): it may be reasonable to omit it for users who don't need
// to work with 256-bit numbers, otherwise it gives 20% improvement for 256-bit
// multiplication (like elliptic secp256k1).
var comb10MulTo = function comb10MulTo(self, num, out) {
  var a = self.words;
  var b = num.words;
  var o = out.words;
  var c = 0;
  var lo;
  var mid;
  var hi;
  var a0 = a[0] | 0;
  var al0 = a0 & 0x1fff;
  var ah0 = a0 >>> 13;
  var a1 = a[1] | 0;
  var al1 = a1 & 0x1fff;
  var ah1 = a1 >>> 13;
  var a2 = a[2] | 0;
  var al2 = a2 & 0x1fff;
  var ah2 = a2 >>> 13;
  var a3 = a[3] | 0;
  var al3 = a3 & 0x1fff;
  var ah3 = a3 >>> 13;
  var a4 = a[4] | 0;
  var al4 = a4 & 0x1fff;
  var ah4 = a4 >>> 13;
  var a5 = a[5] | 0;
  var al5 = a5 & 0x1fff;
  var ah5 = a5 >>> 13;
  var a6 = a[6] | 0;
  var al6 = a6 & 0x1fff;
  var ah6 = a6 >>> 13;
  var a7 = a[7] | 0;
  var al7 = a7 & 0x1fff;
  var ah7 = a7 >>> 13;
  var a8 = a[8] | 0;
  var al8 = a8 & 0x1fff;
  var ah8 = a8 >>> 13;
  var a9 = a[9] | 0;
  var al9 = a9 & 0x1fff;
  var ah9 = a9 >>> 13;
  var b0 = b[0] | 0;
  var bl0 = b0 & 0x1fff;
  var bh0 = b0 >>> 13;
  var b1 = b[1] | 0;
  var bl1 = b1 & 0x1fff;
  var bh1 = b1 >>> 13;
  var b2 = b[2] | 0;
  var bl2 = b2 & 0x1fff;
  var bh2 = b2 >>> 13;
  var b3 = b[3] | 0;
  var bl3 = b3 & 0x1fff;
  var bh3 = b3 >>> 13;
  var b4 = b[4] | 0;
  var bl4 = b4 & 0x1fff;
  var bh4 = b4 >>> 13;
  var b5 = b[5] | 0;
  var bl5 = b5 & 0x1fff;
  var bh5 = b5 >>> 13;
  var b6 = b[6] | 0;
  var bl6 = b6 & 0x1fff;
  var bh6 = b6 >>> 13;
  var b7 = b[7] | 0;
  var bl7 = b7 & 0x1fff;
  var bh7 = b7 >>> 13;
  var b8 = b[8] | 0;
  var bl8 = b8 & 0x1fff;
  var bh8 = b8 >>> 13;
  var b9 = b[9] | 0;
  var bl9 = b9 & 0x1fff;
  var bh9 = b9 >>> 13;

  out.negative = self.negative ^ num.negative;
  out.length = 19;
  /* k = 0 */
  lo = Math.imul(al0, bl0);
  mid = Math.imul(al0, bh0);
  mid = (mid + Math.imul(ah0, bl0)) | 0;
  hi = Math.imul(ah0, bh0);
  var w0 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w0 >>> 26)) | 0;
  w0 &= 0x3ffffff;
  /* k = 1 */
  lo = Math.imul(al1, bl0);
  mid = Math.imul(al1, bh0);
  mid = (mid + Math.imul(ah1, bl0)) | 0;
  hi = Math.imul(ah1, bh0);
  lo = (lo + Math.imul(al0, bl1)) | 0;
  mid = (mid + Math.imul(al0, bh1)) | 0;
  mid = (mid + Math.imul(ah0, bl1)) | 0;
  hi = (hi + Math.imul(ah0, bh1)) | 0;
  var w1 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w1 >>> 26)) | 0;
  w1 &= 0x3ffffff;
  /* k = 2 */
  lo = Math.imul(al2, bl0);
  mid = Math.imul(al2, bh0);
  mid = (mid + Math.imul(ah2, bl0)) | 0;
  hi = Math.imul(ah2, bh0);
  lo = (lo + Math.imul(al1, bl1)) | 0;
  mid = (mid + Math.imul(al1, bh1)) | 0;
  mid = (mid + Math.imul(ah1, bl1)) | 0;
  hi = (hi + Math.imul(ah1, bh1)) | 0;
  lo = (lo + Math.imul(al0, bl2)) | 0;
  mid = (mid + Math.imul(al0, bh2)) | 0;
  mid = (mid + Math.imul(ah0, bl2)) | 0;
  hi = (hi + Math.imul(ah0, bh2)) | 0;
  var w2 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w2 >>> 26)) | 0;
  w2 &= 0x3ffffff;
  /* k = 3 */
  lo = Math.imul(al3, bl0);
  mid = Math.imul(al3, bh0);
  mid = (mid + Math.imul(ah3, bl0)) | 0;
  hi = Math.imul(ah3, bh0);
  lo = (lo + Math.imul(al2, bl1)) | 0;
  mid = (mid + Math.imul(al2, bh1)) | 0;
  mid = (mid + Math.imul(ah2, bl1)) | 0;
  hi = (hi + Math.imul(ah2, bh1)) | 0;
  lo = (lo + Math.imul(al1, bl2)) | 0;
  mid = (mid + Math.imul(al1, bh2)) | 0;
  mid = (mid + Math.imul(ah1, bl2)) | 0;
  hi = (hi + Math.imul(ah1, bh2)) | 0;
  lo = (lo + Math.imul(al0, bl3)) | 0;
  mid = (mid + Math.imul(al0, bh3)) | 0;
  mid = (mid + Math.imul(ah0, bl3)) | 0;
  hi = (hi + Math.imul(ah0, bh3)) | 0;
  var w3 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w3 >>> 26)) | 0;
  w3 &= 0x3ffffff;
  /* k = 4 */
  lo = Math.imul(al4, bl0);
  mid = Math.imul(al4, bh0);
  mid = (mid + Math.imul(ah4, bl0)) | 0;
  hi = Math.imul(ah4, bh0);
  lo = (lo + Math.imul(al3, bl1)) | 0;
  mid = (mid + Math.imul(al3, bh1)) | 0;
  mid = (mid + Math.imul(ah3, bl1)) | 0;
  hi = (hi + Math.imul(ah3, bh1)) | 0;
  lo = (lo + Math.imul(al2, bl2)) | 0;
  mid = (mid + Math.imul(al2, bh2)) | 0;
  mid = (mid + Math.imul(ah2, bl2)) | 0;
  hi = (hi + Math.imul(ah2, bh2)) | 0;
  lo = (lo + Math.imul(al1, bl3)) | 0;
  mid = (mid + Math.imul(al1, bh3)) | 0;
  mid = (mid + Math.imul(ah1, bl3)) | 0;
  hi = (hi + Math.imul(ah1, bh3)) | 0;
  lo = (lo + Math.imul(al0, bl4)) | 0;
  mid = (mid + Math.imul(al0, bh4)) | 0;
  mid = (mid + Math.imul(ah0, bl4)) | 0;
  hi = (hi + Math.imul(ah0, bh4)) | 0;
  var w4 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w4 >>> 26)) | 0;
  w4 &= 0x3ffffff;
  /* k = 5 */
  lo = Math.imul(al5, bl0);
  mid = Math.imul(al5, bh0);
  mid = (mid + Math.imul(ah5, bl0)) | 0;
  hi = Math.imul(ah5, bh0);
  lo = (lo + Math.imul(al4, bl1)) | 0;
  mid = (mid + Math.imul(al4, bh1)) | 0;
  mid = (mid + Math.imul(ah4, bl1)) | 0;
  hi = (hi + Math.imul(ah4, bh1)) | 0;
  lo = (lo + Math.imul(al3, bl2)) | 0;
  mid = (mid + Math.imul(al3, bh2)) | 0;
  mid = (mid + Math.imul(ah3, bl2)) | 0;
  hi = (hi + Math.imul(ah3, bh2)) | 0;
  lo = (lo + Math.imul(al2, bl3)) | 0;
  mid = (mid + Math.imul(al2, bh3)) | 0;
  mid = (mid + Math.imul(ah2, bl3)) | 0;
  hi = (hi + Math.imul(ah2, bh3)) | 0;
  lo = (lo + Math.imul(al1, bl4)) | 0;
  mid = (mid + Math.imul(al1, bh4)) | 0;
  mid = (mid + Math.imul(ah1, bl4)) | 0;
  hi = (hi + Math.imul(ah1, bh4)) | 0;
  lo = (lo + Math.imul(al0, bl5)) | 0;
  mid = (mid + Math.imul(al0, bh5)) | 0;
  mid = (mid + Math.imul(ah0, bl5)) | 0;
  hi = (hi + Math.imul(ah0, bh5)) | 0;
  var w5 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w5 >>> 26)) | 0;
  w5 &= 0x3ffffff;
  /* k = 6 */
  lo = Math.imul(al6, bl0);
  mid = Math.imul(al6, bh0);
  mid = (mid + Math.imul(ah6, bl0)) | 0;
  hi = Math.imul(ah6, bh0);
  lo = (lo + Math.imul(al5, bl1)) | 0;
  mid = (mid + Math.imul(al5, bh1)) | 0;
  mid = (mid + Math.imul(ah5, bl1)) | 0;
  hi = (hi + Math.imul(ah5, bh1)) | 0;
  lo = (lo + Math.imul(al4, bl2)) | 0;
  mid = (mid + Math.imul(al4, bh2)) | 0;
  mid = (mid + Math.imul(ah4, bl2)) | 0;
  hi = (hi + Math.imul(ah4, bh2)) | 0;
  lo = (lo + Math.imul(al3, bl3)) | 0;
  mid = (mid + Math.imul(al3, bh3)) | 0;
  mid = (mid + Math.imul(ah3, bl3)) | 0;
  hi = (hi + Math.imul(ah3, bh3)) | 0;
  lo = (lo + Math.imul(al2, bl4)) | 0;
  mid = (mid + Math.imul(al2, bh4)) | 0;
  mid = (mid + Math.imul(ah2, bl4)) | 0;
  hi = (hi + Math.imul(ah2, bh4)) | 0;
  lo = (lo + Math.imul(al1, bl5)) | 0;
  mid = (mid + Math.imul(al1, bh5)) | 0;
  mid = (mid + Math.imul(ah1, bl5)) | 0;
  hi = (hi + Math.imul(ah1, bh5)) | 0;
  lo = (lo + Math.imul(al0, bl6)) | 0;
  mid = (mid + Math.imul(al0, bh6)) | 0;
  mid = (mid + Math.imul(ah0, bl6)) | 0;
  hi = (hi + Math.imul(ah0, bh6)) | 0;
  var w6 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w6 >>> 26)) | 0;
  w6 &= 0x3ffffff;
  /* k = 7 */
  lo = Math.imul(al7, bl0);
  mid = Math.imul(al7, bh0);
  mid = (mid + Math.imul(ah7, bl0)) | 0;
  hi = Math.imul(ah7, bh0);
  lo = (lo + Math.imul(al6, bl1)) | 0;
  mid = (mid + Math.imul(al6, bh1)) | 0;
  mid = (mid + Math.imul(ah6, bl1)) | 0;
  hi = (hi + Math.imul(ah6, bh1)) | 0;
  lo = (lo + Math.imul(al5, bl2)) | 0;
  mid = (mid + Math.imul(al5, bh2)) | 0;
  mid = (mid + Math.imul(ah5, bl2)) | 0;
  hi = (hi + Math.imul(ah5, bh2)) | 0;
  lo = (lo + Math.imul(al4, bl3)) | 0;
  mid = (mid + Math.imul(al4, bh3)) | 0;
  mid = (mid + Math.imul(ah4, bl3)) | 0;
  hi = (hi + Math.imul(ah4, bh3)) | 0;
  lo = (lo + Math.imul(al3, bl4)) | 0;
  mid = (mid + Math.imul(al3, bh4)) | 0;
  mid = (mid + Math.imul(ah3, bl4)) | 0;
  hi = (hi + Math.imul(ah3, bh4)) | 0;
  lo = (lo + Math.imul(al2, bl5)) | 0;
  mid = (mid + Math.imul(al2, bh5)) | 0;
  mid = (mid + Math.imul(ah2, bl5)) | 0;
  hi = (hi + Math.imul(ah2, bh5)) | 0;
  lo = (lo + Math.imul(al1, bl6)) | 0;
  mid = (mid + Math.imul(al1, bh6)) | 0;
  mid = (mid + Math.imul(ah1, bl6)) | 0;
  hi = (hi + Math.imul(ah1, bh6)) | 0;
  lo = (lo + Math.imul(al0, bl7)) | 0;
  mid = (mid + Math.imul(al0, bh7)) | 0;
  mid = (mid + Math.imul(ah0, bl7)) | 0;
  hi = (hi + Math.imul(ah0, bh7)) | 0;
  var w7 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w7 >>> 26)) | 0;
  w7 &= 0x3ffffff;
  /* k = 8 */
  lo = Math.imul(al8, bl0);
  mid = Math.imul(al8, bh0);
  mid = (mid + Math.imul(ah8, bl0)) | 0;
  hi = Math.imul(ah8, bh0);
  lo = (lo + Math.imul(al7, bl1)) | 0;
  mid = (mid + Math.imul(al7, bh1)) | 0;
  mid = (mid + Math.imul(ah7, bl1)) | 0;
  hi = (hi + Math.imul(ah7, bh1)) | 0;
  lo = (lo + Math.imul(al6, bl2)) | 0;
  mid = (mid + Math.imul(al6, bh2)) | 0;
  mid = (mid + Math.imul(ah6, bl2)) | 0;
  hi = (hi + Math.imul(ah6, bh2)) | 0;
  lo = (lo + Math.imul(al5, bl3)) | 0;
  mid = (mid + Math.imul(al5, bh3)) | 0;
  mid = (mid + Math.imul(ah5, bl3)) | 0;
  hi = (hi + Math.imul(ah5, bh3)) | 0;
  lo = (lo + Math.imul(al4, bl4)) | 0;
  mid = (mid + Math.imul(al4, bh4)) | 0;
  mid = (mid + Math.imul(ah4, bl4)) | 0;
  hi = (hi + Math.imul(ah4, bh4)) | 0;
  lo = (lo + Math.imul(al3, bl5)) | 0;
  mid = (mid + Math.imul(al3, bh5)) | 0;
  mid = (mid + Math.imul(ah3, bl5)) | 0;
  hi = (hi + Math.imul(ah3, bh5)) | 0;
  lo = (lo + Math.imul(al2, bl6)) | 0;
  mid = (mid + Math.imul(al2, bh6)) | 0;
  mid = (mid + Math.imul(ah2, bl6)) | 0;
  hi = (hi + Math.imul(ah2, bh6)) | 0;
  lo = (lo + Math.imul(al1, bl7)) | 0;
  mid = (mid + Math.imul(al1, bh7)) | 0;
  mid = (mid + Math.imul(ah1, bl7)) | 0;
  hi = (hi + Math.imul(ah1, bh7)) | 0;
  lo = (lo + Math.imul(al0, bl8)) | 0;
  mid = (mid + Math.imul(al0, bh8)) | 0;
  mid = (mid + Math.imul(ah0, bl8)) | 0;
  hi = (hi + Math.imul(ah0, bh8)) | 0;
  var w8 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w8 >>> 26)) | 0;
  w8 &= 0x3ffffff;
  /* k = 9 */
  lo = Math.imul(al9, bl0);
  mid = Math.imul(al9, bh0);
  mid = (mid + Math.imul(ah9, bl0)) | 0;
  hi = Math.imul(ah9, bh0);
  lo = (lo + Math.imul(al8, bl1)) | 0;
  mid = (mid + Math.imul(al8, bh1)) | 0;
  mid = (mid + Math.imul(ah8, bl1)) | 0;
  hi = (hi + Math.imul(ah8, bh1)) | 0;
  lo = (lo + Math.imul(al7, bl2)) | 0;
  mid = (mid + Math.imul(al7, bh2)) | 0;
  mid = (mid + Math.imul(ah7, bl2)) | 0;
  hi = (hi + Math.imul(ah7, bh2)) | 0;
  lo = (lo + Math.imul(al6, bl3)) | 0;
  mid = (mid + Math.imul(al6, bh3)) | 0;
  mid = (mid + Math.imul(ah6, bl3)) | 0;
  hi = (hi + Math.imul(ah6, bh3)) | 0;
  lo = (lo + Math.imul(al5, bl4)) | 0;
  mid = (mid + Math.imul(al5, bh4)) | 0;
  mid = (mid + Math.imul(ah5, bl4)) | 0;
  hi = (hi + Math.imul(ah5, bh4)) | 0;
  lo = (lo + Math.imul(al4, bl5)) | 0;
  mid = (mid + Math.imul(al4, bh5)) | 0;
  mid = (mid + Math.imul(ah4, bl5)) | 0;
  hi = (hi + Math.imul(ah4, bh5)) | 0;
  lo = (lo + Math.imul(al3, bl6)) | 0;
  mid = (mid + Math.imul(al3, bh6)) | 0;
  mid = (mid + Math.imul(ah3, bl6)) | 0;
  hi = (hi + Math.imul(ah3, bh6)) | 0;
  lo = (lo + Math.imul(al2, bl7)) | 0;
  mid = (mid + Math.imul(al2, bh7)) | 0;
  mid = (mid + Math.imul(ah2, bl7)) | 0;
  hi = (hi + Math.imul(ah2, bh7)) | 0;
  lo = (lo + Math.imul(al1, bl8)) | 0;
  mid = (mid + Math.imul(al1, bh8)) | 0;
  mid = (mid + Math.imul(ah1, bl8)) | 0;
  hi = (hi + Math.imul(ah1, bh8)) | 0;
  lo = (lo + Math.imul(al0, bl9)) | 0;
  mid = (mid + Math.imul(al0, bh9)) | 0;
  mid = (mid + Math.imul(ah0, bl9)) | 0;
  hi = (hi + Math.imul(ah0, bh9)) | 0;
  var w9 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w9 >>> 26)) | 0;
  w9 &= 0x3ffffff;
  /* k = 10 */
  lo = Math.imul(al9, bl1);
  mid = Math.imul(al9, bh1);
  mid = (mid + Math.imul(ah9, bl1)) | 0;
  hi = Math.imul(ah9, bh1);
  lo = (lo + Math.imul(al8, bl2)) | 0;
  mid = (mid + Math.imul(al8, bh2)) | 0;
  mid = (mid + Math.imul(ah8, bl2)) | 0;
  hi = (hi + Math.imul(ah8, bh2)) | 0;
  lo = (lo + Math.imul(al7, bl3)) | 0;
  mid = (mid + Math.imul(al7, bh3)) | 0;
  mid = (mid + Math.imul(ah7, bl3)) | 0;
  hi = (hi + Math.imul(ah7, bh3)) | 0;
  lo = (lo + Math.imul(al6, bl4)) | 0;
  mid = (mid + Math.imul(al6, bh4)) | 0;
  mid = (mid + Math.imul(ah6, bl4)) | 0;
  hi = (hi + Math.imul(ah6, bh4)) | 0;
  lo = (lo + Math.imul(al5, bl5)) | 0;
  mid = (mid + Math.imul(al5, bh5)) | 0;
  mid = (mid + Math.imul(ah5, bl5)) | 0;
  hi = (hi + Math.imul(ah5, bh5)) | 0;
  lo = (lo + Math.imul(al4, bl6)) | 0;
  mid = (mid + Math.imul(al4, bh6)) | 0;
  mid = (mid + Math.imul(ah4, bl6)) | 0;
  hi = (hi + Math.imul(ah4, bh6)) | 0;
  lo = (lo + Math.imul(al3, bl7)) | 0;
  mid = (mid + Math.imul(al3, bh7)) | 0;
  mid = (mid + Math.imul(ah3, bl7)) | 0;
  hi = (hi + Math.imul(ah3, bh7)) | 0;
  lo = (lo + Math.imul(al2, bl8)) | 0;
  mid = (mid + Math.imul(al2, bh8)) | 0;
  mid = (mid + Math.imul(ah2, bl8)) | 0;
  hi = (hi + Math.imul(ah2, bh8)) | 0;
  lo = (lo + Math.imul(al1, bl9)) | 0;
  mid = (mid + Math.imul(al1, bh9)) | 0;
  mid = (mid + Math.imul(ah1, bl9)) | 0;
  hi = (hi + Math.imul(ah1, bh9)) | 0;
  var w10 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w10 >>> 26)) | 0;
  w10 &= 0x3ffffff;
  /* k = 11 */
  lo = Math.imul(al9, bl2);
  mid = Math.imul(al9, bh2);
  mid = (mid + Math.imul(ah9, bl2)) | 0;
  hi = Math.imul(ah9, bh2);
  lo = (lo + Math.imul(al8, bl3)) | 0;
  mid = (mid + Math.imul(al8, bh3)) | 0;
  mid = (mid + Math.imul(ah8, bl3)) | 0;
  hi = (hi + Math.imul(ah8, bh3)) | 0;
  lo = (lo + Math.imul(al7, bl4)) | 0;
  mid = (mid + Math.imul(al7, bh4)) | 0;
  mid = (mid + Math.imul(ah7, bl4)) | 0;
  hi = (hi + Math.imul(ah7, bh4)) | 0;
  lo = (lo + Math.imul(al6, bl5)) | 0;
  mid = (mid + Math.imul(al6, bh5)) | 0;
  mid = (mid + Math.imul(ah6, bl5)) | 0;
  hi = (hi + Math.imul(ah6, bh5)) | 0;
  lo = (lo + Math.imul(al5, bl6)) | 0;
  mid = (mid + Math.imul(al5, bh6)) | 0;
  mid = (mid + Math.imul(ah5, bl6)) | 0;
  hi = (hi + Math.imul(ah5, bh6)) | 0;
  lo = (lo + Math.imul(al4, bl7)) | 0;
  mid = (mid + Math.imul(al4, bh7)) | 0;
  mid = (mid + Math.imul(ah4, bl7)) | 0;
  hi = (hi + Math.imul(ah4, bh7)) | 0;
  lo = (lo + Math.imul(al3, bl8)) | 0;
  mid = (mid + Math.imul(al3, bh8)) | 0;
  mid = (mid + Math.imul(ah3, bl8)) | 0;
  hi = (hi + Math.imul(ah3, bh8)) | 0;
  lo = (lo + Math.imul(al2, bl9)) | 0;
  mid = (mid + Math.imul(al2, bh9)) | 0;
  mid = (mid + Math.imul(ah2, bl9)) | 0;
  hi = (hi + Math.imul(ah2, bh9)) | 0;
  var w11 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w11 >>> 26)) | 0;
  w11 &= 0x3ffffff;
  /* k = 12 */
  lo = Math.imul(al9, bl3);
  mid = Math.imul(al9, bh3);
  mid = (mid + Math.imul(ah9, bl3)) | 0;
  hi = Math.imul(ah9, bh3);
  lo = (lo + Math.imul(al8, bl4)) | 0;
  mid = (mid + Math.imul(al8, bh4)) | 0;
  mid = (mid + Math.imul(ah8, bl4)) | 0;
  hi = (hi + Math.imul(ah8, bh4)) | 0;
  lo = (lo + Math.imul(al7, bl5)) | 0;
  mid = (mid + Math.imul(al7, bh5)) | 0;
  mid = (mid + Math.imul(ah7, bl5)) | 0;
  hi = (hi + Math.imul(ah7, bh5)) | 0;
  lo = (lo + Math.imul(al6, bl6)) | 0;
  mid = (mid + Math.imul(al6, bh6)) | 0;
  mid = (mid + Math.imul(ah6, bl6)) | 0;
  hi = (hi + Math.imul(ah6, bh6)) | 0;
  lo = (lo + Math.imul(al5, bl7)) | 0;
  mid = (mid + Math.imul(al5, bh7)) | 0;
  mid = (mid + Math.imul(ah5, bl7)) | 0;
  hi = (hi + Math.imul(ah5, bh7)) | 0;
  lo = (lo + Math.imul(al4, bl8)) | 0;
  mid = (mid + Math.imul(al4, bh8)) | 0;
  mid = (mid + Math.imul(ah4, bl8)) | 0;
  hi = (hi + Math.imul(ah4, bh8)) | 0;
  lo = (lo + Math.imul(al3, bl9)) | 0;
  mid = (mid + Math.imul(al3, bh9)) | 0;
  mid = (mid + Math.imul(ah3, bl9)) | 0;
  hi = (hi + Math.imul(ah3, bh9)) | 0;
  var w12 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w12 >>> 26)) | 0;
  w12 &= 0x3ffffff;
  /* k = 13 */
  lo = Math.imul(al9, bl4);
  mid = Math.imul(al9, bh4);
  mid = (mid + Math.imul(ah9, bl4)) | 0;
  hi = Math.imul(ah9, bh4);
  lo = (lo + Math.imul(al8, bl5)) | 0;
  mid = (mid + Math.imul(al8, bh5)) | 0;
  mid = (mid + Math.imul(ah8, bl5)) | 0;
  hi = (hi + Math.imul(ah8, bh5)) | 0;
  lo = (lo + Math.imul(al7, bl6)) | 0;
  mid = (mid + Math.imul(al7, bh6)) | 0;
  mid = (mid + Math.imul(ah7, bl6)) | 0;
  hi = (hi + Math.imul(ah7, bh6)) | 0;
  lo = (lo + Math.imul(al6, bl7)) | 0;
  mid = (mid + Math.imul(al6, bh7)) | 0;
  mid = (mid + Math.imul(ah6, bl7)) | 0;
  hi = (hi + Math.imul(ah6, bh7)) | 0;
  lo = (lo + Math.imul(al5, bl8)) | 0;
  mid = (mid + Math.imul(al5, bh8)) | 0;
  mid = (mid + Math.imul(ah5, bl8)) | 0;
  hi = (hi + Math.imul(ah5, bh8)) | 0;
  lo = (lo + Math.imul(al4, bl9)) | 0;
  mid = (mid + Math.imul(al4, bh9)) | 0;
  mid = (mid + Math.imul(ah4, bl9)) | 0;
  hi = (hi + Math.imul(ah4, bh9)) | 0;
  var w13 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w13 >>> 26)) | 0;
  w13 &= 0x3ffffff;
  /* k = 14 */
  lo = Math.imul(al9, bl5);
  mid = Math.imul(al9, bh5);
  mid = (mid + Math.imul(ah9, bl5)) | 0;
  hi = Math.imul(ah9, bh5);
  lo = (lo + Math.imul(al8, bl6)) | 0;
  mid = (mid + Math.imul(al8, bh6)) | 0;
  mid = (mid + Math.imul(ah8, bl6)) | 0;
  hi = (hi + Math.imul(ah8, bh6)) | 0;
  lo = (lo + Math.imul(al7, bl7)) | 0;
  mid = (mid + Math.imul(al7, bh7)) | 0;
  mid = (mid + Math.imul(ah7, bl7)) | 0;
  hi = (hi + Math.imul(ah7, bh7)) | 0;
  lo = (lo + Math.imul(al6, bl8)) | 0;
  mid = (mid + Math.imul(al6, bh8)) | 0;
  mid = (mid + Math.imul(ah6, bl8)) | 0;
  hi = (hi + Math.imul(ah6, bh8)) | 0;
  lo = (lo + Math.imul(al5, bl9)) | 0;
  mid = (mid + Math.imul(al5, bh9)) | 0;
  mid = (mid + Math.imul(ah5, bl9)) | 0;
  hi = (hi + Math.imul(ah5, bh9)) | 0;
  var w14 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w14 >>> 26)) | 0;
  w14 &= 0x3ffffff;
  /* k = 15 */
  lo = Math.imul(al9, bl6);
  mid = Math.imul(al9, bh6);
  mid = (mid + Math.imul(ah9, bl6)) | 0;
  hi = Math.imul(ah9, bh6);
  lo = (lo + Math.imul(al8, bl7)) | 0;
  mid = (mid + Math.imul(al8, bh7)) | 0;
  mid = (mid + Math.imul(ah8, bl7)) | 0;
  hi = (hi + Math.imul(ah8, bh7)) | 0;
  lo = (lo + Math.imul(al7, bl8)) | 0;
  mid = (mid + Math.imul(al7, bh8)) | 0;
  mid = (mid + Math.imul(ah7, bl8)) | 0;
  hi = (hi + Math.imul(ah7, bh8)) | 0;
  lo = (lo + Math.imul(al6, bl9)) | 0;
  mid = (mid + Math.imul(al6, bh9)) | 0;
  mid = (mid + Math.imul(ah6, bl9)) | 0;
  hi = (hi + Math.imul(ah6, bh9)) | 0;
  var w15 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w15 >>> 26)) | 0;
  w15 &= 0x3ffffff;
  /* k = 16 */
  lo = Math.imul(al9, bl7);
  mid = Math.imul(al9, bh7);
  mid = (mid + Math.imul(ah9, bl7)) | 0;
  hi = Math.imul(ah9, bh7);
  lo = (lo + Math.imul(al8, bl8)) | 0;
  mid = (mid + Math.imul(al8, bh8)) | 0;
  mid = (mid + Math.imul(ah8, bl8)) | 0;
  hi = (hi + Math.imul(ah8, bh8)) | 0;
  lo = (lo + Math.imul(al7, bl9)) | 0;
  mid = (mid + Math.imul(al7, bh9)) | 0;
  mid = (mid + Math.imul(ah7, bl9)) | 0;
  hi = (hi + Math.imul(ah7, bh9)) | 0;
  var w16 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w16 >>> 26)) | 0;
  w16 &= 0x3ffffff;
  /* k = 17 */
  lo = Math.imul(al9, bl8);
  mid = Math.imul(al9, bh8);
  mid = (mid + Math.imul(ah9, bl8)) | 0;
  hi = Math.imul(ah9, bh8);
  lo = (lo + Math.imul(al8, bl9)) | 0;
  mid = (mid + Math.imul(al8, bh9)) | 0;
  mid = (mid + Math.imul(ah8, bl9)) | 0;
  hi = (hi + Math.imul(ah8, bh9)) | 0;
  var w17 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w17 >>> 26)) | 0;
  w17 &= 0x3ffffff;
  /* k = 18 */
  lo = Math.imul(al9, bl9);
  mid = Math.imul(al9, bh9);
  mid = (mid + Math.imul(ah9, bl9)) | 0;
  hi = Math.imul(ah9, bh9);
  var w18 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w18 >>> 26)) | 0;
  w18 &= 0x3ffffff;
  o[0] = w0;
  o[1] = w1;
  o[2] = w2;
  o[3] = w3;
  o[4] = w4;
  o[5] = w5;
  o[6] = w6;
  o[7] = w7;
  o[8] = w8;
  o[9] = w9;
  o[10] = w10;
  o[11] = w11;
  o[12] = w12;
  o[13] = w13;
  o[14] = w14;
  o[15] = w15;
  o[16] = w16;
  o[17] = w17;
  o[18] = w18;
  if (c !== 0) {
    o[19] = c;
    out.length++;
  }
  return out;
};

// Polyfill comb
if (!Math.imul) {
  comb10MulTo = smallMulTo;
}

function bigMulTo(self, num, out) {
  out.negative = num.negative ^ self.negative;
  out.length = self.length + num.length;

  var carry = 0;
  var hncarry = 0;
  for (var k = 0; k < out.length - 1; k++) {
    // Sum all words with the same `i + j = k` and accumulate `ncarry`,
    // note that ncarry could be >= 0x3ffffff
    var ncarry = hncarry;
    hncarry = 0;
    var rword = carry & 0x3ffffff;
    var maxJ = Math.min(k, num.length - 1);
    for (var j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
      var i = k - j;
      var a = self.words[i] | 0;
      var b = num.words[j] | 0;
      var r = a * b;

      var lo = r & 0x3ffffff;
      ncarry = (ncarry + ((r / 0x4000000) | 0)) | 0;
      lo = (lo + rword) | 0;
      rword = lo & 0x3ffffff;
      ncarry = (ncarry + (lo >>> 26)) | 0;

      hncarry += ncarry >>> 26;
      ncarry &= 0x3ffffff;
    }
    out.words[k] = rword;
    carry = ncarry;
    ncarry = hncarry;
  }
  if (carry !== 0) {
    out.words[k] = carry;
  } else {
    out.length--;
  }

  return out.strip();
}

function jumboMulTo(self, num, out) {
  var fftm = new FFTM();
  return fftm.mulp(self, num, out);
}

BN.prototype.mulTo = function mulTo(num, out) {
  var res;
  var len = this.length + num.length;
  if (this.length === 10 && num.length === 10) {
    res = comb10MulTo(this, num, out);
  } else if (len < 63) {
    res = smallMulTo(this, num, out);
  } else if (len < 1024) {
    res = bigMulTo(this, num, out);
  } else {
    res = jumboMulTo(this, num, out);
  }

  return res;
};

// Cooley-Tukey algorithm for FFT
// slightly revisited to rely on looping instead of recursion

function FFTM(x, y) {
  this.x = x;
  this.y = y;
}

FFTM.prototype.makeRBT = function makeRBT(N) {
  var t = new Array(N);
  var l = BN.prototype._countBits(N) - 1;
  for (var i = 0; i < N; i++) {
    t[i] = this.revBin(i, l, N);
  }

  return t;
};

// Returns binary-reversed representation of `x`
FFTM.prototype.revBin = function revBin(x, l, N) {
  if (x === 0 || x === N - 1) return x;

  var rb = 0;
  for (var i = 0; i < l; i++) {
    rb |= (x & 1) << (l - i - 1);
    x >>= 1;
  }

  return rb;
};

// Performs "tweedling" phase, therefore 'emulating'
// behaviour of the recursive algorithm
FFTM.prototype.permute = function permute(rbt, rws, iws, rtws, itws, N) {
  for (var i = 0; i < N; i++) {
    rtws[i] = rws[rbt[i]];
    itws[i] = iws[rbt[i]];
  }
};

FFTM.prototype.transform = function transform(rws, iws, rtws, itws, N, rbt) {
  this.permute(rbt, rws, iws, rtws, itws, N);

  for (var s = 1; s < N; s <<= 1) {
    var l = s << 1;

    var rtwdf = Math.cos(2 * Math.PI / l);
    var itwdf = Math.sin(2 * Math.PI / l);

    for (var p = 0; p < N; p += l) {
      var rtwdf_ = rtwdf;
      var itwdf_ = itwdf;

      for (var j = 0; j < s; j++) {
        var re = rtws[p + j];
        var ie = itws[p + j];

        var ro = rtws[p + j + s];
        var io = itws[p + j + s];

        var rx = rtwdf_ * ro - itwdf_ * io;

        io = rtwdf_ * io + itwdf_ * ro;
        ro = rx;

        rtws[p + j] = re + ro;
        itws[p + j] = ie + io;

        rtws[p + j + s] = re - ro;
        itws[p + j + s] = ie - io;

        /* jshint maxdepth : false */
        if (j !== l) {
          rx = rtwdf * rtwdf_ - itwdf * itwdf_;

          itwdf_ = rtwdf * itwdf_ + itwdf * rtwdf_;
          rtwdf_ = rx;
        }
      }
    }
  }
};

FFTM.prototype.guessLen13b = function guessLen13b(n, m) {
  var N = Math.max(m, n) | 1;
  var odd = N & 1;
  var i = 0;
  for (N = N / 2 | 0; N; N = N >>> 1) {
    i++;
  }

  return 1 << i + 1 + odd;
};

FFTM.prototype.conjugate = function conjugate(rws, iws, N) {
  if (N <= 1) return;

  for (var i = 0; i < N / 2; i++) {
    var t = rws[i];

    rws[i] = rws[N - i - 1];
    rws[N - i - 1] = t;

    t = iws[i];

    iws[i] = -iws[N - i - 1];
    iws[N - i - 1] = -t;
  }
};

FFTM.prototype.normalize13b = function normalize13b(ws, N) {
  var carry = 0;
  for (var i = 0; i < N / 2; i++) {
    var w = Math.round(ws[2 * i + 1] / N) * 0x2000 +
      Math.round(ws[2 * i] / N) +
      carry;

    ws[i] = w & 0x3ffffff;

    if (w < 0x4000000) {
      carry = 0;
    } else {
      carry = w / 0x4000000 | 0;
    }
  }

  return ws;
};

FFTM.prototype.convert13b = function convert13b(ws, len, rws, N) {
  var carry = 0;
  for (var i = 0; i < len; i++) {
    carry = carry + (ws[i] | 0);

    rws[2 * i] = carry & 0x1fff; carry = carry >>> 13;
    rws[2 * i + 1] = carry & 0x1fff; carry = carry >>> 13;
  }

  // Pad with zeroes
  for (i = 2 * len; i < N; ++i) {
    rws[i] = 0;
  }

  assert(carry === 0);
  assert((carry & ~0x1fff) === 0);
};

FFTM.prototype.stub = function stub(N) {
  var ph = new Array(N);
  for (var i = 0; i < N; i++) {
    ph[i] = 0;
  }

  return ph;
};

FFTM.prototype.mulp = function mulp(x, y, out) {
  var N = 2 * this.guessLen13b(x.length, y.length);

  var rbt = this.makeRBT(N);

  var _ = this.stub(N);

  var rws = new Array(N);
  var rwst = new Array(N);
  var iwst = new Array(N);

  var nrws = new Array(N);
  var nrwst = new Array(N);
  var niwst = new Array(N);

  var rmws = out.words;
  rmws.length = N;

  this.convert13b(x.words, x.length, rws, N);
  this.convert13b(y.words, y.length, nrws, N);

  this.transform(rws, _, rwst, iwst, N, rbt);
  this.transform(nrws, _, nrwst, niwst, N, rbt);

  for (var i = 0; i < N; i++) {
    var rx = rwst[i] * nrwst[i] - iwst[i] * niwst[i];
    iwst[i] = rwst[i] * niwst[i] + iwst[i] * nrwst[i];
    rwst[i] = rx;
  }

  this.conjugate(rwst, iwst, N);
  this.transform(rwst, iwst, rmws, _, N, rbt);
  this.conjugate(rmws, _, N);
  this.normalize13b(rmws, N);

  out.negative = x.negative ^ y.negative;
  out.length = x.length + y.length;
  return out.strip();
};

// Multiply `this` by `num`
BN.prototype.mul = function mul(num) {
  var out = new BN(null);
  out.words = new Array(this.length + num.length);
  return this.mulTo(num, out);
};

// Multiply employing FFT
BN.prototype.mulf = function mulf(num) {
  var out = new BN(null);
  out.words = new Array(this.length + num.length);
  return jumboMulTo(this, num, out);
};

// In-place Multiplication
BN.prototype.imul = function imul(num) {
  return this.clone().mulTo(num, this);
};

BN.prototype.imuln = function imuln(num) {
  assert(typeof num === 'number');
  assert(num < 0x4000000);

  // Carry
  var carry = 0;
  for (var i = 0; i < this.length; i++) {
    var w = (this.words[i] | 0) * num;
    var lo = (w & 0x3ffffff) + (carry & 0x3ffffff);
    carry >>= 26;
    carry += (w / 0x4000000) | 0;
    // NOTE: lo is 27bit maximum
    carry += lo >>> 26;
    this.words[i] = lo & 0x3ffffff;
  }

  if (carry !== 0) {
    this.words[i] = carry;
    this.length++;
  }
  this.length = num === 0 ? 1 : this.length;

  return this;
};

BN.prototype.muln = function muln(num) {
  return this.clone().imuln(num);
};

// `this` * `this`
BN.prototype.sqr = function sqr() {
  return this.mul(this);
};

// `this` * `this` in-place
BN.prototype.isqr = function isqr() {
  return this.imul(this.clone());
};

// Math.pow(`this`, `num`)
BN.prototype.pow = function pow(num) {
  var w = toBitArray(num);
  if (w.length === 0) return new BN(1);

  // Skip leading zeroes
  var res = this;
  for (var i = 0; i < w.length; i++, res = res.sqr()) {
    if (w[i] !== 0) break;
  }

  if (++i < w.length) {
    for (var q = res.sqr(); i < w.length; i++, q = q.sqr()) {
      if (w[i] === 0) continue;

      res = res.mul(q);
    }
  }

  return res;
};

// Shift-left in-place
BN.prototype.iushln = function iushln(bits) {
  assert(typeof bits === 'number' && bits >= 0);
  var r = bits % 26;
  var s = (bits - r) / 26;
  var carryMask = (0x3ffffff >>> (26 - r)) << (26 - r);
  var i;

  if (r !== 0) {
    var carry = 0;

    for (i = 0; i < this.length; i++) {
      var newCarry = this.words[i] & carryMask;
      var c = ((this.words[i] | 0) - newCarry) << r;
      this.words[i] = c | carry;
      carry = newCarry >>> (26 - r);
    }

    if (carry) {
      this.words[i] = carry;
      this.length++;
    }
  }

  if (s !== 0) {
    for (i = this.length - 1; i >= 0; i--) {
      this.words[i + s] = this.words[i];
    }

    for (i = 0; i < s; i++) {
      this.words[i] = 0;
    }

    this.length += s;
  }

  return this.strip();
};

BN.prototype.ishln = function ishln(bits) {
  // TODO(indutny): implement me
  assert(this.negative === 0);
  return this.iushln(bits);
};

// Shift-right in-place
// NOTE: `hint` is a lowest bit before trailing zeroes
// NOTE: if `extended` is present - it will be filled with destroyed bits
BN.prototype.iushrn = function iushrn(bits, hint, extended) {
  assert(typeof bits === 'number' && bits >= 0);
  var h;
  if (hint) {
    h = (hint - (hint % 26)) / 26;
  } else {
    h = 0;
  }

  var r = bits % 26;
  var s = Math.min((bits - r) / 26, this.length);
  var mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);
  var maskedWords = extended;

  h -= s;
  h = Math.max(0, h);

  // Extended mode, copy masked part
  if (maskedWords) {
    for (var i = 0; i < s; i++) {
      maskedWords.words[i] = this.words[i];
    }
    maskedWords.length = s;
  }

  if (s === 0) {
    // No-op, we should not move anything at all
  } else if (this.length > s) {
    this.length -= s;
    for (i = 0; i < this.length; i++) {
      this.words[i] = this.words[i + s];
    }
  } else {
    this.words[0] = 0;
    this.length = 1;
  }

  var carry = 0;
  for (i = this.length - 1; i >= 0 && (carry !== 0 || i >= h); i--) {
    var word = this.words[i] | 0;
    this.words[i] = (carry << (26 - r)) | (word >>> r);
    carry = word & mask;
  }

  // Push carried bits as a mask
  if (maskedWords && carry !== 0) {
    maskedWords.words[maskedWords.length++] = carry;
  }

  if (this.length === 0) {
    this.words[0] = 0;
    this.length = 1;
  }

  return this.strip();
};

BN.prototype.ishrn = function ishrn(bits, hint, extended) {
  // TODO(indutny): implement me
  assert(this.negative === 0);
  return this.iushrn(bits, hint, extended);
};

// Shift-left
BN.prototype.shln = function shln(bits) {
  return this.clone().ishln(bits);
};

BN.prototype.ushln = function ushln(bits) {
  return this.clone().iushln(bits);
};

// Shift-right
BN.prototype.shrn = function shrn(bits) {
  return this.clone().ishrn(bits);
};

BN.prototype.ushrn = function ushrn(bits) {
  return this.clone().iushrn(bits);
};

// Test if n bit is set
BN.prototype.testn = function testn(bit) {
  assert(typeof bit === 'number' && bit >= 0);
  var r = bit % 26;
  var s = (bit - r) / 26;
  var q = 1 << r;

  // Fast case: bit is much higher than all existing words
  if (this.length <= s) return false;

  // Check bit and return
  var w = this.words[s];

  return !!(w & q);
};

// Return only lowers bits of number (in-place)
BN.prototype.imaskn = function imaskn(bits) {
  assert(typeof bits === 'number' && bits >= 0);
  var r = bits % 26;
  var s = (bits - r) / 26;

  assert(this.negative === 0, 'imaskn works only with positive numbers');

  if (this.length <= s) {
    return this;
  }

  if (r !== 0) {
    s++;
  }
  this.length = Math.min(s, this.length);

  if (r !== 0) {
    var mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);
    this.words[this.length - 1] &= mask;
  }

  return this.strip();
};

// Return only lowers bits of number
BN.prototype.maskn = function maskn(bits) {
  return this.clone().imaskn(bits);
};

// Add plain number `num` to `this`
BN.prototype.iaddn = function iaddn(num) {
  assert(typeof num === 'number');
  assert(num < 0x4000000);
  if (num < 0) return this.isubn(-num);

  // Possible sign change
  if (this.negative !== 0) {
    if (this.length === 1 && (this.words[0] | 0) < num) {
      this.words[0] = num - (this.words[0] | 0);
      this.negative = 0;
      return this;
    }

    this.negative = 0;
    this.isubn(num);
    this.negative = 1;
    return this;
  }

  // Add without checks
  return this._iaddn(num);
};

BN.prototype._iaddn = function _iaddn(num) {
  this.words[0] += num;

  // Carry
  for (var i = 0; i < this.length && this.words[i] >= 0x4000000; i++) {
    this.words[i] -= 0x4000000;
    if (i === this.length - 1) {
      this.words[i + 1] = 1;
    } else {
      this.words[i + 1]++;
    }
  }
  this.length = Math.max(this.length, i + 1);

  return this;
};

// Subtract plain number `num` from `this`
BN.prototype.isubn = function isubn(num) {
  assert(typeof num === 'number');
  assert(num < 0x4000000);
  if (num < 0) return this.iaddn(-num);

  if (this.negative !== 0) {
    this.negative = 0;
    this.iaddn(num);
    this.negative = 1;
    return this;
  }

  this.words[0] -= num;

  if (this.length === 1 && this.words[0] < 0) {
    this.words[0] = -this.words[0];
    this.negative = 1;
  } else {
    // Carry
    for (var i = 0; i < this.length && this.words[i] < 0; i++) {
      this.words[i] += 0x4000000;
      this.words[i + 1] -= 1;
    }
  }

  return this.strip();
};

BN.prototype.addn = function addn(num) {
  return this.clone().iaddn(num);
};

BN.prototype.subn = function subn(num) {
  return this.clone().isubn(num);
};

BN.prototype.iabs = function iabs() {
  this.negative = 0;

  return this;
};

BN.prototype.abs = function abs() {
  return this.clone().iabs();
};

BN.prototype._ishlnsubmul = function _ishlnsubmul(num, mul, shift) {
  var len = num.length + shift;
  var i;

  this._expand(len);

  var w;
  var carry = 0;
  for (i = 0; i < num.length; i++) {
    w = (this.words[i + shift] | 0) + carry;
    var right = (num.words[i] | 0) * mul;
    w -= right & 0x3ffffff;
    carry = (w >> 26) - ((right / 0x4000000) | 0);
    this.words[i + shift] = w & 0x3ffffff;
  }
  for (; i < this.length - shift; i++) {
    w = (this.words[i + shift] | 0) + carry;
    carry = w >> 26;
    this.words[i + shift] = w & 0x3ffffff;
  }

  if (carry === 0) return this.strip();

  // Subtraction overflow
  assert(carry === -1);
  carry = 0;
  for (i = 0; i < this.length; i++) {
    w = -(this.words[i] | 0) + carry;
    carry = w >> 26;
    this.words[i] = w & 0x3ffffff;
  }
  this.negative = 1;

  return this.strip();
};

BN.prototype._wordDiv = function _wordDiv(num, mode) {
  var shift = this.length - num.length;

  var a = this.clone();
  var b = num;

  // Normalize
  var bhi = b.words[b.length - 1] | 0;
  var bhiBits = this._countBits(bhi);
  shift = 26 - bhiBits;
  if (shift !== 0) {
    b = b.ushln(shift);
    a.iushln(shift);
    bhi = b.words[b.length - 1] | 0;
  }

  // Initialize quotient
  var m = a.length - b.length;
  var q;

  if (mode !== 'mod') {
    q = new BN(null);
    q.length = m + 1;
    q.words = new Array(q.length);
    for (var i = 0; i < q.length; i++) {
      q.words[i] = 0;
    }
  }

  var diff = a.clone()._ishlnsubmul(b, 1, m);
  if (diff.negative === 0) {
    a = diff;
    if (q) {
      q.words[m] = 1;
    }
  }

  for (var j = m - 1; j >= 0; j--) {
    var qj = (a.words[b.length + j] | 0) * 0x4000000 +
      (a.words[b.length + j - 1] | 0);

    // NOTE: (qj / bhi) is (0x3ffffff * 0x4000000 + 0x3ffffff) / 0x2000000 max
    // (0x7ffffff)
    qj = Math.min((qj / bhi) | 0, 0x3ffffff);

    a._ishlnsubmul(b, qj, j);
    while (a.negative !== 0) {
      qj--;
      a.negative = 0;
      a._ishlnsubmul(b, 1, j);
      if (!a.isZero()) {
        a.negative ^= 1;
      }
    }
    if (q) {
      q.words[j] = qj;
    }
  }
  if (q) {
    q.strip();
  }
  a.strip();

  // Denormalize
  if (mode !== 'div' && shift !== 0) {
    a.iushrn(shift);
  }

  return {
    div: q || null,
    mod: a
  };
};

// NOTE: 1) `mode` can be set to `mod` to request mod only,
//       to `div` to request div only, or be absent to
//       request both div & mod
//       2) `positive` is true if unsigned mod is requested
BN.prototype.divmod = function divmod(num, mode, positive) {
  assert(!num.isZero());

  if (this.isZero()) {
    return {
      div: new BN(0),
      mod: new BN(0)
    };
  }

  var div, mod, res;
  if (this.negative !== 0 && num.negative === 0) {
    res = this.neg().divmod(num, mode);

    if (mode !== 'mod') {
      div = res.div.neg();
    }

    if (mode !== 'div') {
      mod = res.mod.neg();
      if (positive && mod.negative !== 0) {
        mod.iadd(num);
      }
    }

    return {
      div: div,
      mod: mod
    };
  }

  if (this.negative === 0 && num.negative !== 0) {
    res = this.divmod(num.neg(), mode);

    if (mode !== 'mod') {
      div = res.div.neg();
    }

    return {
      div: div,
      mod: res.mod
    };
  }

  if ((this.negative & num.negative) !== 0) {
    res = this.neg().divmod(num.neg(), mode);

    if (mode !== 'div') {
      mod = res.mod.neg();
      if (positive && mod.negative !== 0) {
        mod.isub(num);
      }
    }

    return {
      div: res.div,
      mod: mod
    };
  }

  // Both numbers are positive at this point

  // Strip both numbers to approximate shift value
  if (num.length > this.length || this.cmp(num) < 0) {
    return {
      div: new BN(0),
      mod: this
    };
  }

  // Very short reduction
  if (num.length === 1) {
    if (mode === 'div') {
      return {
        div: this.divn(num.words[0]),
        mod: null
      };
    }

    if (mode === 'mod') {
      return {
        div: null,
        mod: new BN(this.modn(num.words[0]))
      };
    }

    return {
      div: this.divn(num.words[0]),
      mod: new BN(this.modn(num.words[0]))
    };
  }

  return this._wordDiv(num, mode);
};

// Find `this` / `num`
BN.prototype.div = function div(num) {
  return this.divmod(num, 'div', false).div;
};

// Find `this` % `num`
BN.prototype.mod = function mod(num) {
  return this.divmod(num, 'mod', false).mod;
};

BN.prototype.umod = function umod(num) {
  return this.divmod(num, 'mod', true).mod;
};

// Find Round(`this` / `num`)
BN.prototype.divRound = function divRound(num) {
  var dm = this.divmod(num);

  // Fast case - exact division
  if (dm.mod.isZero()) return dm.div;

  var mod = dm.div.negative !== 0 ? dm.mod.isub(num) : dm.mod;

  var half = num.ushrn(1);
  var r2 = num.andln(1);
  var cmp = mod.cmp(half);

  // Round down
  if (cmp < 0 || r2 === 1 && cmp === 0) return dm.div;

  // Round up
  return dm.div.negative !== 0 ? dm.div.isubn(1) : dm.div.iaddn(1);
};

BN.prototype.modn = function modn(num) {
  assert(num <= 0x3ffffff);
  var p = (1 << 26) % num;

  var acc = 0;
  for (var i = this.length - 1; i >= 0; i--) {
    acc = (p * acc + (this.words[i] | 0)) % num;
  }

  return acc;
};

// In-place division by number
BN.prototype.idivn = function idivn(num) {
  assert(num <= 0x3ffffff);

  var carry = 0;
  for (var i = this.length - 1; i >= 0; i--) {
    var w = (this.words[i] | 0) + carry * 0x4000000;
    this.words[i] = (w / num) | 0;
    carry = w % num;
  }

  return this.strip();
};

BN.prototype.divn = function divn(num) {
  return this.clone().idivn(num);
};

BN.prototype.egcd = function egcd(p) {
  assert(p.negative === 0);
  assert(!p.isZero());

  var x = this;
  var y = p.clone();

  if (x.negative !== 0) {
    x = x.umod(p);
  } else {
    x = x.clone();
  }

  // A * x + B * y = x
  var A = new BN(1);
  var B = new BN(0);

  // C * x + D * y = y
  var C = new BN(0);
  var D = new BN(1);

  var g = 0;

  while (x.isEven() && y.isEven()) {
    x.iushrn(1);
    y.iushrn(1);
    ++g;
  }

  var yp = y.clone();
  var xp = x.clone();

  while (!x.isZero()) {
    for (var i = 0, im = 1; (x.words[0] & im) === 0 && i < 26; ++i, im <<= 1);
    if (i > 0) {
      x.iushrn(i);
      while (i-- > 0) {
        if (A.isOdd() || B.isOdd()) {
          A.iadd(yp);
          B.isub(xp);
        }

        A.iushrn(1);
        B.iushrn(1);
      }
    }

    for (var j = 0, jm = 1; (y.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
    if (j > 0) {
      y.iushrn(j);
      while (j-- > 0) {
        if (C.isOdd() || D.isOdd()) {
          C.iadd(yp);
          D.isub(xp);
        }

        C.iushrn(1);
        D.iushrn(1);
      }
    }

    if (x.cmp(y) >= 0) {
      x.isub(y);
      A.isub(C);
      B.isub(D);
    } else {
      y.isub(x);
      C.isub(A);
      D.isub(B);
    }
  }

  return {
    a: C,
    b: D,
    gcd: y.iushln(g)
  };
};

// This is reduced incarnation of the binary EEA
// above, designated to invert members of the
// _prime_ fields F(p) at a maximal speed
BN.prototype._invmp = function _invmp(p) {
  assert(p.negative === 0);
  assert(!p.isZero());

  var a = this;
  var b = p.clone();

  if (a.negative !== 0) {
    a = a.umod(p);
  } else {
    a = a.clone();
  }

  var x1 = new BN(1);
  var x2 = new BN(0);

  var delta = b.clone();

  while (a.cmpn(1) > 0 && b.cmpn(1) > 0) {
    for (var i = 0, im = 1; (a.words[0] & im) === 0 && i < 26; ++i, im <<= 1);
    if (i > 0) {
      a.iushrn(i);
      while (i-- > 0) {
        if (x1.isOdd()) {
          x1.iadd(delta);
        }

        x1.iushrn(1);
      }
    }

    for (var j = 0, jm = 1; (b.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
    if (j > 0) {
      b.iushrn(j);
      while (j-- > 0) {
        if (x2.isOdd()) {
          x2.iadd(delta);
        }

        x2.iushrn(1);
      }
    }

    if (a.cmp(b) >= 0) {
      a.isub(b);
      x1.isub(x2);
    } else {
      b.isub(a);
      x2.isub(x1);
    }
  }

  var res;
  if (a.cmpn(1) === 0) {
    res = x1;
  } else {
    res = x2;
  }

  if (res.cmpn(0) < 0) {
    res.iadd(p);
  }

  return res;
};

BN.prototype.gcd = function gcd(num) {
  if (this.isZero()) return num.abs();
  if (num.isZero()) return this.abs();

  var a = this.clone();
  var b = num.clone();
  a.negative = 0;
  b.negative = 0;

  // Remove common factor of two
  for (var shift = 0; a.isEven() && b.isEven(); shift++) {
    a.iushrn(1);
    b.iushrn(1);
  }

  do {
    while (a.isEven()) {
      a.iushrn(1);
    }
    while (b.isEven()) {
      b.iushrn(1);
    }

    var r = a.cmp(b);
    if (r < 0) {
      // Swap `a` and `b` to make `a` always bigger than `b`
      var t = a;
      a = b;
      b = t;
    } else if (r === 0 || b.cmpn(1) === 0) {
      break;
    }

    a.isub(b);
  } while (true);

  return b.iushln(shift);
};

// Invert number in the field F(num)
BN.prototype.invm = function invm(num) {
  return this.egcd(num).a.umod(num);
};

BN.prototype.isEven = function isEven() {
  return (this.words[0] & 1) === 0;
};

BN.prototype.isOdd = function isOdd() {
  return (this.words[0] & 1) === 1;
};

// And first word and num
BN.prototype.andln = function andln(num) {
  return this.words[0] & num;
};

// Increment at the bit position in-line
BN.prototype.bincn = function bincn(bit) {
  assert(typeof bit === 'number');
  var r = bit % 26;
  var s = (bit - r) / 26;
  var q = 1 << r;

  // Fast case: bit is much higher than all existing words
  if (this.length <= s) {
    this._expand(s + 1);
    this.words[s] |= q;
    return this;
  }

  // Add bit and propagate, if needed
  var carry = q;
  for (var i = s; carry !== 0 && i < this.length; i++) {
    var w = this.words[i] | 0;
    w += carry;
    carry = w >>> 26;
    w &= 0x3ffffff;
    this.words[i] = w;
  }
  if (carry !== 0) {
    this.words[i] = carry;
    this.length++;
  }
  return this;
};

BN.prototype.isZero = function isZero() {
  return this.length === 1 && this.words[0] === 0;
};

BN.prototype.cmpn = function cmpn(num) {
  var negative = num < 0;

  if (this.negative !== 0 && !negative) return -1;
  if (this.negative === 0 && negative) return 1;

  this.strip();

  var res;
  if (this.length > 1) {
    res = 1;
  } else {
    if (negative) {
      num = -num;
    }

    assert(num <= 0x3ffffff, 'Number is too big');

    var w = this.words[0] | 0;
    res = w === num ? 0 : w < num ? -1 : 1;
  }
  if (this.negative !== 0) return -res | 0;
  return res;
};

// Compare two numbers and return:
// 1 - if `this` > `num`
// 0 - if `this` == `num`
// -1 - if `this` < `num`
BN.prototype.cmp = function cmp(num) {
  if (this.negative !== 0 && num.negative === 0) return -1;
  if (this.negative === 0 && num.negative !== 0) return 1;

  var res = this.ucmp(num);
  if (this.negative !== 0) return -res | 0;
  return res;
};

// Unsigned comparison
BN.prototype.ucmp = function ucmp(num) {
  // At this point both numbers have the same sign
  if (this.length > num.length) return 1;
  if (this.length < num.length) return -1;

  var res = 0;
  for (var i = this.length - 1; i >= 0; i--) {
    var a = this.words[i] | 0;
    var b = num.words[i] | 0;

    if (a === b) continue;
    if (a < b) {
      res = -1;
    } else if (a > b) {
      res = 1;
    }
    break;
  }
  return res;
};

BN.prototype.gtn = function gtn(num) {
  return this.cmpn(num) === 1;
};

BN.prototype.gt = function gt(num) {
  return this.cmp(num) === 1;
};

BN.prototype.gten = function gten(num) {
  return this.cmpn(num) >= 0;
};

BN.prototype.gte = function gte(num) {
  return this.cmp(num) >= 0;
};

BN.prototype.ltn = function ltn(num) {
  return this.cmpn(num) === -1;
};

BN.prototype.lt = function lt(num) {
  return this.cmp(num) === -1;
};

BN.prototype.lten = function lten(num) {
  return this.cmpn(num) <= 0;
};

BN.prototype.lte = function lte(num) {
  return this.cmp(num) <= 0;
};

BN.prototype.eqn = function eqn(num) {
  return this.cmpn(num) === 0;
};

BN.prototype.eq = function eq(num) {
  return this.cmp(num) === 0;
};

//
// A reduce context, could be using montgomery or something better, depending
// on the `m` itself.
//
BN.red = function red(num) {
  return new Red(num);
};

BN.prototype.toRed = function toRed(ctx) {
  assert(!this.red, 'Already a number in reduction context');
  assert(this.negative === 0, 'red works only with positives');
  return ctx.convertTo(this)._forceRed(ctx);
};

BN.prototype.fromRed = function fromRed() {
  assert(this.red, 'fromRed works only with numbers in reduction context');
  return this.red.convertFrom(this);
};

BN.prototype._forceRed = function _forceRed(ctx) {
  this.red = ctx;
  return this;
};

BN.prototype.forceRed = function forceRed(ctx) {
  assert(!this.red, 'Already a number in reduction context');
  return this._forceRed(ctx);
};

BN.prototype.redAdd = function redAdd(num) {
  assert(this.red, 'redAdd works only with red numbers');
  return this.red.add(this, num);
};

BN.prototype.redIAdd = function redIAdd(num) {
  assert(this.red, 'redIAdd works only with red numbers');
  return this.red.iadd(this, num);
};

BN.prototype.redSub = function redSub(num) {
  assert(this.red, 'redSub works only with red numbers');
  return this.red.sub(this, num);
};

BN.prototype.redISub = function redISub(num) {
  assert(this.red, 'redISub works only with red numbers');
  return this.red.isub(this, num);
};

BN.prototype.redShl = function redShl(num) {
  assert(this.red, 'redShl works only with red numbers');
  return this.red.shl(this, num);
};

BN.prototype.redMul = function redMul(num) {
  assert(this.red, 'redMul works only with red numbers');
  this.red._verify2(this, num);
  return this.red.mul(this, num);
};

BN.prototype.redIMul = function redIMul(num) {
  assert(this.red, 'redMul works only with red numbers');
  this.red._verify2(this, num);
  return this.red.imul(this, num);
};

BN.prototype.redSqr = function redSqr() {
  assert(this.red, 'redSqr works only with red numbers');
  this.red._verify1(this);
  return this.red.sqr(this);
};

BN.prototype.redISqr = function redISqr() {
  assert(this.red, 'redISqr works only with red numbers');
  this.red._verify1(this);
  return this.red.isqr(this);
};

// Square root over p
BN.prototype.redSqrt = function redSqrt() {
  assert(this.red, 'redSqrt works only with red numbers');
  this.red._verify1(this);
  return this.red.sqrt(this);
};

BN.prototype.redInvm = function redInvm() {
  assert(this.red, 'redInvm works only with red numbers');
  this.red._verify1(this);
  return this.red.invm(this);
};

// Return negative clone of `this` % `red modulo`
BN.prototype.redNeg = function redNeg() {
  assert(this.red, 'redNeg works only with red numbers');
  this.red._verify1(this);
  return this.red.neg(this);
};

BN.prototype.redPow = function redPow(num) {
  assert(this.red && !num.red, 'redPow(normalNum)');
  this.red._verify1(this);
  return this.red.pow(this, num);
};

// Prime numbers with efficient reduction
var primes = {
  k256: null,
  p224: null,
  p192: null,
  p25519: null
};

// Pseudo-Mersenne prime
function MPrime(name, p) {
  // P = 2 ^ N - K
  this.name = name;
  this.p = new BN(p, 16);
  this.n = this.p.bitLength();
  this.k = new BN(1).iushln(this.n).isub(this.p);

  this.tmp = this._tmp();
}

MPrime.prototype._tmp = function _tmp() {
  var tmp = new BN(null);
  tmp.words = new Array(Math.ceil(this.n / 13));
  return tmp;
};

MPrime.prototype.ireduce = function ireduce(num) {
  // Assumes that `num` is less than `P^2`
  // num = HI * (2 ^ N - K) + HI * K + LO = HI * K + LO (mod P)
  var r = num;
  var rlen;

  do {
    this.split(r, this.tmp);
    r = this.imulK(r);
    r = r.iadd(this.tmp);
    rlen = r.bitLength();
  } while (rlen > this.n);

  var cmp = rlen < this.n ? -1 : r.ucmp(this.p);
  if (cmp === 0) {
    r.words[0] = 0;
    r.length = 1;
  } else if (cmp > 0) {
    r.isub(this.p);
  } else {
    if (r.strip !== undefined) {
      // r is BN v4 instance
      r.strip();
    } else {
      // r is BN v5 instance
      r._strip();
    }
  }

  return r;
};

MPrime.prototype.split = function split(input, out) {
  input.iushrn(this.n, 0, out);
};

MPrime.prototype.imulK = function imulK(num) {
  return num.imul(this.k);
};

function K256() {
  MPrime.call(
    this,
    'k256',
    'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f');
}
inherits(K256, MPrime);

K256.prototype.split = function split(input, output) {
  // 256 = 9 * 26 + 22
  var mask = 0x3fffff;

  var outLen = Math.min(input.length, 9);
  for (var i = 0; i < outLen; i++) {
    output.words[i] = input.words[i];
  }
  output.length = outLen;

  if (input.length <= 9) {
    input.words[0] = 0;
    input.length = 1;
    return;
  }

  // Shift by 9 limbs
  var prev = input.words[9];
  output.words[output.length++] = prev & mask;

  for (i = 10; i < input.length; i++) {
    var next = input.words[i] | 0;
    input.words[i - 10] = ((next & mask) << 4) | (prev >>> 22);
    prev = next;
  }
  prev >>>= 22;
  input.words[i - 10] = prev;
  if (prev === 0 && input.length > 10) {
    input.length -= 10;
  } else {
    input.length -= 9;
  }
};

K256.prototype.imulK = function imulK(num) {
  // K = 0x1000003d1 = [ 0x40, 0x3d1 ]
  num.words[num.length] = 0;
  num.words[num.length + 1] = 0;
  num.length += 2;

  // bounded at: 0x40 * 0x3ffffff + 0x3d0 = 0x100000390
  var lo = 0;
  for (var i = 0; i < num.length; i++) {
    var w = num.words[i] | 0;
    lo += w * 0x3d1;
    num.words[i] = lo & 0x3ffffff;
    lo = w * 0x40 + ((lo / 0x4000000) | 0);
  }

  // Fast length reduction
  if (num.words[num.length - 1] === 0) {
    num.length--;
    if (num.words[num.length - 1] === 0) {
      num.length--;
    }
  }
  return num;
};

function P224() {
  MPrime.call(
    this,
    'p224',
    'ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001');
}
inherits(P224, MPrime);

function P192() {
  MPrime.call(
    this,
    'p192',
    'ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff');
}
inherits(P192, MPrime);

function P25519() {
  // 2 ^ 255 - 19
  MPrime.call(
    this,
    '25519',
    '7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed');
}
inherits(P25519, MPrime);

P25519.prototype.imulK = function imulK(num) {
  // K = 0x13
  var carry = 0;
  for (var i = 0; i < num.length; i++) {
    var hi = (num.words[i] | 0) * 0x13 + carry;
    var lo = hi & 0x3ffffff;
    hi >>>= 26;

    num.words[i] = lo;
    carry = hi;
  }
  if (carry !== 0) {
    num.words[num.length++] = carry;
  }
  return num;
};

// Exported mostly for testing purposes, use plain name instead
BN._prime = function prime(name) {
  // Cached version of prime
  if (primes[name]) return primes[name];

  var prime;
  if (name === 'k256') {
    prime = new K256();
  } else if (name === 'p224') {
    prime = new P224();
  } else if (name === 'p192') {
    prime = new P192();
  } else if (name === 'p25519') {
    prime = new P25519();
  } else {
    throw new Error('Unknown prime ' + name);
  }
  primes[name] = prime;

  return prime;
};

//
// Base reduction engine
//
function Red(m) {
  if (typeof m === 'string') {
    var prime = BN._prime(m);
    this.m = prime.p;
    this.prime = prime;
  } else {
    assert(m.gtn(1), 'modulus must be greater than 1');
    this.m = m;
    this.prime = null;
  }
}

Red.prototype._verify1 = function _verify1(a) {
  assert(a.negative === 0, 'red works only with positives');
  assert(a.red, 'red works only with red numbers');
};

Red.prototype._verify2 = function _verify2(a, b) {
  assert((a.negative | b.negative) === 0, 'red works only with positives');
  assert(a.red && a.red === b.red,
    'red works only with red numbers');
};

Red.prototype.imod = function imod(a) {
  if (this.prime) return this.prime.ireduce(a)._forceRed(this);
  return a.umod(this.m)._forceRed(this);
};

Red.prototype.neg = function neg(a) {
  if (a.isZero()) {
    return a.clone();
  }

  return this.m.sub(a)._forceRed(this);
};

Red.prototype.add = function add(a, b) {
  this._verify2(a, b);

  var res = a.add(b);
  if (res.cmp(this.m) >= 0) {
    res.isub(this.m);
  }
  return res._forceRed(this);
};

Red.prototype.iadd = function iadd(a, b) {
  this._verify2(a, b);

  var res = a.iadd(b);
  if (res.cmp(this.m) >= 0) {
    res.isub(this.m);
  }
  return res;
};

Red.prototype.sub = function sub(a, b) {
  this._verify2(a, b);

  var res = a.sub(b);
  if (res.cmpn(0) < 0) {
    res.iadd(this.m);
  }
  return res._forceRed(this);
};

Red.prototype.isub = function isub(a, b) {
  this._verify2(a, b);

  var res = a.isub(b);
  if (res.cmpn(0) < 0) {
    res.iadd(this.m);
  }
  return res;
};

Red.prototype.shl = function shl(a, num) {
  this._verify1(a);
  return this.imod(a.ushln(num));
};

Red.prototype.imul = function imul(a, b) {
  this._verify2(a, b);
  return this.imod(a.imul(b));
};

Red.prototype.mul = function mul(a, b) {
  this._verify2(a, b);
  return this.imod(a.mul(b));
};

Red.prototype.isqr = function isqr(a) {
  return this.imul(a, a.clone());
};

Red.prototype.sqr = function sqr(a) {
  return this.mul(a, a);
};

Red.prototype.sqrt = function sqrt(a) {
  if (a.isZero()) return a.clone();

  var mod3 = this.m.andln(3);
  assert(mod3 % 2 === 1);

  // Fast case
  if (mod3 === 3) {
    var pow = this.m.add(new BN(1)).iushrn(2);
    return this.pow(a, pow);
  }

  // Tonelli-Shanks algorithm (Totally unoptimized and slow)
  //
  // Find Q and S, that Q * 2 ^ S = (P - 1)
  var q = this.m.subn(1);
  var s = 0;
  while (!q.isZero() && q.andln(1) === 0) {
    s++;
    q.iushrn(1);
  }
  assert(!q.isZero());

  var one = new BN(1).toRed(this);
  var nOne = one.redNeg();

  // Find quadratic non-residue
  // NOTE: Max is such because of generalized Riemann hypothesis.
  var lpow = this.m.subn(1).iushrn(1);
  var z = this.m.bitLength();
  z = new BN(2 * z * z).toRed(this);

  while (this.pow(z, lpow).cmp(nOne) !== 0) {
    z.redIAdd(nOne);
  }

  var c = this.pow(z, q);
  var r = this.pow(a, q.addn(1).iushrn(1));
  var t = this.pow(a, q);
  var m = s;
  while (t.cmp(one) !== 0) {
    var tmp = t;
    for (var i = 0; tmp.cmp(one) !== 0; i++) {
      tmp = tmp.redSqr();
    }
    assert(i < m);
    var b = this.pow(c, new BN(1).iushln(m - i - 1));

    r = r.redMul(b);
    c = b.redSqr();
    t = t.redMul(c);
    m = i;
  }

  return r;
};

Red.prototype.invm = function invm(a) {
  var inv = a._invmp(this.m);
  if (inv.negative !== 0) {
    inv.negative = 0;
    return this.imod(inv).redNeg();
  } else {
    return this.imod(inv);
  }
};

Red.prototype.pow = function pow(a, num) {
  if (num.isZero()) return new BN(1).toRed(this);
  if (num.cmpn(1) === 0) return a.clone();

  var windowSize = 4;
  var wnd = new Array(1 << windowSize);
  wnd[0] = new BN(1).toRed(this);
  wnd[1] = a;
  for (var i = 2; i < wnd.length; i++) {
    wnd[i] = this.mul(wnd[i - 1], a);
  }

  var res = wnd[0];
  var current = 0;
  var currentLen = 0;
  var start = num.bitLength() % 26;
  if (start === 0) {
    start = 26;
  }

  for (i = num.length - 1; i >= 0; i--) {
    var word = num.words[i];
    for (var j = start - 1; j >= 0; j--) {
      var bit = (word >> j) & 1;
      if (res !== wnd[0]) {
        res = this.sqr(res);
      }

      if (bit === 0 && current === 0) {
        currentLen = 0;
        continue;
      }

      current <<= 1;
      current |= bit;
      currentLen++;
      if (currentLen !== windowSize && (i !== 0 || j !== 0)) continue;

      res = this.mul(res, wnd[current]);
      currentLen = 0;
      current = 0;
    }
    start = 26;
  }

  return res;
};

Red.prototype.convertTo = function convertTo(num) {
  var r = num.umod(this.m);

  return r === num ? r.clone() : r;
};

Red.prototype.convertFrom = function convertFrom(num) {
  var res = num.clone();
  res.red = null;
  return res;
};

//
// Montgomery method engine
//

BN.mont = function mont(num) {
  return new Mont(num);
};

function Mont(m) {
  Red.call(this, m);

  this.shift = this.m.bitLength();
  if (this.shift % 26 !== 0) {
    this.shift += 26 - (this.shift % 26);
  }

  this.r = new BN(1).iushln(this.shift);
  this.r2 = this.imod(this.r.sqr());
  this.rinv = this.r._invmp(this.m);

  this.minv = this.rinv.mul(this.r).isubn(1).div(this.m);
  this.minv = this.minv.umod(this.r);
  this.minv = this.r.sub(this.minv);
}
inherits(Mont, Red);

Mont.prototype.convertTo = function convertTo(num) {
  return this.imod(num.ushln(this.shift));
};

Mont.prototype.convertFrom = function convertFrom(num) {
  var r = this.imod(num.mul(this.rinv));
  r.red = null;
  return r;
};

Mont.prototype.imul = function imul(a, b) {
  if (a.isZero() || b.isZero()) {
    a.words[0] = 0;
    a.length = 1;
    return a;
  }

  var t = a.imul(b);
  var c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
  var u = t.isub(c).iushrn(this.shift);
  var res = u;

  if (u.cmp(this.m) >= 0) {
    res = u.isub(this.m);
  } else if (u.cmpn(0) < 0) {
    res = u.iadd(this.m);
  }

  return res._forceRed(this);
};

Mont.prototype.mul = function mul(a, b) {
  if (a.isZero() || b.isZero()) return new BN(0)._forceRed(this);

  var t = a.mul(b);
  var c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
  var u = t.isub(c).iushrn(this.shift);
  var res = u;
  if (u.cmp(this.m) >= 0) {
    res = u.isub(this.m);
  } else if (u.cmpn(0) < 0) {
    res = u.iadd(this.m);
  }

  return res._forceRed(this);
};

Mont.prototype.invm = function invm(a) {
  // (AR)^-1 * R^2 = (A^-1 * R^-1) * R^2 = A^-1 * R
  var res = this.imod(a._invmp(this.m).mul(this.r2));
  return res._forceRed(this);
};
function toArray(msg, enc) {
  if (Array.isArray(msg))
    return msg.slice();
  if (!msg)
    return [];
  var res = [];
  if (typeof msg !== 'string') {
    for (var i = 0; i < msg.length; i++)
      res[i] = msg[i] | 0;
    return res;
  }
  if (enc === 'hex') {
    msg = msg.replace(/[^a-z0-9]+/ig, '');
    if (msg.length % 2 !== 0)
      msg = '0' + msg;
    for (var i = 0; i < msg.length; i += 2)
      res.push(parseInt(msg[i] + msg[i + 1], 16));
  } else {
    for (var i = 0; i < msg.length; i++) {
      var c = msg.charCodeAt(i);
      var hi = c >> 8;
      var lo = c & 0xff;
      if (hi)
        res.push(hi, lo);
      else
        res.push(lo);
    }
  }
  return res;
}

function minAssert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
}
function HmacDRBG() {

  function HmacDRBG(options) {
    if (!(this instanceof HmacDRBG))
      return new HmacDRBG(options);
    this.hash = options.hash;
    this.predResist = !!options.predResist;

    this.outLen = this.hash.outSize;
    this.minEntropy = options.minEntropy || this.hash.hmacStrength;

    this._reseed = null;
    this.reseedInterval = null;
    this.K = null;
    this.V = null;

    var entropy = toArray(options.entropy, options.entropyEnc || 'hex');
    var nonce = toArray(options.nonce, options.nonceEnc || 'hex');
    var pers = toArray(options.pers, options.persEnc || 'hex');
    minAssert(entropy.length >= (this.minEntropy / 8),
      'Not enough entropy. Minimum is: ' + this.minEntropy + ' bits');
    this._init(entropy, nonce, pers);
  }

  HmacDRBG.prototype._init = function init(entropy, nonce, pers) {
    var seed = entropy.concat(nonce).concat(pers);

    this.K = new Array(this.outLen / 8);
    this.V = new Array(this.outLen / 8);
    for (var i = 0; i < this.V.length; i++) {
      this.K[i] = 0x00;
      this.V[i] = 0x01;
    }

    this._update(seed);
    this._reseed = 1;
    this.reseedInterval = 0x1000000000000;  // 2^48
  };

  HmacDRBG.prototype._hmac = function hmac() {
    return new hash.hmac(this.hash, this.K);
  };

  HmacDRBG.prototype._update = function update(seed) {
    var kmac = this._hmac()
      .update(this.V)
      .update([0x00]);
    if (seed)
      kmac = kmac.update(seed);
    this.K = kmac.digest();
    this.V = this._hmac().update(this.V).digest();
    if (!seed)
      return;

    this.K = this._hmac()
      .update(this.V)
      .update([0x01])
      .update(seed)
      .digest();
    this.V = this._hmac().update(this.V).digest();
  };

  HmacDRBG.prototype.reseed = function reseed(entropy, entropyEnc, add, addEnc) {
    // Optional entropy enc
    if (typeof entropyEnc !== 'string') {
      addEnc = add;
      add = entropyEnc;
      entropyEnc = null;
    }

    entropy = utils.toArray(entropy, entropyEnc);
    add = utils.toArray(add, addEnc);

    minAssert(entropy.length >= (this.minEntropy / 8),
      'Not enough entropy. Minimum is: ' + this.minEntropy + ' bits');

    this._update(entropy.concat(add || []));
    this._reseed = 1;
  };

  HmacDRBG.prototype.generate = function generate(len, enc, add, addEnc) {
    if (this._reseed > this.reseedInterval)
      throw new Error('Reseed is required');

    // Optional encoding
    if (typeof enc !== 'string') {
      addEnc = add;
      add = enc;
      enc = null;
    }

    // Optional additional data
    if (add) {
      add = utils.toArray(add, addEnc || 'hex');
      this._update(add);
    }

    var temp = [];
    while (temp.length < len) {
      this.V = this._hmac().update(this.V).digest();
      temp = temp.concat(this.V);
    }

    var res = temp.slice(0, len);
    this._update(add);
    this._reseed++;
    return utils.encode(res, enc);
  };
  return HmacDRBG;
}

function getNAF(num, w, bits) {
  var naf = new Array(Math.max(num.bitLength(), bits) + 1);
  var i;
  for (i = 0; i < naf.length; i += 1) {
    naf[i] = 0;
  }

  var ws = 1 << (w + 1);
  var k = num.clone();

  for (i = 0; i < naf.length; i++) {
    var z;
    var mod = k.andln(ws - 1);
    if (k.isOdd()) {
      if (mod > (ws >> 1) - 1)
        z = (ws >> 1) - mod;
      else
        z = mod;
      k.isubn(z);
    } else {
      z = 0;
    }

    naf[i] = z;
    k.iushrn(1);
  }

  return naf;
}

function getJSF(k1, k2) {
  var jsf = [
    [],
    [],
  ];

  k1 = k1.clone();
  k2 = k2.clone();
  var d1 = 0;
  var d2 = 0;
  var m8;
  while (k1.cmpn(-d1) > 0 || k2.cmpn(-d2) > 0) {
    // First phase
    var m14 = (k1.andln(3) + d1) & 3;
    var m24 = (k2.andln(3) + d2) & 3;
    if (m14 === 3)
      m14 = -1;
    if (m24 === 3)
      m24 = -1;
    var u1;
    if ((m14 & 1) === 0) {
      u1 = 0;
    } else {
      m8 = (k1.andln(7) + d1) & 7;
      if ((m8 === 3 || m8 === 5) && m24 === 2)
        u1 = -m14;
      else
        u1 = m14;
    }
    jsf[0].push(u1);

    var u2;
    if ((m24 & 1) === 0) {
      u2 = 0;
    } else {
      m8 = (k2.andln(7) + d2) & 7;
      if ((m8 === 3 || m8 === 5) && m14 === 2)
        u2 = -m24;
      else
        u2 = m24;
    }
    jsf[1].push(u2);

    // Second phase
    if (2 * d1 === u1 + 1)
      d1 = 1 - d1;
    if (2 * d2 === u2 + 1)
      d2 = 1 - d2;
    k1.iushrn(1);
    k2.iushrn(1);
  }

  return jsf;
}

function utilsHashToHex32(msg, endian) {
  var res = '';
  for (var i = 0; i < msg.length; i++) {
    var w = msg[i];
    if (endian === 'little')
      w = htonl(w);
    res += zero8(w.toString(16));
  }
  return res;
}

function utilsHashSplit32(msg, endian) {
  var res = new Array(msg.length * 4);
  for (var i = 0, k = 0; i < msg.length; i++, k += 4) {
    var m = msg[i];
    if (endian === 'big') {
      res[k] = m >>> 24;
      res[k + 1] = (m >>> 16) & 0xff;
      res[k + 2] = (m >>> 8) & 0xff;
      res[k + 3] = m & 0xff;
    } else {
      res[k + 3] = m >>> 24;
      res[k + 2] = (m >>> 16) & 0xff;
      res[k + 1] = (m >>> 8) & 0xff;
      res[k] = m & 0xff;
    }
  }
  return res;
}

function SHA384() {
  if (!(this instanceof SHA384))
    return new SHA384();

  SHA512.call(this);
  this.h = [
    0xcbbb9d5d, 0xc1059ed8,
    0x629a292a, 0x367cd507,
    0x9159015a, 0x3070dd17,
    0x152fecd8, 0xf70e5939,
    0x67332667, 0xffc00b31,
    0x8eb44a87, 0x68581511,
    0xdb0c2e0d, 0x64f98fa7,
    0x47b5481d, 0xbefa4fa4];
}
inherits(SHA384, SHA512);
module.exports = SHA384;

SHA384.blockSize = 1024;
SHA384.outSize = 384;
SHA384.hmacStrength = 192;
SHA384.padLength = 128;

SHA384.prototype._digest = function digest(enc) {
  if (enc === 'hex')
    return utilsHashToHex32(this.h.slice(0, 12), 'big');
  else
    return utilsHashSplit32(this.h.slice(0, 12), 'big');
};

var curve = exports;
function BaseCurve(type, conf) {
  this.type = type;
  this.p = new BN(conf.p, 16);

  // Use Montgomery, when there is no fast reduction for the prime
  this.red = conf.prime ? BN.red(conf.prime) : BN.mont(this.p);

  // Useful for many curves
  this.zero = new BN(0).toRed(this.red);
  this.one = new BN(1).toRed(this.red);
  this.two = new BN(2).toRed(this.red);

  // Curve configuration, optional
  this.n = conf.n && new BN(conf.n, 16);
  this.g = conf.g && this.pointFromJSON(conf.g, conf.gRed);

  // Temporary arrays
  this._wnafT1 = new Array(4);
  this._wnafT2 = new Array(4);
  this._wnafT3 = new Array(4);
  this._wnafT4 = new Array(4);

  this._bitLength = this.n ? this.n.bitLength() : 0;

  // Generalized Greg Maxwell's trick
  var adjustCount = this.n && this.p.div(this.n);
  if (!adjustCount || adjustCount.cmpn(100) > 0) {
    this.redN = null;
  } else {
    this._maxwellTrick = true;
    this.redN = this.n.toRed(this.red);
  }
}
curve.base = BaseCurve;

BaseCurve.prototype.point = function point() {
  throw new Error('Not implemented');
};

BaseCurve.prototype.validate = function validate() {
  throw new Error('Not implemented');
};

BaseCurve.prototype._fixedNafMul = function _fixedNafMul(p, k) {
  minAssert(p.precomputed);
  var doubles = p._getDoubles();

  var naf = getNAF(k, 1, this._bitLength);
  var I = (1 << (doubles.step + 1)) - (doubles.step % 2 === 0 ? 2 : 1);
  I /= 3;

  // Translate into more windowed form
  var repr = [];
  var j;
  var nafW;
  for (j = 0; j < naf.length; j += doubles.step) {
    nafW = 0;
    for (var l = j + doubles.step - 1; l >= j; l--)
      nafW = (nafW << 1) + naf[l];
    repr.push(nafW);
  }

  var a = this.jpoint(null, null, null);
  var b = this.jpoint(null, null, null);
  for (var i = I; i > 0; i--) {
    for (j = 0; j < repr.length; j++) {
      nafW = repr[j];
      if (nafW === i)
        b = b.mixedAdd(doubles.points[j]);
      else if (nafW === -i)
        b = b.mixedAdd(doubles.points[j].neg());
    }
    a = a.add(b);
  }
  return a.toP();
};

BaseCurve.prototype._wnafMul = function _wnafMul(p, k) {
  var w = 4;

  // Precompute window
  var nafPoints = p._getNAFPoints(w);
  w = nafPoints.wnd;
  var wnd = nafPoints.points;

  // Get NAF form
  var naf = getNAF(k, w, this._bitLength);

  // Add `this`*(N+1) for every w-NAF index
  var acc = this.jpoint(null, null, null);
  for (var i = naf.length - 1; i >= 0; i--) {
    // Count zeroes
    for (var l = 0; i >= 0 && naf[i] === 0; i--)
      l++;
    if (i >= 0)
      l++;
    acc = acc.dblp(l);

    if (i < 0)
      break;
    var z = naf[i];
    minminAssert(z !== 0);
    if (p.type === 'affine') {
      // J +- P
      if (z > 0)
        acc = acc.mixedAdd(wnd[(z - 1) >> 1]);
      else
        acc = acc.mixedAdd(wnd[(-z - 1) >> 1].neg());
    } else {
      // J +- J
      if (z > 0)
        acc = acc.add(wnd[(z - 1) >> 1]);
      else
        acc = acc.add(wnd[(-z - 1) >> 1].neg());
    }
  }
  return p.type === 'affine' ? acc.toP() : acc;
};

BaseCurve.prototype._wnafMulAdd = function _wnafMulAdd(defW,
  points,
  coeffs,
  len,
  jacobianResult) {
  var wndWidth = this._wnafT1;
  var wnd = this._wnafT2;
  var naf = this._wnafT3;

  // Fill all arrays
  var max = 0;
  var i;
  var j;
  var p;
  for (i = 0; i < len; i++) {
    p = points[i];
    var nafPoints = p._getNAFPoints(defW);
    wndWidth[i] = nafPoints.wnd;
    wnd[i] = nafPoints.points;
  }

  // Comb small window NAFs
  for (i = len - 1; i >= 1; i -= 2) {
    var a = i - 1;
    var b = i;
    if (wndWidth[a] !== 1 || wndWidth[b] !== 1) {
      naf[a] = getNAF(coeffs[a], wndWidth[a], this._bitLength);
      naf[b] = getNAF(coeffs[b], wndWidth[b], this._bitLength);
      max = Math.max(naf[a].length, max);
      max = Math.max(naf[b].length, max);
      continue;
    }

    var comb = [
      points[a], /* 1 */
      null, /* 3 */
      null, /* 5 */
      points[b], /* 7 */
    ];

    // Try to avoid Projective points, if possible
    if (points[a].y.cmp(points[b].y) === 0) {
      comb[1] = points[a].add(points[b]);
      comb[2] = points[a].toJ().mixedAdd(points[b].neg());
    } else if (points[a].y.cmp(points[b].y.redNeg()) === 0) {
      comb[1] = points[a].toJ().mixedAdd(points[b]);
      comb[2] = points[a].add(points[b].neg());
    } else {
      comb[1] = points[a].toJ().mixedAdd(points[b]);
      comb[2] = points[a].toJ().mixedAdd(points[b].neg());
    }

    var index = [
      -3, /* -1 -1 */
      -1, /* -1 0 */
      -5, /* -1 1 */
      -7, /* 0 -1 */
      0, /* 0 0 */
      7, /* 0 1 */
      5, /* 1 -1 */
      1, /* 1 0 */
      3,  /* 1 1 */
    ];

    var jsf = getJSF(coeffs[a], coeffs[b]);
    max = Math.max(jsf[0].length, max);
    naf[a] = new Array(max);
    naf[b] = new Array(max);
    for (j = 0; j < max; j++) {
      var ja = jsf[0][j] | 0;
      var jb = jsf[1][j] | 0;

      naf[a][j] = index[(ja + 1) * 3 + (jb + 1)];
      naf[b][j] = 0;
      wnd[a] = comb;
    }
  }

  var acc = this.jpoint(null, null, null);
  var tmp = this._wnafT4;
  for (i = max; i >= 0; i--) {
    var k = 0;

    while (i >= 0) {
      var zero = true;
      for (j = 0; j < len; j++) {
        tmp[j] = naf[j][i] | 0;
        if (tmp[j] !== 0)
          zero = false;
      }
      if (!zero)
        break;
      k++;
      i--;
    }
    if (i >= 0)
      k++;
    acc = acc.dblp(k);
    if (i < 0)
      break;

    for (j = 0; j < len; j++) {
      var z = tmp[j];
      p;
      if (z === 0)
        continue;
      else if (z > 0)
        p = wnd[j][(z - 1) >> 1];
      else if (z < 0)
        p = wnd[j][(-z - 1) >> 1].neg();

      if (p.type === 'affine')
        acc = acc.mixedAdd(p);
      else
        acc = acc.add(p);
    }
  }
  // Zeroify references
  for (i = 0; i < len; i++)
    wnd[i] = null;

  if (jacobianResult)
    return acc;
  else
    return acc.toP();
};

function BasePoint(curve, type) {
  this.curve = curve;
  this.type = type;
  this.precomputed = null;
}
BaseCurve.BasePoint = BasePoint;

BasePoint.prototype.eq = function eq(/*other*/) {
  throw new Error('Not implemented');
};

BasePoint.prototype.validate = function validate() {
  return this.curve.validate(this);
};

BaseCurve.prototype.decodePoint = function decodePoint(bytes, enc) {
  bytes = utils.toArray(bytes, enc);

  var len = this.p.byteLength();

  // uncompressed, hybrid-odd, hybrid-even
  if ((bytes[0] === 0x04 || bytes[0] === 0x06 || bytes[0] === 0x07) &&
    bytes.length - 1 === 2 * len) {
    if (bytes[0] === 0x06)
      minAssert(bytes[bytes.length - 1] % 2 === 0);
    else if (bytes[0] === 0x07)
      minAssert(bytes[bytes.length - 1] % 2 === 1);

    var res = this.point(bytes.slice(1, 1 + len),
      bytes.slice(1 + len, 1 + 2 * len));

    return res;
  } else if ((bytes[0] === 0x02 || bytes[0] === 0x03) &&
    bytes.length - 1 === len) {
    return this.pointFromX(bytes.slice(1, 1 + len), bytes[0] === 0x03);
  }
  throw new Error('Unknown point format');
};

BasePoint.prototype.encodeCompressed = function encodeCompressed(enc) {
  return this.encode(enc, true);
};

BasePoint.prototype._encode = function _encode(compact) {
  var len = this.curve.p.byteLength();
  var x = this.getX().toArray('be', len);

  if (compact)
    return [this.getY().isEven() ? 0x02 : 0x03].concat(x);

  return [0x04].concat(x, this.getY().toArray('be', len));
};

BasePoint.prototype.encode = function encode(enc, compact) {
  return utils.encode(this._encode(compact), enc);
};

BasePoint.prototype.precompute = function precompute(power) {
  if (this.precomputed)
    return this;

  var precomputed = {
    doubles: null,
    naf: null,
    beta: null,
  };
  precomputed.naf = this._getNAFPoints(8);
  precomputed.doubles = this._getDoubles(4, power);
  precomputed.beta = this._getBeta();
  this.precomputed = precomputed;

  return this;
};

BasePoint.prototype._hasDoubles = function _hasDoubles(k) {
  if (!this.precomputed)
    return false;

  var doubles = this.precomputed.doubles;
  if (!doubles)
    return false;

  return doubles.points.length >= Math.ceil((k.bitLength() + 1) / doubles.step);
};

BasePoint.prototype._getDoubles = function _getDoubles(step, power) {
  if (this.precomputed && this.precomputed.doubles)
    return this.precomputed.doubles;

  var doubles = [this];
  var acc = this;
  for (var i = 0; i < power; i += step) {
    for (var j = 0; j < step; j++)
      acc = acc.dbl();
    doubles.push(acc);
  }
  return {
    step: step,
    points: doubles,
  };
};

BasePoint.prototype._getNAFPoints = function _getNAFPoints(wnd) {
  if (this.precomputed && this.precomputed.naf)
    return this.precomputed.naf;

  var res = [this];
  var max = (1 << wnd) - 1;
  var dbl = max === 1 ? null : this.dbl();
  for (var i = 1; i < max; i++)
    res[i] = res[i - 1].add(dbl);
  return {
    wnd: wnd,
    points: res,
  };
};

BasePoint.prototype._getBeta = function _getBeta() {
  return null;
};

BasePoint.prototype.dblp = function dblp(k) {
  var r = this;
  for (var i = 0; i < k; i++)
    r = r.dbl();
  return r;
};

function inherits(ctor, superCtor) {
  if (superCtor) {
    ctor.super_ = superCtor
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    })
  }
};

function theShort() {
  let Base = curve.base;

  function ShortCurve(conf) {
    Base.call(this, 'short', conf);

    this.a = new BN(conf.a, 16).toRed(this.red);
    this.b = new BN(conf.b, 16).toRed(this.red);
    this.tinv = this.two.redInvm();

    this.zeroA = this.a.fromRed().cmpn(0) === 0;
    this.threeA = this.a.fromRed().sub(this.p).cmpn(-3) === 0;

    // If the curve is endomorphic, precalculate beta and lambda
    this.endo = this._getEndomorphism(conf);
    this._endoWnafT1 = new Array(4);
    this._endoWnafT2 = new Array(4);
  }
  inherits(ShortCurve, Base);

  ShortCurve.prototype._getEndomorphism = function _getEndomorphism(conf) {
    // No efficient endomorphism
    if (!this.zeroA || !this.g || !this.n || this.p.modn(3) !== 1)
      return;

    // Compute beta and lambda, that lambda * P = (beta * Px; Py)
    var beta;
    var lambda;
    if (conf.beta) {
      beta = new BN(conf.beta, 16).toRed(this.red);
    } else {
      var betas = this._getEndoRoots(this.p);
      // Choose the smallest beta
      beta = betas[0].cmp(betas[1]) < 0 ? betas[0] : betas[1];
      beta = beta.toRed(this.red);
    }
    if (conf.lambda) {
      lambda = new BN(conf.lambda, 16);
    } else {
      // Choose the lambda that is matching selected beta
      var lambdas = this._getEndoRoots(this.n);
      if (this.g.mul(lambdas[0]).x.cmp(this.g.x.redMul(beta)) === 0) {
        lambda = lambdas[0];
      } else {
        lambda = lambdas[1];
        minAssert(this.g.mul(lambda).x.cmp(this.g.x.redMul(beta)) === 0);
      }
    }

    // Get basis vectors, used for balanced length-two representation
    var basis;
    if (conf.basis) {
      basis = conf.basis.map(function(vec) {
        return {
          a: new BN(vec.a, 16),
          b: new BN(vec.b, 16),
        };
      });
    } else {
      basis = this._getEndoBasis(lambda);
    }

    return {
      beta: beta,
      lambda: lambda,
      basis: basis,
    };
  };

  ShortCurve.prototype._getEndoRoots = function _getEndoRoots(num) {
    // Find roots of for x^2 + x + 1 in F
    // Root = (-1 +- Sqrt(-3)) / 2
    //
    var red = num === this.p ? this.red : BN.mont(num);
    var tinv = new BN(2).toRed(red).redInvm();
    var ntinv = tinv.redNeg();

    var s = new BN(3).toRed(red).redNeg().redSqrt().redMul(tinv);

    var l1 = ntinv.redAdd(s).fromRed();
    var l2 = ntinv.redSub(s).fromRed();
    return [l1, l2];
  };

  ShortCurve.prototype._getEndoBasis = function _getEndoBasis(lambda) {
    // aprxSqrt >= sqrt(this.n)
    var aprxSqrt = this.n.ushrn(Math.floor(this.n.bitLength() / 2));

    // 3.74
    // Run EGCD, until r(L + 1) < aprxSqrt
    var u = lambda;
    var v = this.n.clone();
    var x1 = new BN(1);
    var y1 = new BN(0);
    var x2 = new BN(0);
    var y2 = new BN(1);

    // NOTE: all vectors are roots of: a + b * lambda = 0 (mod n)
    var a0;
    var b0;
    // First vector
    var a1;
    var b1;
    // Second vector
    var a2;
    var b2;

    var prevR;
    var i = 0;
    var r;
    var x;
    while (u.cmpn(0) !== 0) {
      var q = v.div(u);
      r = v.sub(q.mul(u));
      x = x2.sub(q.mul(x1));
      var y = y2.sub(q.mul(y1));

      if (!a1 && r.cmp(aprxSqrt) < 0) {
        a0 = prevR.neg();
        b0 = x1;
        a1 = r.neg();
        b1 = x;
      } else if (a1 && ++i === 2) {
        break;
      }
      prevR = r;

      v = u;
      u = r;
      x2 = x1;
      x1 = x;
      y2 = y1;
      y1 = y;
    }
    a2 = r.neg();
    b2 = x;

    var len1 = a1.sqr().add(b1.sqr());
    var len2 = a2.sqr().add(b2.sqr());
    if (len2.cmp(len1) >= 0) {
      a2 = a0;
      b2 = b0;
    }

    // Normalize signs
    if (a1.negative) {
      a1 = a1.neg();
      b1 = b1.neg();
    }
    if (a2.negative) {
      a2 = a2.neg();
      b2 = b2.neg();
    }

    return [
      { a: a1, b: b1 },
      { a: a2, b: b2 },
    ];
  };

  ShortCurve.prototype._endoSplit = function _endoSplit(k) {
    var basis = this.endo.basis;
    var v1 = basis[0];
    var v2 = basis[1];

    var c1 = v2.b.mul(k).divRound(this.n);
    var c2 = v1.b.neg().mul(k).divRound(this.n);

    var p1 = c1.mul(v1.a);
    var p2 = c2.mul(v2.a);
    var q1 = c1.mul(v1.b);
    var q2 = c2.mul(v2.b);

    // Calculate answer
    var k1 = k.sub(p1).sub(p2);
    var k2 = q1.add(q2).neg();
    return { k1: k1, k2: k2 };
  };

  ShortCurve.prototype.pointFromX = function pointFromX(x, odd) {
    x = new BN(x, 16);
    if (!x.red)
      x = x.toRed(this.red);

    var y2 = x.redSqr().redMul(x).redIAdd(x.redMul(this.a)).redIAdd(this.b);
    var y = y2.redSqrt();
    if (y.redSqr().redSub(y2).cmp(this.zero) !== 0)
      throw new Error('invalid point');

    // XXX Is there any way to tell if the number is odd without converting it
    // to non-red form?
    var isOdd = y.fromRed().isOdd();
    if (odd && !isOdd || !odd && isOdd)
      y = y.redNeg();

    return this.point(x, y);
  };

  ShortCurve.prototype.validate = function validate(point) {
    if (point.inf)
      return true;

    var x = point.x;
    var y = point.y;

    var ax = this.a.redMul(x);
    var rhs = x.redSqr().redMul(x).redIAdd(ax).redIAdd(this.b);
    return y.redSqr().redISub(rhs).cmpn(0) === 0;
  };

  ShortCurve.prototype._endoWnafMulAdd =
    function _endoWnafMulAdd(points, coeffs, jacobianResult) {
      var npoints = this._endoWnafT1;
      var ncoeffs = this._endoWnafT2;
      for (var i = 0; i < points.length; i++) {
        var split = this._endoSplit(coeffs[i]);
        var p = points[i];
        var beta = p._getBeta();

        if (split.k1.negative) {
          split.k1.ineg();
          p = p.neg(true);
        }
        if (split.k2.negative) {
          split.k2.ineg();
          beta = beta.neg(true);
        }

        npoints[i * 2] = p;
        npoints[i * 2 + 1] = beta;
        ncoeffs[i * 2] = split.k1;
        ncoeffs[i * 2 + 1] = split.k2;
      }
      var res = this._wnafMulAdd(1, npoints, ncoeffs, i * 2, jacobianResult);

      // Clean-up references to points and coefficients
      for (var j = 0; j < i * 2; j++) {
        npoints[j] = null;
        ncoeffs[j] = null;
      }
      return res;
    };

  function Point(curve, x, y, isRed) {
    Base.BasePoint.call(this, curve, 'affine');
    if (x === null && y === null) {
      this.x = null;
      this.y = null;
      this.inf = true;
    } else {
      this.x = new BN(x, 16);
      this.y = new BN(y, 16);
      // Force redgomery representation when loading from JSON
      if (isRed) {
        this.x.forceRed(this.curve.red);
        this.y.forceRed(this.curve.red);
      }
      if (!this.x.red)
        this.x = this.x.toRed(this.curve.red);
      if (!this.y.red)
        this.y = this.y.toRed(this.curve.red);
      this.inf = false;
    }
  }
  inherits(Point, Base.BasePoint);

  ShortCurve.prototype.point = function point(x, y, isRed) {
    return new Point(this, x, y, isRed);
  };

  ShortCurve.prototype.pointFromJSON = function pointFromJSON(obj, red) {
    return Point.fromJSON(this, obj, red);
  };

  Point.prototype._getBeta = function _getBeta() {
    if (!this.curve.endo)
      return;

    var pre = this.precomputed;
    if (pre && pre.beta)
      return pre.beta;

    var beta = this.curve.point(this.x.redMul(this.curve.endo.beta), this.y);
    if (pre) {
      var curve = this.curve;
      var endoMul = function(p) {
        return curve.point(p.x.redMul(curve.endo.beta), p.y);
      };
      pre.beta = beta;
      beta.precomputed = {
        beta: null,
        naf: pre.naf && {
          wnd: pre.naf.wnd,
          points: pre.naf.points.map(endoMul),
        },
        doubles: pre.doubles && {
          step: pre.doubles.step,
          points: pre.doubles.points.map(endoMul),
        },
      };
    }
    return beta;
  };

  Point.prototype.toJSON = function toJSON() {
    if (!this.precomputed)
      return [this.x, this.y];

    return [this.x, this.y, this.precomputed && {
      doubles: this.precomputed.doubles && {
        step: this.precomputed.doubles.step,
        points: this.precomputed.doubles.points.slice(1),
      },
      naf: this.precomputed.naf && {
        wnd: this.precomputed.naf.wnd,
        points: this.precomputed.naf.points.slice(1),
      },
    }];
  };

  Point.fromJSON = function fromJSON(curve, obj, red) {
    if (typeof obj === 'string')
      obj = JSON.parse(obj);
    var res = curve.point(obj[0], obj[1], red);
    if (!obj[2])
      return res;

    function obj2point(obj) {
      return curve.point(obj[0], obj[1], red);
    }

    var pre = obj[2];
    res.precomputed = {
      beta: null,
      doubles: pre.doubles && {
        step: pre.doubles.step,
        points: [res].concat(pre.doubles.points.map(obj2point)),
      },
      naf: pre.naf && {
        wnd: pre.naf.wnd,
        points: [res].concat(pre.naf.points.map(obj2point)),
      },
    };
    return res;
  };

  Point.prototype.inspect = function inspect() {
    if (this.isInfinity())
      return '<EC Point Infinity>';
    return '<EC Point x: ' + this.x.fromRed().toString(16, 2) +
      ' y: ' + this.y.fromRed().toString(16, 2) + '>';
  };

  Point.prototype.isInfinity = function isInfinity() {
    return this.inf;
  };

  Point.prototype.add = function add(p) {
    // O + P = P
    if (this.inf)
      return p;

    // P + O = P
    if (p.inf)
      return this;

    // P + P = 2P
    if (this.eq(p))
      return this.dbl();

    // P + (-P) = O
    if (this.neg().eq(p))
      return this.curve.point(null, null);

    // P + Q = O
    if (this.x.cmp(p.x) === 0)
      return this.curve.point(null, null);

    var c = this.y.redSub(p.y);
    if (c.cmpn(0) !== 0)
      c = c.redMul(this.x.redSub(p.x).redInvm());
    var nx = c.redSqr().redISub(this.x).redISub(p.x);
    var ny = c.redMul(this.x.redSub(nx)).redISub(this.y);
    return this.curve.point(nx, ny);
  };

  Point.prototype.dbl = function dbl() {
    if (this.inf)
      return this;

    // 2P = O
    var ys1 = this.y.redAdd(this.y);
    if (ys1.cmpn(0) === 0)
      return this.curve.point(null, null);

    var a = this.curve.a;

    var x2 = this.x.redSqr();
    var dyinv = ys1.redInvm();
    var c = x2.redAdd(x2).redIAdd(x2).redIAdd(a).redMul(dyinv);

    var nx = c.redSqr().redISub(this.x.redAdd(this.x));
    var ny = c.redMul(this.x.redSub(nx)).redISub(this.y);
    return this.curve.point(nx, ny);
  };

  Point.prototype.getX = function getX() {
    return this.x.fromRed();
  };

  Point.prototype.getY = function getY() {
    return this.y.fromRed();
  };

  Point.prototype.mul = function mul(k) {
    k = new BN(k, 16);
    if (this.isInfinity())
      return this;
    else if (this._hasDoubles(k))
      return this.curve._fixedNafMul(this, k);
    else if (this.curve.endo)
      return this.curve._endoWnafMulAdd([this], [k]);
    else
      return this.curve._wnafMul(this, k);
  };

  Point.prototype.mulAdd = function mulAdd(k1, p2, k2) {
    var points = [this, p2];
    var coeffs = [k1, k2];
    if (this.curve.endo)
      return this.curve._endoWnafMulAdd(points, coeffs);
    else
      return this.curve._wnafMulAdd(1, points, coeffs, 2);
  };

  Point.prototype.jmulAdd = function jmulAdd(k1, p2, k2) {
    var points = [this, p2];
    var coeffs = [k1, k2];
    if (this.curve.endo)
      return this.curve._endoWnafMulAdd(points, coeffs, true);
    else
      return this.curve._wnafMulAdd(1, points, coeffs, 2, true);
  };

  Point.prototype.eq = function eq(p) {
    return this === p ||
      this.inf === p.inf &&
      (this.inf || this.x.cmp(p.x) === 0 && this.y.cmp(p.y) === 0);
  };

  Point.prototype.neg = function neg(_precompute) {
    if (this.inf)
      return this;

    var res = this.curve.point(this.x, this.y.redNeg());
    if (_precompute && this.precomputed) {
      var pre = this.precomputed;
      var negate = function(p) {
        return p.neg();
      };
      res.precomputed = {
        naf: pre.naf && {
          wnd: pre.naf.wnd,
          points: pre.naf.points.map(negate),
        },
        doubles: pre.doubles && {
          step: pre.doubles.step,
          points: pre.doubles.points.map(negate),
        },
      };
    }
    return res;
  };

  Point.prototype.toJ = function toJ() {
    if (this.inf)
      return this.curve.jpoint(null, null, null);

    var res = this.curve.jpoint(this.x, this.y, this.curve.one);
    return res;
  };

  function JPoint(curve, x, y, z) {
    Base.BasePoint.call(this, curve, 'jacobian');
    if (x === null && y === null && z === null) {
      this.x = this.curve.one;
      this.y = this.curve.one;
      this.z = new BN(0);
    } else {
      this.x = new BN(x, 16);
      this.y = new BN(y, 16);
      this.z = new BN(z, 16);
    }
    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);
    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);
    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);

    this.zOne = this.z === this.curve.one;
  }
  inherits(JPoint, Base.BasePoint);

  ShortCurve.prototype.jpoint = function jpoint(x, y, z) {
    return new JPoint(this, x, y, z);
  };

  JPoint.prototype.toP = function toP() {
    if (this.isInfinity())
      return this.curve.point(null, null);

    var zinv = this.z.redInvm();
    var zinv2 = zinv.redSqr();
    var ax = this.x.redMul(zinv2);
    var ay = this.y.redMul(zinv2).redMul(zinv);

    return this.curve.point(ax, ay);
  };

  JPoint.prototype.neg = function neg() {
    return this.curve.jpoint(this.x, this.y.redNeg(), this.z);
  };

  JPoint.prototype.add = function add(p) {
    // O + P = P
    if (this.isInfinity())
      return p;

    // P + O = P
    if (p.isInfinity())
      return this;

    // 12M + 4S + 7A
    var pz2 = p.z.redSqr();
    var z2 = this.z.redSqr();
    var u1 = this.x.redMul(pz2);
    var u2 = p.x.redMul(z2);
    var s1 = this.y.redMul(pz2.redMul(p.z));
    var s2 = p.y.redMul(z2.redMul(this.z));

    var h = u1.redSub(u2);
    var r = s1.redSub(s2);
    if (h.cmpn(0) === 0) {
      if (r.cmpn(0) !== 0)
        return this.curve.jpoint(null, null, null);
      else
        return this.dbl();
    }

    var h2 = h.redSqr();
    var h3 = h2.redMul(h);
    var v = u1.redMul(h2);

    var nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v);
    var ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3));
    var nz = this.z.redMul(p.z).redMul(h);

    return this.curve.jpoint(nx, ny, nz);
  };

  JPoint.prototype.mixedAdd = function mixedAdd(p) {
    // O + P = P
    if (this.isInfinity())
      return p.toJ();

    // P + O = P
    if (p.isInfinity())
      return this;

    // 8M + 3S + 7A
    var z2 = this.z.redSqr();
    var u1 = this.x;
    var u2 = p.x.redMul(z2);
    var s1 = this.y;
    var s2 = p.y.redMul(z2).redMul(this.z);

    var h = u1.redSub(u2);
    var r = s1.redSub(s2);
    if (h.cmpn(0) === 0) {
      if (r.cmpn(0) !== 0)
        return this.curve.jpoint(null, null, null);
      else
        return this.dbl();
    }

    var h2 = h.redSqr();
    var h3 = h2.redMul(h);
    var v = u1.redMul(h2);

    var nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v);
    var ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3));
    var nz = this.z.redMul(h);

    return this.curve.jpoint(nx, ny, nz);
  };

  JPoint.prototype.dblp = function dblp(pow) {
    if (pow === 0)
      return this;
    if (this.isInfinity())
      return this;
    if (!pow)
      return this.dbl();

    var i;
    if (this.curve.zeroA || this.curve.threeA) {
      var r = this;
      for (i = 0; i < pow; i++)
        r = r.dbl();
      return r;
    }

    // 1M + 2S + 1A + N * (4S + 5M + 8A)
    // N = 1 => 6M + 6S + 9A
    var a = this.curve.a;
    var tinv = this.curve.tinv;

    var jx = this.x;
    var jy = this.y;
    var jz = this.z;
    var jz4 = jz.redSqr().redSqr();

    // Reuse results
    var jyd = jy.redAdd(jy);
    for (i = 0; i < pow; i++) {
      var jx2 = jx.redSqr();
      var jyd2 = jyd.redSqr();
      var jyd4 = jyd2.redSqr();
      var c = jx2.redAdd(jx2).redIAdd(jx2).redIAdd(a.redMul(jz4));

      var t1 = jx.redMul(jyd2);
      var nx = c.redSqr().redISub(t1.redAdd(t1));
      var t2 = t1.redISub(nx);
      var dny = c.redMul(t2);
      dny = dny.redIAdd(dny).redISub(jyd4);
      var nz = jyd.redMul(jz);
      if (i + 1 < pow)
        jz4 = jz4.redMul(jyd4);

      jx = nx;
      jz = nz;
      jyd = dny;
    }

    return this.curve.jpoint(jx, jyd.redMul(tinv), jz);
  };

  JPoint.prototype.dbl = function dbl() {
    if (this.isInfinity())
      return this;

    if (this.curve.zeroA)
      return this._zeroDbl();
    else if (this.curve.threeA)
      return this._threeDbl();
    else
      return this._dbl();
  };

  JPoint.prototype._zeroDbl = function _zeroDbl() {
    var nx;
    var ny;
    var nz;
    // Z = 1
    if (this.zOne) {
      // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
      //     #doubling-mdbl-2007-bl
      // 1M + 5S + 14A

      // XX = X1^2
      var xx = this.x.redSqr();
      // YY = Y1^2
      var yy = this.y.redSqr();
      // YYYY = YY^2
      var yyyy = yy.redSqr();
      // S = 2 * ((X1 + YY)^2 - XX - YYYY)
      var s = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
      s = s.redIAdd(s);
      // M = 3 * XX + a; a = 0
      var m = xx.redAdd(xx).redIAdd(xx);
      // T = M ^ 2 - 2*S
      var t = m.redSqr().redISub(s).redISub(s);

      // 8 * YYYY
      var yyyy8 = yyyy.redIAdd(yyyy);
      yyyy8 = yyyy8.redIAdd(yyyy8);
      yyyy8 = yyyy8.redIAdd(yyyy8);

      // X3 = T
      nx = t;
      // Y3 = M * (S - T) - 8 * YYYY
      ny = m.redMul(s.redISub(t)).redISub(yyyy8);
      // Z3 = 2*Y1
      nz = this.y.redAdd(this.y);
    } else {
      // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
      //     #doubling-dbl-2009-l
      // 2M + 5S + 13A

      // A = X1^2
      var a = this.x.redSqr();
      // B = Y1^2
      var b = this.y.redSqr();
      // C = B^2
      var c = b.redSqr();
      // D = 2 * ((X1 + B)^2 - A - C)
      var d = this.x.redAdd(b).redSqr().redISub(a).redISub(c);
      d = d.redIAdd(d);
      // E = 3 * A
      var e = a.redAdd(a).redIAdd(a);
      // F = E^2
      var f = e.redSqr();

      // 8 * C
      var c8 = c.redIAdd(c);
      c8 = c8.redIAdd(c8);
      c8 = c8.redIAdd(c8);

      // X3 = F - 2 * D
      nx = f.redISub(d).redISub(d);
      // Y3 = E * (D - X3) - 8 * C
      ny = e.redMul(d.redISub(nx)).redISub(c8);
      // Z3 = 2 * Y1 * Z1
      nz = this.y.redMul(this.z);
      nz = nz.redIAdd(nz);
    }

    return this.curve.jpoint(nx, ny, nz);
  };

  JPoint.prototype._threeDbl = function _threeDbl() {
    var nx;
    var ny;
    var nz;
    // Z = 1
    if (this.zOne) {
      // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
      //     #doubling-mdbl-2007-bl
      // 1M + 5S + 15A

      // XX = X1^2
      var xx = this.x.redSqr();
      // YY = Y1^2
      var yy = this.y.redSqr();
      // YYYY = YY^2
      var yyyy = yy.redSqr();
      // S = 2 * ((X1 + YY)^2 - XX - YYYY)
      var s = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
      s = s.redIAdd(s);
      // M = 3 * XX + a
      var m = xx.redAdd(xx).redIAdd(xx).redIAdd(this.curve.a);
      // T = M^2 - 2 * S
      var t = m.redSqr().redISub(s).redISub(s);
      // X3 = T
      nx = t;
      // Y3 = M * (S - T) - 8 * YYYY
      var yyyy8 = yyyy.redIAdd(yyyy);
      yyyy8 = yyyy8.redIAdd(yyyy8);
      yyyy8 = yyyy8.redIAdd(yyyy8);
      ny = m.redMul(s.redISub(t)).redISub(yyyy8);
      // Z3 = 2 * Y1
      nz = this.y.redAdd(this.y);
    } else {
      // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
      // 3M + 5S

      // delta = Z1^2
      var delta = this.z.redSqr();
      // gamma = Y1^2
      var gamma = this.y.redSqr();
      // beta = X1 * gamma
      var beta = this.x.redMul(gamma);
      // alpha = 3 * (X1 - delta) * (X1 + delta)
      var alpha = this.x.redSub(delta).redMul(this.x.redAdd(delta));
      alpha = alpha.redAdd(alpha).redIAdd(alpha);
      // X3 = alpha^2 - 8 * beta
      var beta4 = beta.redIAdd(beta);
      beta4 = beta4.redIAdd(beta4);
      var beta8 = beta4.redAdd(beta4);
      nx = alpha.redSqr().redISub(beta8);
      // Z3 = (Y1 + Z1)^2 - gamma - delta
      nz = this.y.redAdd(this.z).redSqr().redISub(gamma).redISub(delta);
      // Y3 = alpha * (4 * beta - X3) - 8 * gamma^2
      var ggamma8 = gamma.redSqr();
      ggamma8 = ggamma8.redIAdd(ggamma8);
      ggamma8 = ggamma8.redIAdd(ggamma8);
      ggamma8 = ggamma8.redIAdd(ggamma8);
      ny = alpha.redMul(beta4.redISub(nx)).redISub(ggamma8);
    }

    return this.curve.jpoint(nx, ny, nz);
  };

  JPoint.prototype._dbl = function _dbl() {
    var a = this.curve.a;

    // 4M + 6S + 10A
    var jx = this.x;
    var jy = this.y;
    var jz = this.z;
    var jz4 = jz.redSqr().redSqr();

    var jx2 = jx.redSqr();
    var jy2 = jy.redSqr();

    var c = jx2.redAdd(jx2).redIAdd(jx2).redIAdd(a.redMul(jz4));

    var jxd4 = jx.redAdd(jx);
    jxd4 = jxd4.redIAdd(jxd4);
    var t1 = jxd4.redMul(jy2);
    var nx = c.redSqr().redISub(t1.redAdd(t1));
    var t2 = t1.redISub(nx);

    var jyd8 = jy2.redSqr();
    jyd8 = jyd8.redIAdd(jyd8);
    jyd8 = jyd8.redIAdd(jyd8);
    jyd8 = jyd8.redIAdd(jyd8);
    var ny = c.redMul(t2).redISub(jyd8);
    var nz = jy.redAdd(jy).redMul(jz);

    return this.curve.jpoint(nx, ny, nz);
  };

  JPoint.prototype.trpl = function trpl() {
    if (!this.curve.zeroA)
      return this.dbl().add(this);

    // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#tripling-tpl-2007-bl
    // 5M + 10S + ...

    // XX = X1^2
    var xx = this.x.redSqr();
    // YY = Y1^2
    var yy = this.y.redSqr();
    // ZZ = Z1^2
    var zz = this.z.redSqr();
    // YYYY = YY^2
    var yyyy = yy.redSqr();
    // M = 3 * XX + a * ZZ2; a = 0
    var m = xx.redAdd(xx).redIAdd(xx);
    // MM = M^2
    var mm = m.redSqr();
    // E = 6 * ((X1 + YY)^2 - XX - YYYY) - MM
    var e = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
    e = e.redIAdd(e);
    e = e.redAdd(e).redIAdd(e);
    e = e.redISub(mm);
    // EE = E^2
    var ee = e.redSqr();
    // T = 16*YYYY
    var t = yyyy.redIAdd(yyyy);
    t = t.redIAdd(t);
    t = t.redIAdd(t);
    t = t.redIAdd(t);
    // U = (M + E)^2 - MM - EE - T
    var u = m.redIAdd(e).redSqr().redISub(mm).redISub(ee).redISub(t);
    // X3 = 4 * (X1 * EE - 4 * YY * U)
    var yyu4 = yy.redMul(u);
    yyu4 = yyu4.redIAdd(yyu4);
    yyu4 = yyu4.redIAdd(yyu4);
    var nx = this.x.redMul(ee).redISub(yyu4);
    nx = nx.redIAdd(nx);
    nx = nx.redIAdd(nx);
    // Y3 = 8 * Y1 * (U * (T - U) - E * EE)
    var ny = this.y.redMul(u.redMul(t.redISub(u)).redISub(e.redMul(ee)));
    ny = ny.redIAdd(ny);
    ny = ny.redIAdd(ny);
    ny = ny.redIAdd(ny);
    // Z3 = (Z1 + E)^2 - ZZ - EE
    var nz = this.z.redAdd(e).redSqr().redISub(zz).redISub(ee);

    return this.curve.jpoint(nx, ny, nz);
  };

  JPoint.prototype.mul = function mul(k, kbase) {
    k = new BN(k, kbase);

    return this.curve._wnafMul(this, k);
  };

  JPoint.prototype.eq = function eq(p) {
    if (p.type === 'affine')
      return this.eq(p.toJ());

    if (this === p)
      return true;

    // x1 * z2^2 == x2 * z1^2
    var z2 = this.z.redSqr();
    var pz2 = p.z.redSqr();
    if (this.x.redMul(pz2).redISub(p.x.redMul(z2)).cmpn(0) !== 0)
      return false;

    // y1 * z2^3 == y2 * z1^3
    var z3 = z2.redMul(this.z);
    var pz3 = pz2.redMul(p.z);
    return this.y.redMul(pz3).redISub(p.y.redMul(z3)).cmpn(0) === 0;
  };

  JPoint.prototype.eqXToP = function eqXToP(x) {
    var zs = this.z.redSqr();
    var rx = x.toRed(this.curve.red).redMul(zs);
    if (this.x.cmp(rx) === 0)
      return true;

    var xc = x.clone();
    var t = this.curve.redN.redMul(zs);
    for (; ;) {
      xc.iadd(this.curve.n);
      if (xc.cmp(this.curve.p) >= 0)
        return false;

      rx.redIAdd(t);
      if (this.x.cmp(rx) === 0)
        return true;
    }
  };

  JPoint.prototype.inspect = function inspect() {
    if (this.isInfinity())
      return '<EC JPoint Infinity>';
    return '<EC JPoint x: ' + this.x.toString(16, 2) +
      ' y: ' + this.y.toString(16, 2) +
      ' z: ' + this.z.toString(16, 2) + '>';
  };

  JPoint.prototype.isInfinity = function isInfinity() {
    // XXX This code assumes that zero is always zero in red
    return this.z.cmpn(0) === 0;
  }

  return ShortCurve;
}

curve.short = theShort();



function MontCurve(conf) {
  Base.call(this, 'mont', conf);

  this.a = new BN(conf.a, 16).toRed(this.red);
  this.b = new BN(conf.b, 16).toRed(this.red);
  this.i4 = new BN(4).toRed(this.red).redInvm();
  this.two = new BN(2).toRed(this.red);
  this.a24 = this.i4.redMul(this.a.redAdd(this.two));
}
inherits(MontCurve, Base);
curve.mount = MontCurve;

MontCurve.prototype.validate = function validate(point) {
  var x = point.normalize().x;
  var x2 = x.redSqr();
  var rhs = x2.redMul(x).redAdd(x2.redMul(this.a)).redAdd(x);
  var y = rhs.redSqrt();

  return y.redSqr().cmp(rhs) === 0;
};

function Point(curve, x, z) {
  Base.BasePoint.call(this, curve, 'projective');
  if (x === null && z === null) {
    this.x = this.curve.one;
    this.z = this.curve.zero;
  } else {
    this.x = new BN(x, 16);
    this.z = new BN(z, 16);
    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);
    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);
  }
}
inherits(Point, Base.BasePoint);

MontCurve.prototype.decodePoint = function decodePoint(bytes, enc) {
  return this.point(utils.toArray(bytes, enc), 1);
};

MontCurve.prototype.point = function point(x, z) {
  return new Point(this, x, z);
};

MontCurve.prototype.pointFromJSON = function pointFromJSON(obj) {
  return Point.fromJSON(this, obj);
};

Point.prototype.precompute = function precompute() {
  // No-op
};

Point.prototype._encode = function _encode() {
  return this.getX().toArray('be', this.curve.p.byteLength());
};

Point.fromJSON = function fromJSON(curve, obj) {
  return new Point(curve, obj[0], obj[1] || curve.one);
};

Point.prototype.inspect = function inspect() {
  if (this.isInfinity())
    return '<EC Point Infinity>';
  return '<EC Point x: ' + this.x.fromRed().toString(16, 2) +
    ' z: ' + this.z.fromRed().toString(16, 2) + '>';
};

Point.prototype.isInfinity = function isInfinity() {
  // XXX This code assumes that zero is always zero in red
  return this.z.cmpn(0) === 0;
};

Point.prototype.dbl = function dbl() {
  // http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-dbl-1987-m-3
  // 2M + 2S + 4A

  // A = X1 + Z1
  var a = this.x.redAdd(this.z);
  // AA = A^2
  var aa = a.redSqr();
  // B = X1 - Z1
  var b = this.x.redSub(this.z);
  // BB = B^2
  var bb = b.redSqr();
  // C = AA - BB
  var c = aa.redSub(bb);
  // X3 = AA * BB
  var nx = aa.redMul(bb);
  // Z3 = C * (BB + A24 * C)
  var nz = c.redMul(bb.redAdd(this.curve.a24.redMul(c)));
  return this.curve.point(nx, nz);
};

Point.prototype.add = function add() {
  throw new Error('Not supported on Montgomery curve');
};

Point.prototype.diffAdd = function diffAdd(p, diff) {
  // http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#diffadd-dadd-1987-m-3
  // 4M + 2S + 6A

  // A = X2 + Z2
  var a = this.x.redAdd(this.z);
  // B = X2 - Z2
  var b = this.x.redSub(this.z);
  // C = X3 + Z3
  var c = p.x.redAdd(p.z);
  // D = X3 - Z3
  var d = p.x.redSub(p.z);
  // DA = D * A
  var da = d.redMul(a);
  // CB = C * B
  var cb = c.redMul(b);
  // X5 = Z1 * (DA + CB)^2
  var nx = diff.z.redMul(da.redAdd(cb).redSqr());
  // Z5 = X1 * (DA - CB)^2
  var nz = diff.x.redMul(da.redISub(cb).redSqr());
  return this.curve.point(nx, nz);
};

Point.prototype.mul = function mul(k) {
  var t = k.clone();
  var a = this; // (N / 2) * Q + Q
  var b = this.curve.point(null, null); // (N / 2) * Q
  var c = this; // Q

  for (var bits = []; t.cmpn(0) !== 0; t.iushrn(1))
    bits.push(t.andln(1));

  for (var i = bits.length - 1; i >= 0; i--) {
    if (bits[i] === 0) {
      // N * Q + Q = ((N / 2) * Q + Q)) + (N / 2) * Q
      a = a.diffAdd(b, c);
      // N * Q = 2 * ((N / 2) * Q + Q))
      b = b.dbl();
    } else {
      // N * Q = ((N / 2) * Q + Q) + ((N / 2) * Q)
      b = a.diffAdd(b, c);
      // N * Q + Q = 2 * ((N / 2) * Q + Q)
      a = a.dbl();
    }
  }
  return b;
};

Point.prototype.mulAdd = function mulAdd() {
  throw new Error('Not supported on Montgomery curve');
};

Point.prototype.jumlAdd = function jumlAdd() {
  throw new Error('Not supported on Montgomery curve');
};

Point.prototype.eq = function eq(other) {
  return this.getX().cmp(other.getX()) === 0;
};

Point.prototype.normalize = function normalize() {
  this.x = this.x.redMul(this.z.redInvm());
  this.z = this.curve.one;
  return this;
};

Point.prototype.getX = function getX() {
  // Normalize coordinates
  this.normalize();

  return this.x.fromRed();
};

function EdwardsCurve(conf) {
  // NOTE: Important as we are creating point in Base.call()
  this.twisted = (conf.a | 0) !== 1;
  this.mOneA = this.twisted && (conf.a | 0) === -1;
  this.extended = this.mOneA;

  Base.call(this, 'edwards', conf);

  this.a = new BN(conf.a, 16).umod(this.red.m);
  this.a = this.a.toRed(this.red);
  this.c = new BN(conf.c, 16).toRed(this.red);
  this.c2 = this.c.redSqr();
  this.d = new BN(conf.d, 16).toRed(this.red);
  this.dd = this.d.redAdd(this.d);

  minAssert(!this.twisted || this.c.fromRed().cmpn(1) === 0);
  this.oneC = (conf.c | 0) === 1;
}
inherits(EdwardsCurve, Base);
curve.edwards = EdwardsCurve;

EdwardsCurve.prototype._mulA = function _mulA(num) {
  if (this.mOneA)
    return num.redNeg();
  else
    return this.a.redMul(num);
};

EdwardsCurve.prototype._mulC = function _mulC(num) {
  if (this.oneC)
    return num;
  else
    return this.c.redMul(num);
};

// Just for compatibility with Short curve
EdwardsCurve.prototype.jpoint = function jpoint(x, y, z, t) {
  return this.point(x, y, z, t);
};

EdwardsCurve.prototype.pointFromX = function pointFromX(x, odd) {
  x = new BN(x, 16);
  if (!x.red)
    x = x.toRed(this.red);

  var x2 = x.redSqr();
  var rhs = this.c2.redSub(this.a.redMul(x2));
  var lhs = this.one.redSub(this.c2.redMul(this.d).redMul(x2));

  var y2 = rhs.redMul(lhs.redInvm());
  var y = y2.redSqrt();
  if (y.redSqr().redSub(y2).cmp(this.zero) !== 0)
    throw new Error('invalid point');

  var isOdd = y.fromRed().isOdd();
  if (odd && !isOdd || !odd && isOdd)
    y = y.redNeg();

  return this.point(x, y);
};

EdwardsCurve.prototype.pointFromY = function pointFromY(y, odd) {
  y = new BN(y, 16);
  if (!y.red)
    y = y.toRed(this.red);

  // x^2 = (y^2 - c^2) / (c^2 d y^2 - a)
  var y2 = y.redSqr();
  var lhs = y2.redSub(this.c2);
  var rhs = y2.redMul(this.d).redMul(this.c2).redSub(this.a);
  var x2 = lhs.redMul(rhs.redInvm());

  if (x2.cmp(this.zero) === 0) {
    if (odd)
      throw new Error('invalid point');
    else
      return this.point(this.zero, y);
  }

  var x = x2.redSqrt();
  if (x.redSqr().redSub(x2).cmp(this.zero) !== 0)
    throw new Error('invalid point');

  if (x.fromRed().isOdd() !== odd)
    x = x.redNeg();

  return this.point(x, y);
};

EdwardsCurve.prototype.validate = function validate(point) {
  if (point.isInfinity())
    return true;

  // Curve: A * X^2 + Y^2 = C^2 * (1 + D * X^2 * Y^2)
  point.normalize();

  var x2 = point.x.redSqr();
  var y2 = point.y.redSqr();
  var lhs = x2.redMul(this.a).redAdd(y2);
  var rhs = this.c2.redMul(this.one.redAdd(this.d.redMul(x2).redMul(y2)));

  return lhs.cmp(rhs) === 0;
};

function Point(curve, x, y, z, t) {
  Base2.BasePoint.call(this, curve, 'projective');
  if (x === null && y === null && z === null) {
    this.x = this.curve.zero;
    this.y = this.curve.one;
    this.z = this.curve.one;
    this.t = this.curve.zero;
    this.zOne = true;
  } else {
    this.x = new BN(x, 16);
    this.y = new BN(y, 16);
    this.z = z ? new BN(z, 16) : this.curve.one;
    this.t = t && new BN(t, 16);
    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);
    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);
    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);
    if (this.t && !this.t.red)
      this.t = this.t.toRed(this.curve.red);
    this.zOne = this.z === this.curve.one;

    // Use extended coordinates
    if (this.curve.extended && !this.t) {
      this.t = this.x.redMul(this.y);
      if (!this.zOne)
        this.t = this.t.redMul(this.z.redInvm());
    }
  }
}
inherits(Point, Base.BasePoint);

EdwardsCurve.prototype.pointFromJSON = function pointFromJSON(obj) {
  return Point.fromJSON(this, obj);
};

EdwardsCurve.prototype.point = function point(x, y, z, t) {
  return new Point(this, x, y, z, t);
};

Point.fromJSON = function fromJSON(curve, obj) {
  return new Point(curve, obj[0], obj[1], obj[2]);
};

Point.prototype.inspect = function inspect() {
  if (this.isInfinity())
    return '<EC Point Infinity>';
  return '<EC Point x: ' + this.x.fromRed().toString(16, 2) +
    ' y: ' + this.y.fromRed().toString(16, 2) +
    ' z: ' + this.z.fromRed().toString(16, 2) + '>';
};

Point.prototype.isInfinity = function isInfinity() {
  // XXX This code assumes that zero is always zero in red
  return this.x.cmpn(0) === 0 &&
    (this.y.cmp(this.z) === 0 ||
      (this.zOne && this.y.cmp(this.curve.c) === 0));
};

Point.prototype._extDbl = function _extDbl() {
  // hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
  //     #doubling-dbl-2008-hwcd
  // 4M + 4S

  // A = X1^2
  var a = this.x.redSqr();
  // B = Y1^2
  var b = this.y.redSqr();
  // C = 2 * Z1^2
  var c = this.z.redSqr();
  c = c.redIAdd(c);
  // D = a * A
  var d = this.curve._mulA(a);
  // E = (X1 + Y1)^2 - A - B
  var e = this.x.redAdd(this.y).redSqr().redISub(a).redISub(b);
  // G = D + B
  var g = d.redAdd(b);
  // F = G - C
  var f = g.redSub(c);
  // H = D - B
  var h = d.redSub(b);
  // X3 = E * F
  var nx = e.redMul(f);
  // Y3 = G * H
  var ny = g.redMul(h);
  // T3 = E * H
  var nt = e.redMul(h);
  // Z3 = F * G
  var nz = f.redMul(g);
  return this.curve.point(nx, ny, nz, nt);
};

Point.prototype._projDbl = function _projDbl() {
  // hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
  //     #doubling-dbl-2008-bbjlp
  //     #doubling-dbl-2007-bl
  // and others
  // Generally 3M + 4S or 2M + 4S

  // B = (X1 + Y1)^2
  var b = this.x.redAdd(this.y).redSqr();
  // C = X1^2
  var c = this.x.redSqr();
  // D = Y1^2
  var d = this.y.redSqr();

  var nx;
  var ny;
  var nz;
  var e;
  var h;
  var j;
  if (this.curve.twisted) {
    // E = a * C
    e = this.curve._mulA(c);
    // F = E + D
    var f = e.redAdd(d);
    if (this.zOne) {
      // X3 = (B - C - D) * (F - 2)
      nx = b.redSub(c).redSub(d).redMul(f.redSub(this.curve.two));
      // Y3 = F * (E - D)
      ny = f.redMul(e.redSub(d));
      // Z3 = F^2 - 2 * F
      nz = f.redSqr().redSub(f).redSub(f);
    } else {
      // H = Z1^2
      h = this.z.redSqr();
      // J = F - 2 * H
      j = f.redSub(h).redISub(h);
      // X3 = (B-C-D)*J
      nx = b.redSub(c).redISub(d).redMul(j);
      // Y3 = F * (E - D)
      ny = f.redMul(e.redSub(d));
      // Z3 = F * J
      nz = f.redMul(j);
    }
  } else {
    // E = C + D
    e = c.redAdd(d);
    // H = (c * Z1)^2
    h = this.curve._mulC(this.z).redSqr();
    // J = E - 2 * H
    j = e.redSub(h).redSub(h);
    // X3 = c * (B - E) * J
    nx = this.curve._mulC(b.redISub(e)).redMul(j);
    // Y3 = c * E * (C - D)
    ny = this.curve._mulC(e).redMul(c.redISub(d));
    // Z3 = E * J
    nz = e.redMul(j);
  }
  return this.curve.point(nx, ny, nz);
};

Point.prototype.dbl = function dbl() {
  if (this.isInfinity())
    return this;

  // Double in extended coordinates
  if (this.curve.extended)
    return this._extDbl();
  else
    return this._projDbl();
};

Point.prototype._extAdd = function _extAdd(p) {
  // hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
  //     #addition-add-2008-hwcd-3
  // 8M

  // A = (Y1 - X1) * (Y2 - X2)
  var a = this.y.redSub(this.x).redMul(p.y.redSub(p.x));
  // B = (Y1 + X1) * (Y2 + X2)
  var b = this.y.redAdd(this.x).redMul(p.y.redAdd(p.x));
  // C = T1 * k * T2
  var c = this.t.redMul(this.curve.dd).redMul(p.t);
  // D = Z1 * 2 * Z2
  var d = this.z.redMul(p.z.redAdd(p.z));
  // E = B - A
  var e = b.redSub(a);
  // F = D - C
  var f = d.redSub(c);
  // G = D + C
  var g = d.redAdd(c);
  // H = B + A
  var h = b.redAdd(a);
  // X3 = E * F
  var nx = e.redMul(f);
  // Y3 = G * H
  var ny = g.redMul(h);
  // T3 = E * H
  var nt = e.redMul(h);
  // Z3 = F * G
  var nz = f.redMul(g);
  return this.curve.point(nx, ny, nz, nt);
};

Point.prototype._projAdd = function _projAdd(p) {
  // hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
  //     #addition-add-2008-bbjlp
  //     #addition-add-2007-bl
  // 10M + 1S

  // A = Z1 * Z2
  var a = this.z.redMul(p.z);
  // B = A^2
  var b = a.redSqr();
  // C = X1 * X2
  var c = this.x.redMul(p.x);
  // D = Y1 * Y2
  var d = this.y.redMul(p.y);
  // E = d * C * D
  var e = this.curve.d.redMul(c).redMul(d);
  // F = B - E
  var f = b.redSub(e);
  // G = B + E
  var g = b.redAdd(e);
  // X3 = A * F * ((X1 + Y1) * (X2 + Y2) - C - D)
  var tmp = this.x.redAdd(this.y).redMul(p.x.redAdd(p.y)).redISub(c).redISub(d);
  var nx = a.redMul(f).redMul(tmp);
  var ny;
  var nz;
  if (this.curve.twisted) {
    // Y3 = A * G * (D - a * C)
    ny = a.redMul(g).redMul(d.redSub(this.curve._mulA(c)));
    // Z3 = F * G
    nz = f.redMul(g);
  } else {
    // Y3 = A * G * (D - C)
    ny = a.redMul(g).redMul(d.redSub(c));
    // Z3 = c * F * G
    nz = this.curve._mulC(f).redMul(g);
  }
  return this.curve.point(nx, ny, nz);
};

Point.prototype.add = function add(p) {
  if (this.isInfinity())
    return p;
  if (p.isInfinity())
    return this;

  if (this.curve.extended)
    return this._extAdd(p);
  else
    return this._projAdd(p);
};

Point.prototype.mul = function mul(k) {
  if (this._hasDoubles(k))
    return this.curve._fixedNafMul(this, k);
  else
    return this.curve._wnafMul(this, k);
};

Point.prototype.mulAdd = function mulAdd(k1, p, k2) {
  return this.curve._wnafMulAdd(1, [this, p], [k1, k2], 2, false);
};

Point.prototype.jmulAdd = function jmulAdd(k1, p, k2) {
  return this.curve._wnafMulAdd(1, [this, p], [k1, k2], 2, true);
};

Point.prototype.normalize = function normalize() {
  if (this.zOne)
    return this;

  // Normalize coordinates
  var zi = this.z.redInvm();
  this.x = this.x.redMul(zi);
  this.y = this.y.redMul(zi);
  if (this.t)
    this.t = this.t.redMul(zi);
  this.z = this.curve.one;
  this.zOne = true;
  return this;
};

Point.prototype.neg = function neg() {
  return this.curve.point(this.x.redNeg(),
    this.y,
    this.z,
    this.t && this.t.redNeg());
};

Point.prototype.getX = function getX() {
  this.normalize();
  return this.x.fromRed();
};

Point.prototype.getY = function getY() {
  this.normalize();
  return this.y.fromRed();
};

Point.prototype.eq = function eq(other) {
  return this === other ||
    this.getX().cmp(other.getX()) === 0 &&
    this.getY().cmp(other.getY()) === 0;
};

Point.prototype.eqXToP = function eqXToP(x) {
  var rx = x.toRed(this.curve.red).redMul(this.z);
  if (this.x.cmp(rx) === 0)
    return true;

  var xc = x.clone();
  var t = this.curve.redN.redMul(this.z);
  for (; ;) {
    xc.iadd(this.curve.n);
    if (xc.cmp(this.curve.p) >= 0)
      return false;

    rx.redIAdd(t);
    if (this.x.cmp(rx) === 0)
      return true;
  }
};

// Compatibility with BaseCurve
Point.prototype.toP = Point.prototype.normalize;
Point.prototype.mixedAdd = Point.prototype.add;

var curves = exports;



function PresetCurve(options) {
  if (options.type === 'short')
    this.curve = new curve.short(options);
  else if (options.type === 'edwards')
    this.curve = new curve.edwards(options);
  else
    this.curve = new curve.mont(options);
  this.g = this.curve.g;
  this.n = this.curve.n;
  this.hash = options.hash;

  minAssert(this.g.validate(), 'Invalid curve');
  minAssert(this.g.mul(this.n).isInfinity(), 'Invalid curve, G*N != O');
}
curves.PresetCurve = PresetCurve;

function defineCurve(name, options) {
  Object.defineProperty(curves, name, {
    configurable: true,
    enumerable: true,
    get: function() {
      var curve = new PresetCurve(options);
      Object.defineProperty(curves, name, {
        configurable: true,
        enumerable: true,
        value: curve,
      });
      return curve;
    },
  });
}

defineCurve('p192', {
  type: 'short',
  prime: 'p192',
  p: 'ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff',
  a: 'ffffffff ffffffff ffffffff fffffffe ffffffff fffffffc',
  b: '64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1',
  n: 'ffffffff ffffffff ffffffff 99def836 146bc9b1 b4d22831',
  hash: sha256,
  gRed: false,
  g: [
    '188da80e b03090f6 7cbf20eb 43a18800 f4ff0afd 82ff1012',
    '07192b95 ffc8da78 631011ed 6b24cdd5 73f977a1 1e794811',
  ],
});

defineCurve('p224', {
  type: 'short',
  prime: 'p224',
  p: 'ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001',
  a: 'ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff fffffffe',
  b: 'b4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4',
  n: 'ffffffff ffffffff ffffffff ffff16a2 e0b8f03e 13dd2945 5c5c2a3d',
  hash: sha256,
  gRed: false,
  g: [
    'b70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6 115c1d21',
    'bd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199 85007e34',
  ],
});

defineCurve('p256', {
  type: 'short',
  prime: null,
  p: 'ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff',
  a: 'ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffc',
  b: '5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b',
  n: 'ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551',
  hash: sha256,
  gRed: false,
  g: [
    '6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296',
    '4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5',
  ],
});

defineCurve('p384', {
  type: 'short',
  prime: null,
  p: 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
    'fffffffe ffffffff 00000000 00000000 ffffffff',
  a: 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
    'fffffffe ffffffff 00000000 00000000 fffffffc',
  b: 'b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 0314088f ' +
    '5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef',
  n: 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff c7634d81 ' +
    'f4372ddf 581a0db2 48b0a77a ecec196a ccc52973',
  hash: SHA384,
  gRed: false,
  g: [
    'aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 ' +
    '5502f25d bf55296c 3a545e38 72760ab7',
    '3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 ' +
    '0a60b1ce 1d7e819d 7a431d7c 90ea0e5f',
  ],
});

defineCurve('p521', {
  type: 'short',
  prime: null,
  p: '000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
    'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
    'ffffffff ffffffff ffffffff ffffffff ffffffff',
  a: '000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
    'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
    'ffffffff ffffffff ffffffff ffffffff fffffffc',
  b: '00000051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b ' +
    '99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd ' +
    '3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00',
  n: '000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ' +
    'ffffffff ffffffff fffffffa 51868783 bf2f966b 7fcc0148 ' +
    'f709a5d0 3bb5c9b8 899c47ae bb6fb71e 91386409',
  hash: SHA512,
  gRed: false,
  g: [
    '000000c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139 ' +
    '053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127 ' +
    'a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66',
    '00000118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449 ' +
    '579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901 ' +
    '3fad0761 353c7086 a272c240 88be9476 9fd16650',
  ],
});

defineCurve('curve25519', {
  type: 'mont',
  prime: 'p25519',
  p: '7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed',
  a: '76d06',
  b: '1',
  n: '1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed',
  hash: sha256,
  gRed: false,
  g: [
    '9',
  ],
});

defineCurve('ed25519', {
  type: 'edwards',
  prime: 'p25519',
  p: '7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed',
  a: '-1',
  c: '1',
  // -121665 * (121666^(-1)) (mod P)
  d: '52036cee2b6ffe73 8cc740797779e898 00700a4d4141d8ab 75eb4dca135978a3',
  n: '1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed',
  hash: sha256,
  gRed: false,
  g: [
    '216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a',

    // 4/5
    '6666666666666666666666666666666666666666666666666666666666666658',
  ],
});

var pre;
try {
  pre = {
    doubles: {
      step: 4,
      points: [
        [
          'e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a',
          'f7e3507399e595929db99f34f57937101296891e44d23f0be1f32cce69616821',
        ],
        [
          '8282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508',
          '11f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf',
        ],
        [
          '175e159f728b865a72f99cc6c6fc846de0b93833fd2222ed73fce5b551e5b739',
          'd3506e0d9e3c79eba4ef97a51ff71f5eacb5955add24345c6efa6ffee9fed695',
        ],
        [
          '363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640',
          '4e273adfc732221953b445397f3363145b9a89008199ecb62003c7f3bee9de9',
        ],
        [
          '8b4b5f165df3c2be8c6244b5b745638843e4a781a15bcd1b69f79a55dffdf80c',
          '4aad0a6f68d308b4b3fbd7813ab0da04f9e336546162ee56b3eff0c65fd4fd36',
        ],
        [
          '723cbaa6e5db996d6bf771c00bd548c7b700dbffa6c0e77bcb6115925232fcda',
          '96e867b5595cc498a921137488824d6e2660a0653779494801dc069d9eb39f5f',
        ],
        [
          'eebfa4d493bebf98ba5feec812c2d3b50947961237a919839a533eca0e7dd7fa',
          '5d9a8ca3970ef0f269ee7edaf178089d9ae4cdc3a711f712ddfd4fdae1de8999',
        ],
        [
          '100f44da696e71672791d0a09b7bde459f1215a29b3c03bfefd7835b39a48db0',
          'cdd9e13192a00b772ec8f3300c090666b7ff4a18ff5195ac0fbd5cd62bc65a09',
        ],
        [
          'e1031be262c7ed1b1dc9227a4a04c017a77f8d4464f3b3852c8acde6e534fd2d',
          '9d7061928940405e6bb6a4176597535af292dd419e1ced79a44f18f29456a00d',
        ],
        [
          'feea6cae46d55b530ac2839f143bd7ec5cf8b266a41d6af52d5e688d9094696d',
          'e57c6b6c97dce1bab06e4e12bf3ecd5c981c8957cc41442d3155debf18090088',
        ],
        [
          'da67a91d91049cdcb367be4be6ffca3cfeed657d808583de33fa978bc1ec6cb1',
          '9bacaa35481642bc41f463f7ec9780e5dec7adc508f740a17e9ea8e27a68be1d',
        ],
        [
          '53904faa0b334cdda6e000935ef22151ec08d0f7bb11069f57545ccc1a37b7c0',
          '5bc087d0bc80106d88c9eccac20d3c1c13999981e14434699dcb096b022771c8',
        ],
        [
          '8e7bcd0bd35983a7719cca7764ca906779b53a043a9b8bcaeff959f43ad86047',
          '10b7770b2a3da4b3940310420ca9514579e88e2e47fd68b3ea10047e8460372a',
        ],
        [
          '385eed34c1cdff21e6d0818689b81bde71a7f4f18397e6690a841e1599c43862',
          '283bebc3e8ea23f56701de19e9ebf4576b304eec2086dc8cc0458fe5542e5453',
        ],
        [
          '6f9d9b803ecf191637c73a4413dfa180fddf84a5947fbc9c606ed86c3fac3a7',
          '7c80c68e603059ba69b8e2a30e45c4d47ea4dd2f5c281002d86890603a842160',
        ],
        [
          '3322d401243c4e2582a2147c104d6ecbf774d163db0f5e5313b7e0e742d0e6bd',
          '56e70797e9664ef5bfb019bc4ddaf9b72805f63ea2873af624f3a2e96c28b2a0',
        ],
        [
          '85672c7d2de0b7da2bd1770d89665868741b3f9af7643397721d74d28134ab83',
          '7c481b9b5b43b2eb6374049bfa62c2e5e77f17fcc5298f44c8e3094f790313a6',
        ],
        [
          '948bf809b1988a46b06c9f1919413b10f9226c60f668832ffd959af60c82a0a',
          '53a562856dcb6646dc6b74c5d1c3418c6d4dff08c97cd2bed4cb7f88d8c8e589',
        ],
        [
          '6260ce7f461801c34f067ce0f02873a8f1b0e44dfc69752accecd819f38fd8e8',
          'bc2da82b6fa5b571a7f09049776a1ef7ecd292238051c198c1a84e95b2b4ae17',
        ],
        [
          'e5037de0afc1d8d43d8348414bbf4103043ec8f575bfdc432953cc8d2037fa2d',
          '4571534baa94d3b5f9f98d09fb990bddbd5f5b03ec481f10e0e5dc841d755bda',
        ],
        [
          'e06372b0f4a207adf5ea905e8f1771b4e7e8dbd1c6a6c5b725866a0ae4fce725',
          '7a908974bce18cfe12a27bb2ad5a488cd7484a7787104870b27034f94eee31dd',
        ],
        [
          '213c7a715cd5d45358d0bbf9dc0ce02204b10bdde2a3f58540ad6908d0559754',
          '4b6dad0b5ae462507013ad06245ba190bb4850f5f36a7eeddff2c27534b458f2',
        ],
        [
          '4e7c272a7af4b34e8dbb9352a5419a87e2838c70adc62cddf0cc3a3b08fbd53c',
          '17749c766c9d0b18e16fd09f6def681b530b9614bff7dd33e0b3941817dcaae6',
        ],
        [
          'fea74e3dbe778b1b10f238ad61686aa5c76e3db2be43057632427e2840fb27b6',
          '6e0568db9b0b13297cf674deccb6af93126b596b973f7b77701d3db7f23cb96f',
        ],
        [
          '76e64113f677cf0e10a2570d599968d31544e179b760432952c02a4417bdde39',
          'c90ddf8dee4e95cf577066d70681f0d35e2a33d2b56d2032b4b1752d1901ac01',
        ],
        [
          'c738c56b03b2abe1e8281baa743f8f9a8f7cc643df26cbee3ab150242bcbb891',
          '893fb578951ad2537f718f2eacbfbbbb82314eef7880cfe917e735d9699a84c3',
        ],
        [
          'd895626548b65b81e264c7637c972877d1d72e5f3a925014372e9f6588f6c14b',
          'febfaa38f2bc7eae728ec60818c340eb03428d632bb067e179363ed75d7d991f',
        ],
        [
          'b8da94032a957518eb0f6433571e8761ceffc73693e84edd49150a564f676e03',
          '2804dfa44805a1e4d7c99cc9762808b092cc584d95ff3b511488e4e74efdf6e7',
        ],
        [
          'e80fea14441fb33a7d8adab9475d7fab2019effb5156a792f1a11778e3c0df5d',
          'eed1de7f638e00771e89768ca3ca94472d155e80af322ea9fcb4291b6ac9ec78',
        ],
        [
          'a301697bdfcd704313ba48e51d567543f2a182031efd6915ddc07bbcc4e16070',
          '7370f91cfb67e4f5081809fa25d40f9b1735dbf7c0a11a130c0d1a041e177ea1',
        ],
        [
          '90ad85b389d6b936463f9d0512678de208cc330b11307fffab7ac63e3fb04ed4',
          'e507a3620a38261affdcbd9427222b839aefabe1582894d991d4d48cb6ef150',
        ],
        [
          '8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da',
          '662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82',
        ],
        [
          'e4f3fb0176af85d65ff99ff9198c36091f48e86503681e3e6686fd5053231e11',
          '1e63633ad0ef4f1c1661a6d0ea02b7286cc7e74ec951d1c9822c38576feb73bc',
        ],
        [
          '8c00fa9b18ebf331eb961537a45a4266c7034f2f0d4e1d0716fb6eae20eae29e',
          'efa47267fea521a1a9dc343a3736c974c2fadafa81e36c54e7d2a4c66702414b',
        ],
        [
          'e7a26ce69dd4829f3e10cec0a9e98ed3143d084f308b92c0997fddfc60cb3e41',
          '2a758e300fa7984b471b006a1aafbb18d0a6b2c0420e83e20e8a9421cf2cfd51',
        ],
        [
          'b6459e0ee3662ec8d23540c223bcbdc571cbcb967d79424f3cf29eb3de6b80ef',
          '67c876d06f3e06de1dadf16e5661db3c4b3ae6d48e35b2ff30bf0b61a71ba45',
        ],
        [
          'd68a80c8280bb840793234aa118f06231d6f1fc67e73c5a5deda0f5b496943e8',
          'db8ba9fff4b586d00c4b1f9177b0e28b5b0e7b8f7845295a294c84266b133120',
        ],
        [
          '324aed7df65c804252dc0270907a30b09612aeb973449cea4095980fc28d3d5d',
          '648a365774b61f2ff130c0c35aec1f4f19213b0c7e332843967224af96ab7c84',
        ],
        [
          '4df9c14919cde61f6d51dfdbe5fee5dceec4143ba8d1ca888e8bd373fd054c96',
          '35ec51092d8728050974c23a1d85d4b5d506cdc288490192ebac06cad10d5d',
        ],
        [
          '9c3919a84a474870faed8a9c1cc66021523489054d7f0308cbfc99c8ac1f98cd',
          'ddb84f0f4a4ddd57584f044bf260e641905326f76c64c8e6be7e5e03d4fc599d',
        ],
        [
          '6057170b1dd12fdf8de05f281d8e06bb91e1493a8b91d4cc5a21382120a959e5',
          '9a1af0b26a6a4807add9a2daf71df262465152bc3ee24c65e899be932385a2a8',
        ],
        [
          'a576df8e23a08411421439a4518da31880cef0fba7d4df12b1a6973eecb94266',
          '40a6bf20e76640b2c92b97afe58cd82c432e10a7f514d9f3ee8be11ae1b28ec8',
        ],
        [
          '7778a78c28dec3e30a05fe9629de8c38bb30d1f5cf9a3a208f763889be58ad71',
          '34626d9ab5a5b22ff7098e12f2ff580087b38411ff24ac563b513fc1fd9f43ac',
        ],
        [
          '928955ee637a84463729fd30e7afd2ed5f96274e5ad7e5cb09eda9c06d903ac',
          'c25621003d3f42a827b78a13093a95eeac3d26efa8a8d83fc5180e935bcd091f',
        ],
        [
          '85d0fef3ec6db109399064f3a0e3b2855645b4a907ad354527aae75163d82751',
          '1f03648413a38c0be29d496e582cf5663e8751e96877331582c237a24eb1f962',
        ],
        [
          'ff2b0dce97eece97c1c9b6041798b85dfdfb6d8882da20308f5404824526087e',
          '493d13fef524ba188af4c4dc54d07936c7b7ed6fb90e2ceb2c951e01f0c29907',
        ],
        [
          '827fbbe4b1e880ea9ed2b2e6301b212b57f1ee148cd6dd28780e5e2cf856e241',
          'c60f9c923c727b0b71bef2c67d1d12687ff7a63186903166d605b68baec293ec',
        ],
        [
          'eaa649f21f51bdbae7be4ae34ce6e5217a58fdce7f47f9aa7f3b58fa2120e2b3',
          'be3279ed5bbbb03ac69a80f89879aa5a01a6b965f13f7e59d47a5305ba5ad93d',
        ],
        [
          'e4a42d43c5cf169d9391df6decf42ee541b6d8f0c9a137401e23632dda34d24f',
          '4d9f92e716d1c73526fc99ccfb8ad34ce886eedfa8d8e4f13a7f7131deba9414',
        ],
        [
          '1ec80fef360cbdd954160fadab352b6b92b53576a88fea4947173b9d4300bf19',
          'aeefe93756b5340d2f3a4958a7abbf5e0146e77f6295a07b671cdc1cc107cefd',
        ],
        [
          '146a778c04670c2f91b00af4680dfa8bce3490717d58ba889ddb5928366642be',
          'b318e0ec3354028add669827f9d4b2870aaa971d2f7e5ed1d0b297483d83efd0',
        ],
        [
          'fa50c0f61d22e5f07e3acebb1aa07b128d0012209a28b9776d76a8793180eef9',
          '6b84c6922397eba9b72cd2872281a68a5e683293a57a213b38cd8d7d3f4f2811',
        ],
        [
          'da1d61d0ca721a11b1a5bf6b7d88e8421a288ab5d5bba5220e53d32b5f067ec2',
          '8157f55a7c99306c79c0766161c91e2966a73899d279b48a655fba0f1ad836f1',
        ],
        [
          'a8e282ff0c9706907215ff98e8fd416615311de0446f1e062a73b0610d064e13',
          '7f97355b8db81c09abfb7f3c5b2515888b679a3e50dd6bd6cef7c73111f4cc0c',
        ],
        [
          '174a53b9c9a285872d39e56e6913cab15d59b1fa512508c022f382de8319497c',
          'ccc9dc37abfc9c1657b4155f2c47f9e6646b3a1d8cb9854383da13ac079afa73',
        ],
        [
          '959396981943785c3d3e57edf5018cdbe039e730e4918b3d884fdff09475b7ba',
          '2e7e552888c331dd8ba0386a4b9cd6849c653f64c8709385e9b8abf87524f2fd',
        ],
        [
          'd2a63a50ae401e56d645a1153b109a8fcca0a43d561fba2dbb51340c9d82b151',
          'e82d86fb6443fcb7565aee58b2948220a70f750af484ca52d4142174dcf89405',
        ],
        [
          '64587e2335471eb890ee7896d7cfdc866bacbdbd3839317b3436f9b45617e073',
          'd99fcdd5bf6902e2ae96dd6447c299a185b90a39133aeab358299e5e9faf6589',
        ],
        [
          '8481bde0e4e4d885b3a546d3e549de042f0aa6cea250e7fd358d6c86dd45e458',
          '38ee7b8cba5404dd84a25bf39cecb2ca900a79c42b262e556d64b1b59779057e',
        ],
        [
          '13464a57a78102aa62b6979ae817f4637ffcfed3c4b1ce30bcd6303f6caf666b',
          '69be159004614580ef7e433453ccb0ca48f300a81d0942e13f495a907f6ecc27',
        ],
        [
          'bc4a9df5b713fe2e9aef430bcc1dc97a0cd9ccede2f28588cada3a0d2d83f366',
          'd3a81ca6e785c06383937adf4b798caa6e8a9fbfa547b16d758d666581f33c1',
        ],
        [
          '8c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa',
          '40a30463a3305193378fedf31f7cc0eb7ae784f0451cb9459e71dc73cbef9482',
        ],
        [
          '8ea9666139527a8c1dd94ce4f071fd23c8b350c5a4bb33748c4ba111faccae0',
          '620efabbc8ee2782e24e7c0cfb95c5d735b783be9cf0f8e955af34a30e62b945',
        ],
        [
          'dd3625faef5ba06074669716bbd3788d89bdde815959968092f76cc4eb9a9787',
          '7a188fa3520e30d461da2501045731ca941461982883395937f68d00c644a573',
        ],
        [
          'f710d79d9eb962297e4f6232b40e8f7feb2bc63814614d692c12de752408221e',
          'ea98e67232d3b3295d3b535532115ccac8612c721851617526ae47a9c77bfc82',
        ],
      ],
    },
    naf: {
      wnd: 7,
      points: [
        [
          'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
          '388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672',
        ],
        [
          '2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4',
          'd8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6',
        ],
        [
          '5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc',
          '6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da',
        ],
        [
          'acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe',
          'cc338921b0a7d9fd64380971763b61e9add888a4375f8e0f05cc262ac64f9c37',
        ],
        [
          '774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb',
          'd984a032eb6b5e190243dd56d7b7b365372db1e2dff9d6a8301d74c9c953c61b',
        ],
        [
          'f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8',
          'ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81',
        ],
        [
          'd7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e',
          '581e2872a86c72a683842ec228cc6defea40af2bd896d3a5c504dc9ff6a26b58',
        ],
        [
          'defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34',
          '4211ab0694635168e997b0ead2a93daeced1f4a04a95c0f6cfb199f69e56eb77',
        ],
        [
          '2b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c',
          '85e89bc037945d93b343083b5a1c86131a01f60c50269763b570c854e5c09b7a',
        ],
        [
          '352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5',
          '321eb4075348f534d59c18259dda3e1f4a1b3b2e71b1039c67bd3d8bcf81998c',
        ],
        [
          '2fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f',
          '2de1068295dd865b64569335bd5dd80181d70ecfc882648423ba76b532b7d67',
        ],
        [
          '9248279b09b4d68dab21a9b066edda83263c3d84e09572e269ca0cd7f5453714',
          '73016f7bf234aade5d1aa71bdea2b1ff3fc0de2a887912ffe54a32ce97cb3402',
        ],
        [
          'daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729',
          'a69dce4a7d6c98e8d4a1aca87ef8d7003f83c230f3afa726ab40e52290be1c55',
        ],
        [
          'c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db',
          '2119a460ce326cdc76c45926c982fdac0e106e861edf61c5a039063f0e0e6482',
        ],
        [
          '6a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4',
          'e022cf42c2bd4a708b3f5126f16a24ad8b33ba48d0423b6efd5e6348100d8a82',
        ],
        [
          '1697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5',
          'b9c398f186806f5d27561506e4557433a2cf15009e498ae7adee9d63d01b2396',
        ],
        [
          '605bdb019981718b986d0f07e834cb0d9deb8360ffb7f61df982345ef27a7479',
          '2972d2de4f8d20681a78d93ec96fe23c26bfae84fb14db43b01e1e9056b8c49',
        ],
        [
          '62d14dab4150bf497402fdc45a215e10dcb01c354959b10cfe31c7e9d87ff33d',
          '80fc06bd8cc5b01098088a1950eed0db01aa132967ab472235f5642483b25eaf',
        ],
        [
          '80c60ad0040f27dade5b4b06c408e56b2c50e9f56b9b8b425e555c2f86308b6f',
          '1c38303f1cc5c30f26e66bad7fe72f70a65eed4cbe7024eb1aa01f56430bd57a',
        ],
        [
          '7a9375ad6167ad54aa74c6348cc54d344cc5dc9487d847049d5eabb0fa03c8fb',
          'd0e3fa9eca8726909559e0d79269046bdc59ea10c70ce2b02d499ec224dc7f7',
        ],
        [
          'd528ecd9b696b54c907a9ed045447a79bb408ec39b68df504bb51f459bc3ffc9',
          'eecf41253136e5f99966f21881fd656ebc4345405c520dbc063465b521409933',
        ],
        [
          '49370a4b5f43412ea25f514e8ecdad05266115e4a7ecb1387231808f8b45963',
          '758f3f41afd6ed428b3081b0512fd62a54c3f3afbb5b6764b653052a12949c9a',
        ],
        [
          '77f230936ee88cbbd73df930d64702ef881d811e0e1498e2f1c13eb1fc345d74',
          '958ef42a7886b6400a08266e9ba1b37896c95330d97077cbbe8eb3c7671c60d6',
        ],
        [
          'f2dac991cc4ce4b9ea44887e5c7c0bce58c80074ab9d4dbaeb28531b7739f530',
          'e0dedc9b3b2f8dad4da1f32dec2531df9eb5fbeb0598e4fd1a117dba703a3c37',
        ],
        [
          '463b3d9f662621fb1b4be8fbbe2520125a216cdfc9dae3debcba4850c690d45b',
          '5ed430d78c296c3543114306dd8622d7c622e27c970a1de31cb377b01af7307e',
        ],
        [
          'f16f804244e46e2a09232d4aff3b59976b98fac14328a2d1a32496b49998f247',
          'cedabd9b82203f7e13d206fcdf4e33d92a6c53c26e5cce26d6579962c4e31df6',
        ],
        [
          'caf754272dc84563b0352b7a14311af55d245315ace27c65369e15f7151d41d1',
          'cb474660ef35f5f2a41b643fa5e460575f4fa9b7962232a5c32f908318a04476',
        ],
        [
          '2600ca4b282cb986f85d0f1709979d8b44a09c07cb86d7c124497bc86f082120',
          '4119b88753c15bd6a693b03fcddbb45d5ac6be74ab5f0ef44b0be9475a7e4b40',
        ],
        [
          '7635ca72d7e8432c338ec53cd12220bc01c48685e24f7dc8c602a7746998e435',
          '91b649609489d613d1d5e590f78e6d74ecfc061d57048bad9e76f302c5b9c61',
        ],
        [
          '754e3239f325570cdbbf4a87deee8a66b7f2b33479d468fbc1a50743bf56cc18',
          '673fb86e5bda30fb3cd0ed304ea49a023ee33d0197a695d0c5d98093c536683',
        ],
        [
          'e3e6bd1071a1e96aff57859c82d570f0330800661d1c952f9fe2694691d9b9e8',
          '59c9e0bba394e76f40c0aa58379a3cb6a5a2283993e90c4167002af4920e37f5',
        ],
        [
          '186b483d056a033826ae73d88f732985c4ccb1f32ba35f4b4cc47fdcf04aa6eb',
          '3b952d32c67cf77e2e17446e204180ab21fb8090895138b4a4a797f86e80888b',
        ],
        [
          'df9d70a6b9876ce544c98561f4be4f725442e6d2b737d9c91a8321724ce0963f',
          '55eb2dafd84d6ccd5f862b785dc39d4ab157222720ef9da217b8c45cf2ba2417',
        ],
        [
          '5edd5cc23c51e87a497ca815d5dce0f8ab52554f849ed8995de64c5f34ce7143',
          'efae9c8dbc14130661e8cec030c89ad0c13c66c0d17a2905cdc706ab7399a868',
        ],
        [
          '290798c2b6476830da12fe02287e9e777aa3fba1c355b17a722d362f84614fba',
          'e38da76dcd440621988d00bcf79af25d5b29c094db2a23146d003afd41943e7a',
        ],
        [
          'af3c423a95d9f5b3054754efa150ac39cd29552fe360257362dfdecef4053b45',
          'f98a3fd831eb2b749a93b0e6f35cfb40c8cd5aa667a15581bc2feded498fd9c6',
        ],
        [
          '766dbb24d134e745cccaa28c99bf274906bb66b26dcf98df8d2fed50d884249a',
          '744b1152eacbe5e38dcc887980da38b897584a65fa06cedd2c924f97cbac5996',
        ],
        [
          '59dbf46f8c94759ba21277c33784f41645f7b44f6c596a58ce92e666191abe3e',
          'c534ad44175fbc300f4ea6ce648309a042ce739a7919798cd85e216c4a307f6e',
        ],
        [
          'f13ada95103c4537305e691e74e9a4a8dd647e711a95e73cb62dc6018cfd87b8',
          'e13817b44ee14de663bf4bc808341f326949e21a6a75c2570778419bdaf5733d',
        ],
        [
          '7754b4fa0e8aced06d4167a2c59cca4cda1869c06ebadfb6488550015a88522c',
          '30e93e864e669d82224b967c3020b8fa8d1e4e350b6cbcc537a48b57841163a2',
        ],
        [
          '948dcadf5990e048aa3874d46abef9d701858f95de8041d2a6828c99e2262519',
          'e491a42537f6e597d5d28a3224b1bc25df9154efbd2ef1d2cbba2cae5347d57e',
        ],
        [
          '7962414450c76c1689c7b48f8202ec37fb224cf5ac0bfa1570328a8a3d7c77ab',
          '100b610ec4ffb4760d5c1fc133ef6f6b12507a051f04ac5760afa5b29db83437',
        ],
        [
          '3514087834964b54b15b160644d915485a16977225b8847bb0dd085137ec47ca',
          'ef0afbb2056205448e1652c48e8127fc6039e77c15c2378b7e7d15a0de293311',
        ],
        [
          'd3cc30ad6b483e4bc79ce2c9dd8bc54993e947eb8df787b442943d3f7b527eaf',
          '8b378a22d827278d89c5e9be8f9508ae3c2ad46290358630afb34db04eede0a4',
        ],
        [
          '1624d84780732860ce1c78fcbfefe08b2b29823db913f6493975ba0ff4847610',
          '68651cf9b6da903e0914448c6cd9d4ca896878f5282be4c8cc06e2a404078575',
        ],
        [
          '733ce80da955a8a26902c95633e62a985192474b5af207da6df7b4fd5fc61cd4',
          'f5435a2bd2badf7d485a4d8b8db9fcce3e1ef8e0201e4578c54673bc1dc5ea1d',
        ],
        [
          '15d9441254945064cf1a1c33bbd3b49f8966c5092171e699ef258dfab81c045c',
          'd56eb30b69463e7234f5137b73b84177434800bacebfc685fc37bbe9efe4070d',
        ],
        [
          'a1d0fcf2ec9de675b612136e5ce70d271c21417c9d2b8aaaac138599d0717940',
          'edd77f50bcb5a3cab2e90737309667f2641462a54070f3d519212d39c197a629',
        ],
        [
          'e22fbe15c0af8ccc5780c0735f84dbe9a790badee8245c06c7ca37331cb36980',
          'a855babad5cd60c88b430a69f53a1a7a38289154964799be43d06d77d31da06',
        ],
        [
          '311091dd9860e8e20ee13473c1155f5f69635e394704eaa74009452246cfa9b3',
          '66db656f87d1f04fffd1f04788c06830871ec5a64feee685bd80f0b1286d8374',
        ],
        [
          '34c1fd04d301be89b31c0442d3e6ac24883928b45a9340781867d4232ec2dbdf',
          '9414685e97b1b5954bd46f730174136d57f1ceeb487443dc5321857ba73abee',
        ],
        [
          'f219ea5d6b54701c1c14de5b557eb42a8d13f3abbcd08affcc2a5e6b049b8d63',
          '4cb95957e83d40b0f73af4544cccf6b1f4b08d3c07b27fb8d8c2962a400766d1',
        ],
        [
          'd7b8740f74a8fbaab1f683db8f45de26543a5490bca627087236912469a0b448',
          'fa77968128d9c92ee1010f337ad4717eff15db5ed3c049b3411e0315eaa4593b',
        ],
        [
          '32d31c222f8f6f0ef86f7c98d3a3335ead5bcd32abdd94289fe4d3091aa824bf',
          '5f3032f5892156e39ccd3d7915b9e1da2e6dac9e6f26e961118d14b8462e1661',
        ],
        [
          '7461f371914ab32671045a155d9831ea8793d77cd59592c4340f86cbc18347b5',
          '8ec0ba238b96bec0cbdddcae0aa442542eee1ff50c986ea6b39847b3cc092ff6',
        ],
        [
          'ee079adb1df1860074356a25aa38206a6d716b2c3e67453d287698bad7b2b2d6',
          '8dc2412aafe3be5c4c5f37e0ecc5f9f6a446989af04c4e25ebaac479ec1c8c1e',
        ],
        [
          '16ec93e447ec83f0467b18302ee620f7e65de331874c9dc72bfd8616ba9da6b5',
          '5e4631150e62fb40d0e8c2a7ca5804a39d58186a50e497139626778e25b0674d',
        ],
        [
          'eaa5f980c245f6f038978290afa70b6bd8855897f98b6aa485b96065d537bd99',
          'f65f5d3e292c2e0819a528391c994624d784869d7e6ea67fb18041024edc07dc',
        ],
        [
          '78c9407544ac132692ee1910a02439958ae04877151342ea96c4b6b35a49f51',
          'f3e0319169eb9b85d5404795539a5e68fa1fbd583c064d2462b675f194a3ddb4',
        ],
        [
          '494f4be219a1a77016dcd838431aea0001cdc8ae7a6fc688726578d9702857a5',
          '42242a969283a5f339ba7f075e36ba2af925ce30d767ed6e55f4b031880d562c',
        ],
        [
          'a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5',
          '204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b',
        ],
        [
          'c41916365abb2b5d09192f5f2dbeafec208f020f12570a184dbadc3e58595997',
          '4f14351d0087efa49d245b328984989d5caf9450f34bfc0ed16e96b58fa9913',
        ],
        [
          '841d6063a586fa475a724604da03bc5b92a2e0d2e0a36acfe4c73a5514742881',
          '73867f59c0659e81904f9a1c7543698e62562d6744c169ce7a36de01a8d6154',
        ],
        [
          '5e95bb399a6971d376026947f89bde2f282b33810928be4ded112ac4d70e20d5',
          '39f23f366809085beebfc71181313775a99c9aed7d8ba38b161384c746012865',
        ],
        [
          '36e4641a53948fd476c39f8a99fd974e5ec07564b5315d8bf99471bca0ef2f66',
          'd2424b1b1abe4eb8164227b085c9aa9456ea13493fd563e06fd51cf5694c78fc',
        ],
        [
          '336581ea7bfbbb290c191a2f507a41cf5643842170e914faeab27c2c579f726',
          'ead12168595fe1be99252129b6e56b3391f7ab1410cd1e0ef3dcdcabd2fda224',
        ],
        [
          '8ab89816dadfd6b6a1f2634fcf00ec8403781025ed6890c4849742706bd43ede',
          '6fdcef09f2f6d0a044e654aef624136f503d459c3e89845858a47a9129cdd24e',
        ],
        [
          '1e33f1a746c9c5778133344d9299fcaa20b0938e8acff2544bb40284b8c5fb94',
          '60660257dd11b3aa9c8ed618d24edff2306d320f1d03010e33a7d2057f3b3b6',
        ],
        [
          '85b7c1dcb3cec1b7ee7f30ded79dd20a0ed1f4cc18cbcfcfa410361fd8f08f31',
          '3d98a9cdd026dd43f39048f25a8847f4fcafad1895d7a633c6fed3c35e999511',
        ],
        [
          '29df9fbd8d9e46509275f4b125d6d45d7fbe9a3b878a7af872a2800661ac5f51',
          'b4c4fe99c775a606e2d8862179139ffda61dc861c019e55cd2876eb2a27d84b',
        ],
        [
          'a0b1cae06b0a847a3fea6e671aaf8adfdfe58ca2f768105c8082b2e449fce252',
          'ae434102edde0958ec4b19d917a6a28e6b72da1834aff0e650f049503a296cf2',
        ],
        [
          '4e8ceafb9b3e9a136dc7ff67e840295b499dfb3b2133e4ba113f2e4c0e121e5',
          'cf2174118c8b6d7a4b48f6d534ce5c79422c086a63460502b827ce62a326683c',
        ],
        [
          'd24a44e047e19b6f5afb81c7ca2f69080a5076689a010919f42725c2b789a33b',
          '6fb8d5591b466f8fc63db50f1c0f1c69013f996887b8244d2cdec417afea8fa3',
        ],
        [
          'ea01606a7a6c9cdd249fdfcfacb99584001edd28abbab77b5104e98e8e3b35d4',
          '322af4908c7312b0cfbfe369f7a7b3cdb7d4494bc2823700cfd652188a3ea98d',
        ],
        [
          'af8addbf2b661c8a6c6328655eb96651252007d8c5ea31be4ad196de8ce2131f',
          '6749e67c029b85f52a034eafd096836b2520818680e26ac8f3dfbcdb71749700',
        ],
        [
          'e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889',
          '2aeabe7e4531510116217f07bf4d07300de97e4874f81f533420a72eeb0bd6a4',
        ],
        [
          '591ee355313d99721cf6993ffed1e3e301993ff3ed258802075ea8ced397e246',
          'b0ea558a113c30bea60fc4775460c7901ff0b053d25ca2bdeee98f1a4be5d196',
        ],
        [
          '11396d55fda54c49f19aa97318d8da61fa8584e47b084945077cf03255b52984',
          '998c74a8cd45ac01289d5833a7beb4744ff536b01b257be4c5767bea93ea57a4',
        ],
        [
          '3c5d2a1ba39c5a1790000738c9e0c40b8dcdfd5468754b6405540157e017aa7a',
          'b2284279995a34e2f9d4de7396fc18b80f9b8b9fdd270f6661f79ca4c81bd257',
        ],
        [
          'cc8704b8a60a0defa3a99a7299f2e9c3fbc395afb04ac078425ef8a1793cc030',
          'bdd46039feed17881d1e0862db347f8cf395b74fc4bcdc4e940b74e3ac1f1b13',
        ],
        [
          'c533e4f7ea8555aacd9777ac5cad29b97dd4defccc53ee7ea204119b2889b197',
          '6f0a256bc5efdf429a2fb6242f1a43a2d9b925bb4a4b3a26bb8e0f45eb596096',
        ],
        [
          'c14f8f2ccb27d6f109f6d08d03cc96a69ba8c34eec07bbcf566d48e33da6593',
          'c359d6923bb398f7fd4473e16fe1c28475b740dd098075e6c0e8649113dc3a38',
        ],
        [
          'a6cbc3046bc6a450bac24789fa17115a4c9739ed75f8f21ce441f72e0b90e6ef',
          '21ae7f4680e889bb130619e2c0f95a360ceb573c70603139862afd617fa9b9f',
        ],
        [
          '347d6d9a02c48927ebfb86c1359b1caf130a3c0267d11ce6344b39f99d43cc38',
          '60ea7f61a353524d1c987f6ecec92f086d565ab687870cb12689ff1e31c74448',
        ],
        [
          'da6545d2181db8d983f7dcb375ef5866d47c67b1bf31c8cf855ef7437b72656a',
          '49b96715ab6878a79e78f07ce5680c5d6673051b4935bd897fea824b77dc208a',
        ],
        [
          'c40747cc9d012cb1a13b8148309c6de7ec25d6945d657146b9d5994b8feb1111',
          '5ca560753be2a12fc6de6caf2cb489565db936156b9514e1bb5e83037e0fa2d4',
        ],
        [
          '4e42c8ec82c99798ccf3a610be870e78338c7f713348bd34c8203ef4037f3502',
          '7571d74ee5e0fb92a7a8b33a07783341a5492144cc54bcc40a94473693606437',
        ],
        [
          '3775ab7089bc6af823aba2e1af70b236d251cadb0c86743287522a1b3b0dedea',
          'be52d107bcfa09d8bcb9736a828cfa7fac8db17bf7a76a2c42ad961409018cf7',
        ],
        [
          'cee31cbf7e34ec379d94fb814d3d775ad954595d1314ba8846959e3e82f74e26',
          '8fd64a14c06b589c26b947ae2bcf6bfa0149ef0be14ed4d80f448a01c43b1c6d',
        ],
        [
          'b4f9eaea09b6917619f6ea6a4eb5464efddb58fd45b1ebefcdc1a01d08b47986',
          '39e5c9925b5a54b07433a4f18c61726f8bb131c012ca542eb24a8ac07200682a',
        ],
        [
          'd4263dfc3d2df923a0179a48966d30ce84e2515afc3dccc1b77907792ebcc60e',
          '62dfaf07a0f78feb30e30d6295853ce189e127760ad6cf7fae164e122a208d54',
        ],
        [
          '48457524820fa65a4f8d35eb6930857c0032acc0a4a2de422233eeda897612c4',
          '25a748ab367979d98733c38a1fa1c2e7dc6cc07db2d60a9ae7a76aaa49bd0f77',
        ],
        [
          'dfeeef1881101f2cb11644f3a2afdfc2045e19919152923f367a1767c11cceda',
          'ecfb7056cf1de042f9420bab396793c0c390bde74b4bbdff16a83ae09a9a7517',
        ],
        [
          '6d7ef6b17543f8373c573f44e1f389835d89bcbc6062ced36c82df83b8fae859',
          'cd450ec335438986dfefa10c57fea9bcc521a0959b2d80bbf74b190dca712d10',
        ],
        [
          'e75605d59102a5a2684500d3b991f2e3f3c88b93225547035af25af66e04541f',
          'f5c54754a8f71ee540b9b48728473e314f729ac5308b06938360990e2bfad125',
        ],
        [
          'eb98660f4c4dfaa06a2be453d5020bc99a0c2e60abe388457dd43fefb1ed620c',
          '6cb9a8876d9cb8520609af3add26cd20a0a7cd8a9411131ce85f44100099223e',
        ],
        [
          '13e87b027d8514d35939f2e6892b19922154596941888336dc3563e3b8dba942',
          'fef5a3c68059a6dec5d624114bf1e91aac2b9da568d6abeb2570d55646b8adf1',
        ],
        [
          'ee163026e9fd6fe017c38f06a5be6fc125424b371ce2708e7bf4491691e5764a',
          '1acb250f255dd61c43d94ccc670d0f58f49ae3fa15b96623e5430da0ad6c62b2',
        ],
        [
          'b268f5ef9ad51e4d78de3a750c2dc89b1e626d43505867999932e5db33af3d80',
          '5f310d4b3c99b9ebb19f77d41c1dee018cf0d34fd4191614003e945a1216e423',
        ],
        [
          'ff07f3118a9df035e9fad85eb6c7bfe42b02f01ca99ceea3bf7ffdba93c4750d',
          '438136d603e858a3a5c440c38eccbaddc1d2942114e2eddd4740d098ced1f0d8',
        ],
        [
          '8d8b9855c7c052a34146fd20ffb658bea4b9f69e0d825ebec16e8c3ce2b526a1',
          'cdb559eedc2d79f926baf44fb84ea4d44bcf50fee51d7ceb30e2e7f463036758',
        ],
        [
          '52db0b5384dfbf05bfa9d472d7ae26dfe4b851ceca91b1eba54263180da32b63',
          'c3b997d050ee5d423ebaf66a6db9f57b3180c902875679de924b69d84a7b375',
        ],
        [
          'e62f9490d3d51da6395efd24e80919cc7d0f29c3f3fa48c6fff543becbd43352',
          '6d89ad7ba4876b0b22c2ca280c682862f342c8591f1daf5170e07bfd9ccafa7d',
        ],
        [
          '7f30ea2476b399b4957509c88f77d0191afa2ff5cb7b14fd6d8e7d65aaab1193',
          'ca5ef7d4b231c94c3b15389a5f6311e9daff7bb67b103e9880ef4bff637acaec',
        ],
        [
          '5098ff1e1d9f14fb46a210fada6c903fef0fb7b4a1dd1d9ac60a0361800b7a00',
          '9731141d81fc8f8084d37c6e7542006b3ee1b40d60dfe5362a5b132fd17ddc0',
        ],
        [
          '32b78c7de9ee512a72895be6b9cbefa6e2f3c4ccce445c96b9f2c81e2778ad58',
          'ee1849f513df71e32efc3896ee28260c73bb80547ae2275ba497237794c8753c',
        ],
        [
          'e2cb74fddc8e9fbcd076eef2a7c72b0ce37d50f08269dfc074b581550547a4f7',
          'd3aa2ed71c9dd2247a62df062736eb0baddea9e36122d2be8641abcb005cc4a4',
        ],
        [
          '8438447566d4d7bedadc299496ab357426009a35f235cb141be0d99cd10ae3a8',
          'c4e1020916980a4da5d01ac5e6ad330734ef0d7906631c4f2390426b2edd791f',
        ],
        [
          '4162d488b89402039b584c6fc6c308870587d9c46f660b878ab65c82c711d67e',
          '67163e903236289f776f22c25fb8a3afc1732f2b84b4e95dbda47ae5a0852649',
        ],
        [
          '3fad3fa84caf0f34f0f89bfd2dcf54fc175d767aec3e50684f3ba4a4bf5f683d',
          'cd1bc7cb6cc407bb2f0ca647c718a730cf71872e7d0d2a53fa20efcdfe61826',
        ],
        [
          '674f2600a3007a00568c1a7ce05d0816c1fb84bf1370798f1c69532faeb1a86b',
          '299d21f9413f33b3edf43b257004580b70db57da0b182259e09eecc69e0d38a5',
        ],
        [
          'd32f4da54ade74abb81b815ad1fb3b263d82d6c692714bcff87d29bd5ee9f08f',
          'f9429e738b8e53b968e99016c059707782e14f4535359d582fc416910b3eea87',
        ],
        [
          '30e4e670435385556e593657135845d36fbb6931f72b08cb1ed954f1e3ce3ff6',
          '462f9bce619898638499350113bbc9b10a878d35da70740dc695a559eb88db7b',
        ],
        [
          'be2062003c51cc3004682904330e4dee7f3dcd10b01e580bf1971b04d4cad297',
          '62188bc49d61e5428573d48a74e1c655b1c61090905682a0d5558ed72dccb9bc',
        ],
        [
          '93144423ace3451ed29e0fb9ac2af211cb6e84a601df5993c419859fff5df04a',
          '7c10dfb164c3425f5c71a3f9d7992038f1065224f72bb9d1d902a6d13037b47c',
        ],
        [
          'b015f8044f5fcbdcf21ca26d6c34fb8197829205c7b7d2a7cb66418c157b112c',
          'ab8c1e086d04e813744a655b2df8d5f83b3cdc6faa3088c1d3aea1454e3a1d5f',
        ],
        [
          'd5e9e1da649d97d89e4868117a465a3a4f8a18de57a140d36b3f2af341a21b52',
          '4cb04437f391ed73111a13cc1d4dd0db1693465c2240480d8955e8592f27447a',
        ],
        [
          'd3ae41047dd7ca065dbf8ed77b992439983005cd72e16d6f996a5316d36966bb',
          'bd1aeb21ad22ebb22a10f0303417c6d964f8cdd7df0aca614b10dc14d125ac46',
        ],
        [
          '463e2763d885f958fc66cdd22800f0a487197d0a82e377b49f80af87c897b065',
          'bfefacdb0e5d0fd7df3a311a94de062b26b80c61fbc97508b79992671ef7ca7f',
        ],
        [
          '7985fdfd127c0567c6f53ec1bb63ec3158e597c40bfe747c83cddfc910641917',
          '603c12daf3d9862ef2b25fe1de289aed24ed291e0ec6708703a5bd567f32ed03',
        ],
        [
          '74a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9',
          'cc6157ef18c9c63cd6193d83631bbea0093e0968942e8c33d5737fd790e0db08',
        ],
        [
          '30682a50703375f602d416664ba19b7fc9bab42c72747463a71d0896b22f6da3',
          '553e04f6b018b4fa6c8f39e7f311d3176290d0e0f19ca73f17714d9977a22ff8',
        ],
        [
          '9e2158f0d7c0d5f26c3791efefa79597654e7a2b2464f52b1ee6c1347769ef57',
          '712fcdd1b9053f09003a3481fa7762e9ffd7c8ef35a38509e2fbf2629008373',
        ],
        [
          '176e26989a43c9cfeba4029c202538c28172e566e3c4fce7322857f3be327d66',
          'ed8cc9d04b29eb877d270b4878dc43c19aefd31f4eee09ee7b47834c1fa4b1c3',
        ],
        [
          '75d46efea3771e6e68abb89a13ad747ecf1892393dfc4f1b7004788c50374da8',
          '9852390a99507679fd0b86fd2b39a868d7efc22151346e1a3ca4726586a6bed8',
        ],
        [
          '809a20c67d64900ffb698c4c825f6d5f2310fb0451c869345b7319f645605721',
          '9e994980d9917e22b76b061927fa04143d096ccc54963e6a5ebfa5f3f8e286c1',
        ],
        [
          '1b38903a43f7f114ed4500b4eac7083fdefece1cf29c63528d563446f972c180',
          '4036edc931a60ae889353f77fd53de4a2708b26b6f5da72ad3394119daf408f9',
        ],
      ],
    },
  };;
} catch (e) {
  pre = undefined;
}

defineCurve('secp256k1', {
  type: 'short',
  prime: 'k256',
  p: 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f',
  a: '0',
  b: '7',
  n: 'ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141',
  h: '1',
  hash: sha256,

  // Precomputed endomorphism
  beta: '7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee',
  lambda: '5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72',
  basis: [
    {
      a: '3086d221a7d46bcde86c90e49284eb15',
      b: '-e4437ed6010e88286f547fa90abfe4c3',
    },
    {
      a: '114ca50f7a8e2f3f657c1108d9d44cfd8',
      b: '3086d221a7d46bcde86c90e49284eb15',
    },
  ],

  gRed: false,
  g: [
    '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
    pre,
  ],
});

var r;

function rand(len) {
  if (!r)
    r = new Rand(null);

  return r.generate(len);
};

function Rand(rand) {
  this.rand = rand;
}

Rand.prototype.generate = function generate(len) {
  return this._rand(len);
};

// Emulate crypto API using randy
Rand.prototype._rand = function _rand(n) {
  if (this.rand.getBytes)
    return this.rand.getBytes(n);

  var res = new Uint8Array(n);
  for (var i = 0; i < res.length; i++)
    res[i] = this.rand.getByte();
  return res;
};

if (typeof self === 'object') {
  if (self.crypto && self.crypto.getRandomValues) {
    // Modern browsers
    Rand.prototype._rand = function _rand(n) {
      var arr = new Uint8Array(n);
      self.crypto.getRandomValues(arr);
      return arr;
    };
  } else if (self.msCrypto && self.msCrypto.getRandomValues) {
    // IE
    Rand.prototype._rand = function _rand(n) {
      var arr = new Uint8Array(n);
      self.msCrypto.getRandomValues(arr);
      return arr;
    };

    // Safari's WebWorkers do not have `crypto`
  } else if (typeof window === 'object') {
    // Old junk
    Rand.prototype._rand = function() {
      throw new Error('Not implemented yet');
    };
  }
} else {
  // Node.js or Web worker with no crypto support
  try {
    if (typeof crypto.randomBytes !== 'function')
      throw new Error('Not supported');

    Rand.prototype._rand = function _rand(n) {
      return crypto.randomBytes(n);
    };
  } catch (e) {
  }
}


function KeyPair(ec, options) {
  this.ec = ec;
  this.priv = null;
  this.pub = null;

  // KeyPair(ec, { priv: ..., pub: ... })
  if (options.priv)
    this._importPrivate(options.priv, options.privEnc);
  if (options.pub)
    this._importPublic(options.pub, options.pubEnc);
}
module.exports = KeyPair;

KeyPair.fromPublic = function fromPublic(ec, pub, enc) {
  if (pub instanceof KeyPair)
    return pub;

  return new KeyPair(ec, {
    pub: pub,
    pubEnc: enc,
  });
};

KeyPair.fromPrivate = function fromPrivate(ec, priv, enc) {
  if (priv instanceof KeyPair)
    return priv;

  return new KeyPair(ec, {
    priv: priv,
    privEnc: enc,
  });
};

KeyPair.prototype.validate = function validate() {
  var pub = this.getPublic();

  if (pub.isInfinity())
    return { result: false, reason: 'Invalid public key' };
  if (!pub.validate())
    return { result: false, reason: 'Public key is not a point' };
  if (!pub.mul(this.ec.curve.n).isInfinity())
    return { result: false, reason: 'Public key * N != O' };

  return { result: true, reason: null };
};

KeyPair.prototype.getPublic = function getPublic(compact, enc) {
  // compact is optional argument
  if (typeof compact === 'string') {
    enc = compact;
    compact = null;
  }

  if (!this.pub)
    this.pub = this.ec.g.mul(this.priv);

  if (!enc)
    return this.pub;

  return this.pub.encode(enc, compact);
};

KeyPair.prototype.getPrivate = function getPrivate(enc) {
  if (enc === 'hex')
    return this.priv.toString(16, 2);
  else
    return this.priv;
};

KeyPair.prototype._importPrivate = function _importPrivate(key, enc) {
  this.priv = new BN(key, enc || 16);

  // Ensure that the priv won't be bigger than n, otherwise we may fail
  // in fixed multiplication method
  this.priv = this.priv.umod(this.ec.curve.n);
};

KeyPair.prototype._importPublic = function _importPublic(key, enc) {
  if (key.x || key.y) {
    // Montgomery points only have an `x` coordinate.
    // Weierstrass/Edwards points on the other hand have both `x` and
    // `y` coordinates.
    if (this.ec.curve.type === 'mont') {
      minAssert(key.x, 'Need x coordinate');
    } else if (this.ec.curve.type === 'short' ||
      this.ec.curve.type === 'edwards') {
      minAssert(key.x && key.y, 'Need both x and y coordinate');
    }
    this.pub = this.ec.curve.point(key.x, key.y);
    return;
  }
  this.pub = this.ec.curve.decodePoint(key, enc);
};

// ECDH
KeyPair.prototype.derive = function derive(pub) {
  if (!pub.validate()) {
    minAssert(pub.validate(), 'public point not validated');
  }
  return pub.mul(this.priv).getX();
};

// ECDSA
KeyPair.prototype.sign = function sign(msg, enc, options) {
  return this.ec.sign(msg, this, enc, options);
};

KeyPair.prototype.verify = function verify(msg, signature, options) {
  return this.ec.verify(msg, signature, this, undefined, options);
};

KeyPair.prototype.inspect = function inspect() {
  return '<Key priv: ' + (this.priv && this.priv.toString(16, 2)) +
    ' pub: ' + (this.pub && this.pub.inspect()) + ' >';
};

function Signature(options, enc) {
  if (options instanceof Signature)
    return options;

  if (this._importDER(options, enc))
    return;

  minAssert(options.r && options.s, 'Signature without r or s');
  this.r = new BN(options.r, 16);
  this.s = new BN(options.s, 16);
  if (options.recoveryParam === undefined)
    this.recoveryParam = null;
  else
    this.recoveryParam = options.recoveryParam;
}
module.exports = Signature;

function Position() {
  this.place = 0;
}

function getLength(buf, p) {
  var initial = buf[p.place++];
  if (!(initial & 0x80)) {
    return initial;
  }
  var octetLen = initial & 0xf;

  // Indefinite length or overflow
  if (octetLen === 0 || octetLen > 4) {
    return false;
  }

  if (buf[p.place] === 0x00) {
    return false;
  }

  var val = 0;
  for (var i = 0, off = p.place; i < octetLen; i++, off++) {
    val <<= 8;
    val |= buf[off];
    val >>>= 0;
  }

  // Leading zeroes
  if (val <= 0x7f) {
    return false;
  }

  p.place = off;
  return val;
}

function rmPadding(buf) {
  var i = 0;
  var len = buf.length - 1;
  while (!buf[i] && !(buf[i + 1] & 0x80) && i < len) {
    i++;
  }
  if (i === 0) {
    return buf;
  }
  return buf.slice(i);
}

Signature.prototype._importDER = function _importDER(data, enc) {
  data = utils.toArray(data, enc);
  var p = new Position();
  if (data[p.place++] !== 0x30) {
    return false;
  }
  var len = getLength(data, p);
  if (len === false) {
    return false;
  }
  if ((len + p.place) !== data.length) {
    return false;
  }
  if (data[p.place++] !== 0x02) {
    return false;
  }
  var rlen = getLength(data, p);
  if (rlen === false) {
    return false;
  }
  if ((data[p.place] & 128) !== 0) {
    return false;
  }
  var r = data.slice(p.place, rlen + p.place);
  p.place += rlen;
  if (data[p.place++] !== 0x02) {
    return false;
  }
  var slen = getLength(data, p);
  if (slen === false) {
    return false;
  }
  if (data.length !== slen + p.place) {
    return false;
  }
  if ((data[p.place] & 128) !== 0) {
    return false;
  }
  var s = data.slice(p.place, slen + p.place);
  if (r[0] === 0) {
    if (r[1] & 0x80) {
      r = r.slice(1);
    } else {
      // Leading zeroes
      return false;
    }
  }
  if (s[0] === 0) {
    if (s[1] & 0x80) {
      s = s.slice(1);
    } else {
      // Leading zeroes
      return false;
    }
  }

  this.r = new BN(r);
  this.s = new BN(s);
  this.recoveryParam = null;

  return true;
};

function constructLength(arr, len) {
  if (len < 0x80) {
    arr.push(len);
    return;
  }
  var octets = 1 + (Math.log(len) / Math.LN2 >>> 3);
  arr.push(octets | 0x80);
  while (--octets) {
    arr.push((len >>> (octets << 3)) & 0xff);
  }
  arr.push(len);
}

Signature.prototype.toDER = function toDER(enc) {
  var r = this.r.toArray();
  var s = this.s.toArray();

  // Pad values
  if (r[0] & 0x80)
    r = [0].concat(r);
  // Pad values
  if (s[0] & 0x80)
    s = [0].concat(s);

  r = rmPadding(r);
  s = rmPadding(s);

  while (!s[0] && !(s[1] & 0x80)) {
    s = s.slice(1);
  }
  var arr = [0x02];
  constructLength(arr, r.length);
  arr = arr.concat(r);
  arr.push(0x02);
  constructLength(arr, s.length);
  var backHalf = arr.concat(s);
  var res = [0x30];
  constructLength(res, backHalf.length);
  res = res.concat(backHalf);
  return utils.encode(res, enc);
};


function EC(options) {
  if (!(this instanceof EC))
    return new EC(options);

  // Shortcut `elliptic.ec(curve-name)`
  if (typeof options === 'string') {
    minAssert(Object.prototype.hasOwnProperty.call(curves, options),
      'Unknown curve ' + options);

    options = curves[options];
  }

  // Shortcut for `elliptic.ec(elliptic.curves.curveName)`
  if (options instanceof curves.PresetCurve)
    options = { curve: options };

  this.curve = options.curve.curve;
  this.n = this.curve.n;
  this.nh = this.n.ushrn(1);
  this.g = this.curve.g;

  // Point on curve
  this.g = options.curve.g;
  this.g.precompute(options.curve.n.bitLength() + 1);

  // Hash for function for DRBG
  this.hash = options.hash || options.curve.hash;
}
module.exports = EC;

EC.prototype.keyPair = function keyPair(options) {
  return new KeyPair(this, options);
};

EC.prototype.keyFromPrivate = function keyFromPrivate(priv, enc) {
  return KeyPair.fromPrivate(this, priv, enc);
};

EC.prototype.keyFromPublic = function keyFromPublic(pub, enc) {
  return KeyPair.fromPublic(this, pub, enc);
};

EC.prototype.genKeyPair = function genKeyPair(options) {
  if (!options)
    options = {};

  // Instantiate Hmac_DRBG
  var drbg = new HmacDRBG({
    hash: this.hash,
    pers: options.pers,
    persEnc: options.persEnc || 'utf8',
    entropy: options.entropy || rand(this.hash.hmacStrength),
    entropyEnc: options.entropy && options.entropyEnc || 'utf8',
    nonce: this.n.toArray(),
  });

  var bytes = this.n.byteLength();
  var ns2 = this.n.sub(new BN(2));
  for (; ;) {
    var priv = new BN(drbg.generate(bytes));
    if (priv.cmp(ns2) > 0)
      continue;

    priv.iaddn(1);
    return this.keyFromPrivate(priv);
  }
};

EC.prototype._truncateToN = function _truncateToN(msg, truncOnly, bitLength) {
  var byteLength;
  if (BN.isBN(msg) || typeof msg === 'number') {
    msg = new BN(msg, 16);
    byteLength = msg.byteLength();
  } else if (typeof msg === 'object') {
    // BN assumes an array-like input and asserts length
    byteLength = msg.length;
    msg = new BN(msg, 16);
  } else {
    // BN converts the value to string
    var str = msg.toString();
    // HEX encoding
    byteLength = (str.length + 1) >>> 1;
    msg = new BN(str, 16);
  }
  // Allow overriding
  if (typeof bitLength !== 'number') {
    bitLength = byteLength * 8;
  }
  var delta = bitLength - this.n.bitLength();
  if (delta > 0)
    msg = msg.ushrn(delta);
  if (!truncOnly && msg.cmp(this.n) >= 0)
    return msg.sub(this.n);
  else
    return msg;
};

EC.prototype.sign = function sign(msg, key, enc, options) {
  if (typeof enc === 'object') {
    options = enc;
    enc = null;
  }
  if (!options)
    options = {};

  if (typeof msg !== 'string' && typeof msg !== 'number' && !BN.isBN(msg)) {
    minAssert(typeof msg === 'object' && msg && typeof msg.length === 'number',
      'Expected message to be an array-like, a hex string, or a BN instance');
    minAssert((msg.length >>> 0) === msg.length); // non-negative 32-bit integer
    for (var i = 0; i < msg.length; i++) minAssert((msg[i] & 255) === msg[i]);
  }

  key = this.keyFromPrivate(key, enc);
  msg = this._truncateToN(msg, false, options.msgBitLength);

  // Would fail further checks, but let's make the error message clear
  minAssert(!msg.isNeg(), 'Can not sign a negative message');

  // Zero-extend key to provide enough entropy
  var bytes = this.n.byteLength();
  var bkey = key.getPrivate().toArray('be', bytes);

  // Zero-extend nonce to have the same byte size as N
  var nonce = msg.toArray('be', bytes);

  // Recheck nonce to be bijective to msg
  minAssert((new BN(nonce)).eq(msg), 'Can not sign message');

  // Instantiate Hmac_DRBG
  var drbg = new HmacDRBG({
    hash: this.hash,
    entropy: bkey,
    nonce: nonce,
    pers: options.pers,
    persEnc: options.persEnc || 'utf8',
  });

  // Number of bytes to generate
  var ns1 = this.n.sub(new BN(1));

  for (var iter = 0; ; iter++) {
    var k = options.k ?
      options.k(iter) :
      new BN(drbg.generate(this.n.byteLength()));
    k = this._truncateToN(k, true);
    if (k.cmpn(1) <= 0 || k.cmp(ns1) >= 0)
      continue;

    var kp = this.g.mul(k);
    if (kp.isInfinity())
      continue;

    var kpX = kp.getX();
    var r = kpX.umod(this.n);
    if (r.cmpn(0) === 0)
      continue;

    var s = k.invm(this.n).mul(r.mul(key.getPrivate()).iadd(msg));
    s = s.umod(this.n);
    if (s.cmpn(0) === 0)
      continue;

    var recoveryParam = (kp.getY().isOdd() ? 1 : 0) |
      (kpX.cmp(r) !== 0 ? 2 : 0);

    // Use complement of `s`, if it is > `n / 2`
    if (options.canonical && s.cmp(this.nh) > 0) {
      s = this.n.sub(s);
      recoveryParam ^= 1;
    }

    return new Signature({ r: r, s: s, recoveryParam: recoveryParam });
  }
};

EC.prototype.verify = function verify(msg, signature, key, enc, options) {
  if (!options)
    options = {};

  msg = this._truncateToN(msg, false, options.msgBitLength);
  key = this.keyFromPublic(key, enc);
  signature = new Signature(signature, 'hex');

  // Perform primitive values validation
  var r = signature.r;
  var s = signature.s;
  if (r.cmpn(1) < 0 || r.cmp(this.n) >= 0)
    return false;
  if (s.cmpn(1) < 0 || s.cmp(this.n) >= 0)
    return false;

  // Validate signature
  var sinv = s.invm(this.n);
  var u1 = sinv.mul(msg).umod(this.n);
  var u2 = sinv.mul(r).umod(this.n);
  var p;

  if (!this.curve._maxwellTrick) {
    p = this.g.mulAdd(u1, key.getPublic(), u2);
    if (p.isInfinity())
      return false;

    return p.getX().umod(this.n).cmp(r) === 0;
  }

  // NOTE: Greg Maxwell's trick, inspired by:
  // https://git.io/vad3K

  p = this.g.jmulAdd(u1, key.getPublic(), u2);
  if (p.isInfinity())
    return false;

  // Compare `p.x` of Jacobian point with `r`,
  // this will do `p.x == r * p.z^2` instead of multiplying `p.x` by the
  // inverse of `p.z^2`
  return p.eqXToP(r);
};

EC.prototype.recoverPubKey = function(msg, signature, j, enc) {
  minAssert((3 & j) === j, 'The recovery param is more than two bits');
  signature = new Signature(signature, enc);

  var n = this.n;
  var e = new BN(msg);
  var r = signature.r;
  var s = signature.s;

  // A set LSB signifies that the y-coordinate is odd
  var isYOdd = j & 1;
  var isSecondKey = j >> 1;
  if (r.cmp(this.curve.p.umod(this.curve.n)) >= 0 && isSecondKey)
    throw new Error('Unable to find sencond key candinate');

  // 1.1. Let x = r + jn.
  if (isSecondKey)
    r = this.curve.pointFromX(r.add(this.curve.n), isYOdd);
  else
    r = this.curve.pointFromX(r, isYOdd);

  var rInv = signature.r.invm(n);
  var s1 = n.sub(e).mul(rInv).umod(n);
  var s2 = s.mul(rInv).umod(n);

  // 1.6.1 Compute Q = r^-1 (sR -  eG)
  //               Q = r^-1 (sR + -eG)
  return this.g.mulAdd(s1, r, s2);
};

EC.prototype.getKeyRecoveryParam = function(e, signature, Q, enc) {
  signature = new Signature(signature, enc);
  if (signature.recoveryParam !== null)
    return signature.recoveryParam;

  for (var i = 0; i < 4; i++) {
    var Qprime;
    try {
      Qprime = this.recoverPubKey(e, signature, i);
    } catch (e) {
      continue;
    }

    if (Qprime.eq(Q))
      return i;
  }
  throw new Error('Unable to find valid recovery factor');
};

const secp256k1 = new EC('secp256k1')





// prototype class for hash functions
function shaHashHash(blockSize, finalSize) {
  this._block = Buffer.alloc(blockSize);
  this._finalSize = finalSize;
  this._blockSize = blockSize;
  this._len = 0;
}

shaHashHash.prototype.update = function(data, enc) {
  /* eslint no-param-reassign: 0 */
  data = Buffer.from(data, enc || 'utf8');

  var block = this._block;
  var blockSize = this._blockSize;
  var length = data.length;
  var accum = this._len;

  for (var offset = 0; offset < length;) {
    var assigned = accum % blockSize;
    var remainder = Math.min(length - offset, blockSize - assigned);

    for (var i = 0; i < remainder; i++) {
      block[assigned + i] = data[offset + i];
    }

    accum += remainder;
    offset += remainder;

    if ((accum % blockSize) === 0) {
      this._update(block);
    }
  }

  this._len += length;
  return this;
};

shaHashHash.prototype.digest = function(enc) {
  var rem = this._len % this._blockSize;

  this._block[rem] = 0x80;

	/*
	 * zero (rem + 1) trailing bits, where (rem + 1) is the smallest
	 * non-negative solution to the equation (length + 1 + (rem + 1)) === finalSize mod blockSize
	 */
  this._block.fill(0, rem + 1);

  if (rem >= this._finalSize) {
    this._update(this._block);
    this._block.fill(0);
  }

  var bits = this._len * 8;

  // uint32
  if (bits <= 0xffffffff) {
    this._block.writeUInt32BE(bits, this._blockSize - 4);

    // uint64
  } else {
    var lowBits = (bits & 0xffffffff) >>> 0;
    var highBits = (bits - lowBits) / 0x100000000;

    this._block.writeUInt32BE(highBits, this._blockSize - 8);
    this._block.writeUInt32BE(lowBits, this._blockSize - 4);
  }

  this._update(this._block);
  var hash = this._hash();

  return enc ? hash.toString(enc) : hash;
};

shaHashHash.prototype._update = function() {
  throw new Error('_update must be implemented by subclass');
};

var K = [
  0x5a827999, 0x6ed9eba1, 0x8f1bbcdc | 0, 0xca62c1d6 | 0
];

var W = new Array(80);

function sha(algorithm) {
  var alg = algorithm.toLowerCase();
  var Algorithm = eval(`${alg}`);
  if (!Algorithm) {
    throw new Error(alg + ' is not supported (we accept pull requests)');
  }

  return new Algorithm();
};

function Sha() {
  this.init();
  this._w = W;

  shaHashHash.call(this, 64, 56);
}

inherits(Sha, shaHashHash);

Sha.prototype.init = function() {
  this._a = 0x67452301;
  this._b = 0xefcdab89;
  this._c = 0x98badcfe;
  this._d = 0x10325476;
  this._e = 0xc3d2e1f0;

  return this;
};

function rotl5(num) {
  return (num << 5) | (num >>> 27);
}

function rotl30(num) {
  return (num << 30) | (num >>> 2);
}

function ft(s, b, c, d) {
  if (s === 0) {
    return (b & c) | (~b & d);
  }
  if (s === 2) {
    return (b & c) | (b & d) | (c & d);
  }
  return b ^ c ^ d;
}

Sha.prototype._update = function(M) {
  var w = this._w;

  var a = this._a | 0;
  var b = this._b | 0;
  var c = this._c | 0;
  var d = this._d | 0;
  var e = this._e | 0;

  for (var i = 0; i < 16; ++i) {
    w[i] = M.readInt32BE(i * 4);
  }
  for (; i < 80; ++i) {
    w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
  }

  for (var j = 0; j < 80; ++j) {
    var s = ~~(j / 20);
    var t = (rotl5(a) + ft(s, b, c, d) + e + w[j] + K[s]) | 0;

    e = d;
    d = c;
    c = rotl30(b);
    b = a;
    a = t;
  }

  this._a = (a + this._a) | 0;
  this._b = (b + this._b) | 0;
  this._c = (c + this._c) | 0;
  this._d = (d + this._d) | 0;
  this._e = (e + this._e) | 0;
};

Sha.prototype._hash = function() {
  var H = Buffer.allocUnsafe(20);

  H.writeInt32BE(this._a | 0, 0);
  H.writeInt32BE(this._b | 0, 4);
  H.writeInt32BE(this._c | 0, 8);
  H.writeInt32BE(this._d | 0, 12);
  H.writeInt32BE(this._e | 0, 16);

  return H;
};


const n = secp256k1.curve.n
const G = secp256k1.curve.g


function eccGetEncoded(P, compressed) { return Buffer.from(P._encode(compressed)) }

function eccAssumeCompression(value, pubkey) {
  if (value === undefined && pubkey !== undefined) return __isPointCompressed(pubkey)
  if (value === undefined) return true
  return value
}

function eccPointFromScalar(d, __compressed) {
  if (!eccIsPrivate(d)) throw new TypeError(THROW_BAD_PRIVATE)

  const dd = eccFromBuffer(d)
  const pp = G.mul(dd)
  if (pp.isInfinity()) return null

  const compressed = eccAssumeCompression(__compressed)
  return eccGetEncoded(pp, compressed)
}

function eccFromBuffer(d) { return new BN(d) }
function eccToBuffer(d) { return d.toArrayLike(Buffer, 'be', 32) }

function eccIsOrderScalar(x) {
  if (!eccIsScalar(x)) return false
  return EC_GROUP_ORDER.compare(x) > 0 // < G
}

function eccPrivateAdd(d, tweak) {
  if (!eccIsPrivate(d)) throw new TypeError(THROW_BAD_PRIVATE)
  if (!eccIsOrderScalar(tweak)) throw new TypeError(THROW_BAD_TWEAK)

  const dd = eccFromBuffer(d)
  const tt = eccFromBuffer(tweak)
  const dt = eccToBuffer(dd.add(tt).umod(n))
  if (!eccIsPrivate(dt)) return null

  return dt
}

const ZERO32 = Buffer.alloc(32, 0)
const EC_GROUP_ORDER = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')

function eccIsScalar(x) {
  return (x instanceof Uint8Array) && x.length === 32
}

function eccIsPrivate(x) {
  if (!eccIsScalar(x)) return false
  return ZERO32.compare(x) < 0 && // > 0
    EC_GROUP_ORDER.compare(x) > 0 // < G
}

function ecc__sign(hash, x, addData) {
  if (!eccIsScalar(hash)) throw new TypeError(THROW_BAD_HASH)
  if (!eccIsPrivate(x)) throw new TypeError(THROW_BAD_PRIVATE)
  if (addData !== undefined && !eccIsScalar(addData)) throw new TypeError(THROW_BAD_EXTRA_DATA)

  const d = eccFromBuffer(x)
  const e = eccFromBuffer(hash)

  let r, s
  const checkSig = function(k) {
    const kI = eccFromBuffer(k)
    const Q = G.mul(kI)

    if (Q.isInfinity()) return false

    r = Q.x.umod(n)
    if (r.isZero() === 0) return false

    s = kI
      .invm(n)
      .mul(e.add(d.mul(r)))
      .umod(n)
    if (s.isZero() === 0) return false

    return true
  }

  deterministicGenerateK(hash, x, checkSig, isPrivate, addData)

  // enforce low S values, see bip62: 'low s values in signatures'
  if (s.cmp(nDiv2) > 0) {
    s = n.sub(s)
  }

  const buffer = Buffer.allocUnsafe(64)
  eccToBuffer(r).copy(buffer, 0)
  eccToBuffer(s).copy(buffer, 32)
  return buffer
}

function eccSign(hash, x) {
  return ecc__sign(hash, x)
}


function createHashHash(hash) {
  Base.call(this, 'digest')

  this._hash = hash
}

inherits(createHashHash, Base)

createHashHash.prototype._update = function(data) {
  this._hash.update(data)
}

createHashHash.prototype._final = function() {
  return this._hash.digest()
}

function createHash(alg) {
  alg = alg.toLowerCase()
  if (alg === 'md5') return new MD5()
  if (alg === 'rmd160' || alg === 'ripemd160') return new RIPEMD160()

  return new createHashHash(sha(alg))
}

const HIGHEST_BIT = 0x80000000;

const UINT31_MAX = Math.pow(2, 31) - 1;

function cryptoHash160(buffer) {
  const sha256Hash = createHash('sha256')
    .update(buffer)
    .digest();
  try {
    return createHash('rmd160')
      .update(sha256Hash)
      .digest();
  }
  catch (err) {
    return createHash('ripemd160')
      .update(sha256Hash)
      .digest();
  }
}

function UInt31(value) {
  return typeforce.UInt32(value) && value <= UINT31_MAX;
}

function BIP32Path(value) {
  return (typeforce.String(value) && value.match(/^(m\/)?(\d+'?\/)*\d+'?$/) !== null);
}

const UINT256_TYPE = typeforce.BufferN(32);

const NETWORK_TYPE = typeforce.compile({
  wif: typeforce.UInt8,
  bip32: {
    public: typeforce.UInt32,
    private: typeforce.UInt32,
  },
});

class BIP32 {
  constructor(__D, __Q, chainCode, network, __DEPTH = 0, __INDEX = 0, __PARENT_FINGERPRINT = 0x00000000) {
    this.__D = __D;
    this.__Q = __Q;
    this.chainCode = chainCode;
    this.network = network;
    this.__DEPTH = __DEPTH;
    this.__INDEX = __INDEX;
    this.__PARENT_FINGERPRINT = __PARENT_FINGERPRINT;
    typeforce(NETWORK_TYPE, network);
    this.lowR = false;
  }
  get depth() {
    return this.__DEPTH;
  }
  get index() {
    return this.__INDEX;
  }
  get parentFingerprint() {
    return this.__PARENT_FINGERPRINT;
  }
  get publicKey() {
    if (this.__Q === undefined)
      this.__Q = eccPointFromScalar(this.__D, true);
    return this.__Q;
  }
  get privateKey() {
    return this.__D;
  }
  get identifier() {
    return cryptoHash160(this.publicKey);
  }
  get fingerprint() {
    return this.identifier.slice(0, 4);
  }
  get compressed() {
    return true;
  }
  // Private === not neutered
  // Public === neutered
  isNeutered() {
    return this.__D === undefined;
  }
  neutered() {
    return fromPublicKeyLocal(this.publicKey, this.chainCode, this.network, this.depth, this.index, this.parentFingerprint);
  }
  toBase58() {
    const network = this.network;
    const version = !this.isNeutered()
      ? network.bip32.private
      : network.bip32.public;
    const buffer = Buffer.allocUnsafe(78);
    // 4 bytes: version bytes
    buffer.writeUInt32BE(version, 0);
    // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
    buffer.writeUInt8(this.depth, 4);
    // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
    buffer.writeUInt32BE(this.parentFingerprint, 5);
    // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
    // This is encoded in big endian. (0x00000000 if master key)
    buffer.writeUInt32BE(this.index, 9);
    // 32 bytes: the chain code
    this.chainCode.copy(buffer, 13);
    // 33 bytes: the public key or private key data
    if (!this.isNeutered()) {
      // 0x00 + k for private keys
      buffer.writeUInt8(0, 45);
      this.privateKey.copy(buffer, 46);
      // 33 bytes: the public key
    }
    else {
      // X9.62 encoding for public keys
      this.publicKey.copy(buffer, 45);
    }
    return bs58check.encode(buffer);
  }
  toWIF() {
    if (!this.privateKey)
      throw new TypeError('Missing private key');
    return wif.encode(this.network.wif, this.privateKey, true);
  }
  // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
  derive(index) {
    typeforce(typeforce.UInt32, index);
    const isHardened = index >= HIGHEST_BIT;
    const data = Buffer.allocUnsafe(37);
    // Hardened child
    if (isHardened) {
      if (this.isNeutered())
        throw new TypeError('Missing private key for hardened child key');
      // data = 0x00 || ser256(kpar) || ser32(index)
      data[0] = 0x00;
      this.privateKey.copy(data, 1);
      data.writeUInt32BE(index, 33);
      // Normal child
    }
    else {
      // data = serP(point(kpar)) || ser32(index)
      //      = serP(Kpar) || ser32(index)
      this.publicKey.copy(data, 0);
      data.writeUInt32BE(index, 33);
    }
    const I = cryptoHmacSHA512(this.chainCode, data);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    // if parse256(IL) >= n, proceed with the next value for i
    if (!eccIsPrivate(IL))
      return this.derive(index + 1);
    // Private parent key -> private child key
    let hd;
    if (!this.isNeutered()) {
      // ki = parse256(IL) + kpar (mod n)
      const ki = eccPrivateAdd(this.privateKey, IL);
      // In case ki == 0, proceed with the next value for i
      if (ki == null)
        return this.derive(index + 1);
      hd = bip32FromPrivateKeyLocal(ki, IR, this.network, this.depth + 1, index, this.fingerprint.readUInt32BE(0));
      // Public parent key -> public child key
    }
    else {
      // Ki = point(parse256(IL)) + Kpar
      //    = G*IL + Kpar
      const Ki = ecc.pointAddScalar(this.publicKey, IL, true);
      // In case Ki is the point at infinity, proceed with the next value for i
      if (Ki === null)
        return this.derive(index + 1);
      hd = fromPublicKeyLocal(Ki, IR, this.network, this.depth + 1, index, this.fingerprint.readUInt32BE(0));
    }
    return hd;
  }
  deriveHardened(index) {
    typeforce(UInt31, index);
    // Only derives hardened private keys by default
    return this.derive(index + HIGHEST_BIT);
  }
  derivePath(path) {
    typeforce(BIP32Path, path);
    let splitPath = path.split('/');
    if (splitPath[0] === 'm') {
      if (this.parentFingerprint)
        throw new TypeError('Expected master, got child');
      splitPath = splitPath.slice(1);
    }
    return splitPath.reduce((prevHd, indexStr) => {
      let index;
      if (indexStr.slice(-1) === `'`) {
        index = parseInt(indexStr.slice(0, -1), 10);
        return prevHd.deriveHardened(index);
      }
      else {
        index = parseInt(indexStr, 10);
        return prevHd.derive(index);
      }
    }, this);
  }
  sign(hash, lowR) {
    if (!this.privateKey)
      throw new Error('Missing private key');
    if (lowR === undefined)
      lowR = this.lowR;
    if (lowR === false) {
      return eccSign(hash, this.privateKey);
    }
    else {
      let sig = eccSign(hash, this.privateKey);
      const extraData = Buffer.alloc(32, 0);
      let counter = 0;
      // if first try is lowR, skip the loop
      // for second try and on, add extra entropy counting up
      while (sig[0] > 0x7f) {
        counter++;
        extraData.writeUIntLE(counter, 0, 6);
        sig = ecc.signWithEntropy(hash, this.privateKey, extraData);
      }
      return sig;
    }
  }
  verify(hash, signature) {
    return ecc.verify(hash, this.publicKey, signature);
  }
}

function bip32FromPrivateKeyLocal(privateKey, chainCode, network, depth, index, parentFingerprint) {
  typeforce({
    privateKey: UINT256_TYPE,
    chainCode: UINT256_TYPE,
  }, { privateKey, chainCode });
  network = network || BITCOIN;
  if (!eccIsPrivate(privateKey))
    throw new TypeError('Private key not in range [1, n)');
  return new BIP32(privateKey, undefined, chainCode, network, depth, index, parentFingerprint);
}

function bip32FromPrivateKey(privateKey, chainCode, network) {
  return bip32FromPrivateKeyLocal(privateKey, chainCode, network);
}

function cryptoHmacSHA512(key, data) {
  return createHmac('sha512', key)
    .update(data)
    .digest();
}

const BITCOIN = {
  messagePrefix: '\x18Bitcoin Signed Message:\n',
  bech32: 'bc',
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80,
};

function bip32FromBase58(inString, network) {
  const buffer = bs58check.decode(inString);
  if (buffer.length !== 78)
    throw new TypeError('Invalid buffer length');
  network = network || BITCOIN;
  // 4 bytes: version bytes
  const version = buffer.readUInt32BE(0);
  if (version !== network.bip32.private && version !== network.bip32.public)
    throw new TypeError('Invalid network version');
  // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ...
  const depth = buffer[4];
  // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  const parentFingerprint = buffer.readUInt32BE(5);
  if (depth === 0) {
    if (parentFingerprint !== 0x00000000)
      throw new TypeError('Invalid parent fingerprint');
  }
  // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  // This is encoded in MSB order. (0x00000000 if master key)
  const index = buffer.readUInt32BE(9);
  if (depth === 0 && index !== 0)
    throw new TypeError('Invalid index');
  // 32 bytes: the chain code
  const chainCode = buffer.slice(13, 45);
  let hd;
  // 33 bytes: private key data (0x00 + k)
  if (version === network.bip32.private) {
    if (buffer.readUInt8(45) !== 0x00)
      throw new TypeError('Invalid private key');
    const k = buffer.slice(46, 78);
    hd = bip32FromPrivateKeyLocal(k, chainCode, network, depth, index, parentFingerprint);
    // 33 bytes: public key data (0x02 + X or 0x03 + X)
  }
  else {
    const X = buffer.slice(45, 78);
    hd = fromPublicKeyLocal(X, chainCode, network, depth, index, parentFingerprint);
  }
  return hd;
}

function bip32FromSeed(seed, network) {
  typeforce(typeforce.Buffer, seed);
  if (seed.length < 16)
    throw new TypeError('Seed should be at least 128 bits');
  if (seed.length > 64)
    throw new TypeError('Seed should be at most 512 bits');
  network = network || BITCOIN;
  const I = cryptoHmacSHA512(Buffer.from('Bitcoin seed', 'utf8'), seed);
  const IL = I.slice(0, 32);
  const IR = I.slice(32);
  return bip32FromPrivateKey(IL, IR, network);
}

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


function basexBase(ALPHABET) {
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
  function encode(source) {
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
  function decodeUnsafe(source) {
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
  function decode(string) {
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

function bs58checkEncode(payload) {
  var checksum = checksumFn(payload)

  return base58.encode(Buffer.concat([
    payload,
    checksum
  ], payload.length + 4))
}

function bs58checkDecodeRaw(buffer) {
  var payload = buffer.slice(0, -4)
  var checksum = buffer.slice(-4)
  var newChecksum = checksumFn(payload)

  if (checksum[0] ^ newChecksum[0] |
    checksum[1] ^ newChecksum[1] |
    checksum[2] ^ newChecksum[2] |
    checksum[3] ^ newChecksum[3]) return

  return payload
}


function bs58checkDecode(string) {
  var buffer = base58.decode(string)
  var payload = bs58checkDecodeRaw(buffer, checksumFn)
  if (!payload) throw new Error('Invalid checksum')
  return payload
}

function wifDecodeRaw(buffer, version) {
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

function wifEncodeRaw(version, privateKey, compressed) {
  var result = new Buffer(compressed ? 34 : 33)

  result.writeUInt8(version, 0)
  privateKey.copy(result, 1)

  if (compressed) {
    result[33] = 0x01
  }

  return result
}

function wifDecode(string, version) {
  return wifDecodeRaw(bs58checkDecode(string), version)
}

function wifEncode(version, privateKey, compressed) {
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
  return Buffer.from(hmac(sha512_1Sha512, "bip-entropy-from-k", message))
}

function bip32XPRVToEntropy(path, xprvString) {
  const xprv = bip32FromBase58(xprvString);
  const child = xprv.derivePath(path);
  return hmacsha512(child.privateKey);
}

async function bip39MnemonicToEntropy(path, mnemonic, passphrase) {
  const bip39Seed = await bip39MnemonicToSeed(mnemonic, passphrase);
  const xprv = await bip32FromSeed(bip39Seed);
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
  bip39: async function(xprvString, language, words, index) {
    const languageIdx = languageIdxOf(language);
    const path = `m/83696968'/39'/${languageIdx}'/${words}'/${index}'`;
    const entropy = await bip32XPRVToEntropy(path, xprvString);
    const res = await entropyToBIP39(entropy, words, language);
    return res;
  },
  xprv: function(xprvString, index) {
    const path = `83696968'/32'/${index}'`;
    return bip32XPRVToXPRV(path, xprvString);
  },
  wif: async function(xprvString, index) {
    const path = `m/83696968'/2'/${index}'`;
    const entropy = await bip32XPRVToEntropy(path, xprvString);
    return entropyToWif(entropy);
  },
  hex: async function(xprvString, index, width) {
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


