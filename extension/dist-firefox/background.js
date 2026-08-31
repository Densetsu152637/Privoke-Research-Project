(() => {
  var __create = Object.create;
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getProtoOf = Object.getPrototypeOf;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __commonJS = (cb, mod) => function __require() {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
    // If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
    mod
  ));

  // node_modules/protobufjs/src/util/aspromise.js
  var require_aspromise = __commonJS({
    "node_modules/protobufjs/src/util/aspromise.js"(exports, module) {
      "use strict";
      module.exports = asPromise;
      function asPromise(fn, ctx) {
        var params = new Array(arguments.length - 1), offset = 0, index = 2, pending = true;
        while (index < arguments.length)
          params[offset++] = arguments[index++];
        return new Promise(function executor(resolve, reject) {
          params[offset] = function callback(err) {
            if (pending) {
              pending = false;
              if (err)
                reject(err);
              else {
                var params2 = new Array(arguments.length - 1), offset2 = 0;
                while (offset2 < params2.length)
                  params2[offset2++] = arguments[offset2];
                resolve.apply(null, params2);
              }
            }
          };
          try {
            fn.apply(ctx || null, params);
          } catch (err) {
            if (pending) {
              pending = false;
              reject(err);
            }
          }
        });
      }
    }
  });

  // node_modules/protobufjs/src/util/base64.js
  var require_base64 = __commonJS({
    "node_modules/protobufjs/src/util/base64.js"(exports) {
      "use strict";
      var base64 = exports;
      base64.length = function length(string) {
        var p = string.length;
        if (!p)
          return 0;
        while (p > 0 && string.charAt(p - 1) === "=")
          --p;
        return Math.floor(p * 3 / 4);
      };
      var b64 = new Array(64);
      var s64 = new Array(123);
      for (i = 0; i < 64; )
        s64[b64[i] = i < 26 ? i + 65 : i < 52 ? i + 71 : i < 62 ? i - 4 : i - 59 | 43] = i++;
      var i;
      s64[45] = 62;
      s64[95] = 63;
      base64.encode = function encode(buffer, start, end) {
        var parts = null, chunk = [];
        var i2 = 0, j = 0, t;
        while (start < end) {
          var b = buffer[start++];
          switch (j) {
            case 0:
              chunk[i2++] = b64[b >> 2];
              t = (b & 3) << 4;
              j = 1;
              break;
            case 1:
              chunk[i2++] = b64[t | b >> 4];
              t = (b & 15) << 2;
              j = 2;
              break;
            case 2:
              chunk[i2++] = b64[t | b >> 6];
              chunk[i2++] = b64[b & 63];
              j = 0;
              break;
          }
          if (i2 > 8191) {
            (parts || (parts = [])).push(String.fromCharCode.apply(String, chunk));
            i2 = 0;
          }
        }
        if (j) {
          chunk[i2++] = b64[t];
          chunk[i2++] = 61;
          if (j === 1)
            chunk[i2++] = 61;
        }
        if (parts) {
          if (i2)
            parts.push(String.fromCharCode.apply(String, chunk.slice(0, i2)));
          return parts.join("");
        }
        return String.fromCharCode.apply(String, chunk.slice(0, i2));
      };
      var invalidEncoding = "invalid encoding";
      base64.decode = function decode(string, buffer, offset) {
        var start = offset;
        var j = 0, t;
        for (var i2 = 0; i2 < string.length; ) {
          var c = string.charCodeAt(i2++);
          if (c === 61 && j > 1)
            break;
          if ((c = s64[c]) === void 0)
            throw Error(invalidEncoding);
          switch (j) {
            case 0:
              t = c;
              j = 1;
              break;
            case 1:
              buffer[offset++] = t << 2 | (c & 48) >> 4;
              t = c;
              j = 2;
              break;
            case 2:
              buffer[offset++] = (t & 15) << 4 | (c & 60) >> 2;
              t = c;
              j = 3;
              break;
            case 3:
              buffer[offset++] = (t & 3) << 6 | c;
              j = 0;
              break;
          }
        }
        if (j === 1)
          throw Error(invalidEncoding);
        return offset - start;
      };
      var base64Re = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
      var base64UrlRe = /[-_]/;
      var base64UrlNoPaddingRe = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}(?:==)?|[A-Za-z0-9_-]{3}=?)?$/;
      base64.test = function test(string) {
        return base64Re.test(string) || base64UrlRe.test(string) && base64UrlNoPaddingRe.test(string);
      };
    }
  });

  // node_modules/protobufjs/src/util/eventemitter.js
  var require_eventemitter = __commonJS({
    "node_modules/protobufjs/src/util/eventemitter.js"(exports, module) {
      "use strict";
      module.exports = EventEmitter;
      function EventEmitter() {
        this._listeners = /* @__PURE__ */ Object.create(null);
      }
      EventEmitter.prototype.on = function on(evt, fn, ctx) {
        (this._listeners[evt] || (this._listeners[evt] = [])).push({
          fn,
          ctx: ctx || this
        });
        return this;
      };
      EventEmitter.prototype.off = function off(evt, fn) {
        if (evt === void 0)
          this._listeners = /* @__PURE__ */ Object.create(null);
        else {
          if (fn === void 0)
            this._listeners[evt] = [];
          else {
            var listeners = this._listeners[evt];
            if (!listeners)
              return this;
            for (var i = 0; i < listeners.length; )
              if (listeners[i].fn === fn)
                listeners.splice(i, 1);
              else
                ++i;
          }
        }
        return this;
      };
      EventEmitter.prototype.emit = function emit(evt) {
        var listeners = this._listeners[evt];
        if (listeners) {
          var args = [], i = 1;
          for (; i < arguments.length; )
            args.push(arguments[i++]);
          for (i = 0; i < listeners.length; )
            listeners[i].fn.apply(listeners[i++].ctx, args);
        }
        return this;
      };
    }
  });

  // node_modules/protobufjs/src/util/float.js
  var require_float = __commonJS({
    "node_modules/protobufjs/src/util/float.js"(exports, module) {
      "use strict";
      module.exports = factory(factory);
      function factory(exports2) {
        if (typeof Float32Array !== "undefined") (function() {
          var f32 = new Float32Array([-0]), f8b = new Uint8Array(f32.buffer), le = f8b[3] === 128;
          function writeFloat_f32_cpy(val, buf, pos) {
            f32[0] = val;
            buf[pos] = f8b[0];
            buf[pos + 1] = f8b[1];
            buf[pos + 2] = f8b[2];
            buf[pos + 3] = f8b[3];
          }
          function writeFloat_f32_rev(val, buf, pos) {
            f32[0] = val;
            buf[pos] = f8b[3];
            buf[pos + 1] = f8b[2];
            buf[pos + 2] = f8b[1];
            buf[pos + 3] = f8b[0];
          }
          exports2.writeFloatLE = le ? writeFloat_f32_cpy : writeFloat_f32_rev;
          exports2.writeFloatBE = le ? writeFloat_f32_rev : writeFloat_f32_cpy;
          function readFloat_f32_cpy(buf, pos) {
            f8b[0] = buf[pos];
            f8b[1] = buf[pos + 1];
            f8b[2] = buf[pos + 2];
            f8b[3] = buf[pos + 3];
            return f32[0];
          }
          function readFloat_f32_rev(buf, pos) {
            f8b[3] = buf[pos];
            f8b[2] = buf[pos + 1];
            f8b[1] = buf[pos + 2];
            f8b[0] = buf[pos + 3];
            return f32[0];
          }
          exports2.readFloatLE = le ? readFloat_f32_cpy : readFloat_f32_rev;
          exports2.readFloatBE = le ? readFloat_f32_rev : readFloat_f32_cpy;
        })();
        else (function() {
          function writeFloat_ieee754(writeUint, val, buf, pos) {
            var sign = val < 0 ? 1 : 0;
            if (sign)
              val = -val;
            if (val === 0)
              writeUint(1 / val > 0 ? (
                /* positive */
                0
              ) : (
                /* negative 0 */
                2147483648
              ), buf, pos);
            else if (isNaN(val))
              writeUint(2143289344, buf, pos);
            else if (val > 34028234663852886e22)
              writeUint((sign << 31 | 2139095040) >>> 0, buf, pos);
            else if (val < 11754943508222875e-54)
              writeUint((sign << 31 | Math.round(val / 1401298464324817e-60)) >>> 0, buf, pos);
            else {
              var exponent = Math.floor(Math.log(val) / Math.LN2), mantissa = Math.round(val * Math.pow(2, -exponent) * 8388608) & 8388607;
              writeUint((sign << 31 | exponent + 127 << 23 | mantissa) >>> 0, buf, pos);
            }
          }
          exports2.writeFloatLE = writeFloat_ieee754.bind(null, writeUintLE);
          exports2.writeFloatBE = writeFloat_ieee754.bind(null, writeUintBE);
          function readFloat_ieee754(readUint, buf, pos) {
            var uint = readUint(buf, pos), sign = (uint >> 31) * 2 + 1, exponent = uint >>> 23 & 255, mantissa = uint & 8388607;
            return exponent === 255 ? mantissa ? NaN : sign * Infinity : exponent === 0 ? sign * 1401298464324817e-60 * mantissa : sign * Math.pow(2, exponent - 150) * (mantissa + 8388608);
          }
          exports2.readFloatLE = readFloat_ieee754.bind(null, readUintLE);
          exports2.readFloatBE = readFloat_ieee754.bind(null, readUintBE);
        })();
        if (typeof Float64Array !== "undefined") (function() {
          var f64 = new Float64Array([-0]), f8b = new Uint8Array(f64.buffer), le = f8b[7] === 128;
          function writeDouble_f64_cpy(val, buf, pos) {
            f64[0] = val;
            buf[pos] = f8b[0];
            buf[pos + 1] = f8b[1];
            buf[pos + 2] = f8b[2];
            buf[pos + 3] = f8b[3];
            buf[pos + 4] = f8b[4];
            buf[pos + 5] = f8b[5];
            buf[pos + 6] = f8b[6];
            buf[pos + 7] = f8b[7];
          }
          function writeDouble_f64_rev(val, buf, pos) {
            f64[0] = val;
            buf[pos] = f8b[7];
            buf[pos + 1] = f8b[6];
            buf[pos + 2] = f8b[5];
            buf[pos + 3] = f8b[4];
            buf[pos + 4] = f8b[3];
            buf[pos + 5] = f8b[2];
            buf[pos + 6] = f8b[1];
            buf[pos + 7] = f8b[0];
          }
          exports2.writeDoubleLE = le ? writeDouble_f64_cpy : writeDouble_f64_rev;
          exports2.writeDoubleBE = le ? writeDouble_f64_rev : writeDouble_f64_cpy;
          function readDouble_f64_cpy(buf, pos) {
            f8b[0] = buf[pos];
            f8b[1] = buf[pos + 1];
            f8b[2] = buf[pos + 2];
            f8b[3] = buf[pos + 3];
            f8b[4] = buf[pos + 4];
            f8b[5] = buf[pos + 5];
            f8b[6] = buf[pos + 6];
            f8b[7] = buf[pos + 7];
            return f64[0];
          }
          function readDouble_f64_rev(buf, pos) {
            f8b[7] = buf[pos];
            f8b[6] = buf[pos + 1];
            f8b[5] = buf[pos + 2];
            f8b[4] = buf[pos + 3];
            f8b[3] = buf[pos + 4];
            f8b[2] = buf[pos + 5];
            f8b[1] = buf[pos + 6];
            f8b[0] = buf[pos + 7];
            return f64[0];
          }
          exports2.readDoubleLE = le ? readDouble_f64_cpy : readDouble_f64_rev;
          exports2.readDoubleBE = le ? readDouble_f64_rev : readDouble_f64_cpy;
        })();
        else (function() {
          function writeDouble_ieee754(writeUint, off0, off1, val, buf, pos) {
            var sign = val < 0 ? 1 : 0;
            if (sign)
              val = -val;
            if (val === 0) {
              writeUint(0, buf, pos + off0);
              writeUint(1 / val > 0 ? (
                /* positive */
                0
              ) : (
                /* negative 0 */
                2147483648
              ), buf, pos + off1);
            } else if (isNaN(val)) {
              writeUint(0, buf, pos + off0);
              writeUint(2146959360, buf, pos + off1);
            } else if (val > 17976931348623157e292) {
              writeUint(0, buf, pos + off0);
              writeUint((sign << 31 | 2146435072) >>> 0, buf, pos + off1);
            } else {
              var mantissa;
              if (val < 22250738585072014e-324) {
                mantissa = val / 5e-324;
                writeUint(mantissa >>> 0, buf, pos + off0);
                writeUint((sign << 31 | mantissa / 4294967296) >>> 0, buf, pos + off1);
              } else {
                var exponent = Math.floor(Math.log(val) / Math.LN2);
                if (exponent === 1024)
                  exponent = 1023;
                mantissa = val * Math.pow(2, -exponent);
                writeUint(mantissa * 4503599627370496 >>> 0, buf, pos + off0);
                writeUint((sign << 31 | exponent + 1023 << 20 | mantissa * 1048576 & 1048575) >>> 0, buf, pos + off1);
              }
            }
          }
          exports2.writeDoubleLE = writeDouble_ieee754.bind(null, writeUintLE, 0, 4);
          exports2.writeDoubleBE = writeDouble_ieee754.bind(null, writeUintBE, 4, 0);
          function readDouble_ieee754(readUint, off0, off1, buf, pos) {
            var lo = readUint(buf, pos + off0), hi = readUint(buf, pos + off1);
            var sign = (hi >> 31) * 2 + 1, exponent = hi >>> 20 & 2047, mantissa = 4294967296 * (hi & 1048575) + lo;
            return exponent === 2047 ? mantissa ? NaN : sign * Infinity : exponent === 0 ? sign * 5e-324 * mantissa : sign * Math.pow(2, exponent - 1075) * (mantissa + 4503599627370496);
          }
          exports2.readDoubleLE = readDouble_ieee754.bind(null, readUintLE, 0, 4);
          exports2.readDoubleBE = readDouble_ieee754.bind(null, readUintBE, 4, 0);
        })();
        return exports2;
      }
      function writeUintLE(val, buf, pos) {
        buf[pos] = val & 255;
        buf[pos + 1] = val >>> 8 & 255;
        buf[pos + 2] = val >>> 16 & 255;
        buf[pos + 3] = val >>> 24;
      }
      function writeUintBE(val, buf, pos) {
        buf[pos] = val >>> 24;
        buf[pos + 1] = val >>> 16 & 255;
        buf[pos + 2] = val >>> 8 & 255;
        buf[pos + 3] = val & 255;
      }
      function readUintLE(buf, pos) {
        return (buf[pos] | buf[pos + 1] << 8 | buf[pos + 2] << 16 | buf[pos + 3] << 24) >>> 0;
      }
      function readUintBE(buf, pos) {
        return (buf[pos] << 24 | buf[pos + 1] << 16 | buf[pos + 2] << 8 | buf[pos + 3]) >>> 0;
      }
    }
  });

  // node_modules/protobufjs/src/util/utf8.js
  var require_utf8 = __commonJS({
    "node_modules/protobufjs/src/util/utf8.js"(exports) {
      "use strict";
      var utf8 = exports;
      var looseDecoder = new TextDecoder("utf-8", { ignoreBOM: true });
      var strictDecoder;
      var TEXT_DECODER_MIN_LENGTH = 64;
      try {
        strictDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
      } catch (err) {
        strictDecoder = looseDecoder;
      }
      utf8.length = function utf8_length(string) {
        var len = 0, c = 0;
        for (var i = 0; i < string.length; ++i) {
          c = string.charCodeAt(i);
          if (c < 128)
            len += 1;
          else if (c < 2048)
            len += 2;
          else if ((c & 64512) === 55296 && (string.charCodeAt(i + 1) & 64512) === 56320) {
            ++i;
            len += 4;
          } else
            len += 3;
        }
        return len;
      };
      function utf8_read_decoder(decoder, buffer, start, end) {
        var source = start === 0 && end === buffer.length ? buffer : buffer.subarray(start, end);
        return decoder.decode(source);
      }
      utf8.read = function utf8_read_loose(buffer, start, end) {
        if (end - start < 1)
          return "";
        if (end - start >= TEXT_DECODER_MIN_LENGTH)
          return utf8_read_decoder(looseDecoder, buffer, start, end);
        var str = "", i = start, c1, c2, c3, c4, c5, c6, c7, c8;
        for (; i + 7 < end; i += 8) {
          c1 = buffer[i];
          c2 = buffer[i + 1];
          c3 = buffer[i + 2];
          c4 = buffer[i + 3];
          c5 = buffer[i + 4];
          c6 = buffer[i + 5];
          c7 = buffer[i + 6];
          c8 = buffer[i + 7];
          if ((c1 | c2 | c3 | c4 | c5 | c6 | c7 | c8) & 128)
            return str + utf8_read_decoder(looseDecoder, buffer, i, end);
          str += String.fromCharCode(c1, c2, c3, c4, c5, c6, c7, c8);
        }
        for (; i < end; ++i) {
          c1 = buffer[i];
          if (c1 & 128)
            return str + utf8_read_decoder(looseDecoder, buffer, i, end);
          str += String.fromCharCode(c1);
        }
        return str;
      };
      utf8.readStrict = function utf8_read_strict(buffer, start, end) {
        if (end - start < 1)
          return "";
        if (end - start >= TEXT_DECODER_MIN_LENGTH)
          return utf8_read_decoder(strictDecoder, buffer, start, end);
        var str = "", i = start, c1, c2, c3, c4, c5, c6, c7, c8;
        for (; i + 7 < end; i += 8) {
          c1 = buffer[i];
          c2 = buffer[i + 1];
          c3 = buffer[i + 2];
          c4 = buffer[i + 3];
          c5 = buffer[i + 4];
          c6 = buffer[i + 5];
          c7 = buffer[i + 6];
          c8 = buffer[i + 7];
          if ((c1 | c2 | c3 | c4 | c5 | c6 | c7 | c8) & 128)
            return str + utf8_read_decoder(strictDecoder, buffer, i, end);
          str += String.fromCharCode(c1, c2, c3, c4, c5, c6, c7, c8);
        }
        for (; i < end; ++i) {
          c1 = buffer[i];
          if (c1 & 128)
            return str + utf8_read_decoder(strictDecoder, buffer, i, end);
          str += String.fromCharCode(c1);
        }
        return str;
      };
      utf8.write = function utf8_write(string, buffer, offset) {
        var start = offset, c1, c2;
        for (var i = 0; i < string.length; ++i) {
          c1 = string.charCodeAt(i);
          if (c1 < 128) {
            buffer[offset++] = c1;
          } else if (c1 < 2048) {
            buffer[offset++] = c1 >> 6 | 192;
            buffer[offset++] = c1 & 63 | 128;
          } else if ((c1 & 64512) === 55296 && ((c2 = string.charCodeAt(i + 1)) & 64512) === 56320) {
            c1 = 65536 + ((c1 & 1023) << 10) + (c2 & 1023);
            ++i;
            buffer[offset++] = c1 >> 18 | 240;
            buffer[offset++] = c1 >> 12 & 63 | 128;
            buffer[offset++] = c1 >> 6 & 63 | 128;
            buffer[offset++] = c1 & 63 | 128;
          } else {
            buffer[offset++] = c1 >> 12 | 224;
            buffer[offset++] = c1 >> 6 & 63 | 128;
            buffer[offset++] = c1 & 63 | 128;
          }
        }
        return offset - start;
      };
    }
  });

  // node_modules/protobufjs/src/util/pool.js
  var require_pool = __commonJS({
    "node_modules/protobufjs/src/util/pool.js"(exports, module) {
      "use strict";
      module.exports = pool;
      function pool(alloc, slice, size) {
        var SIZE = size || 8192;
        var MAX = SIZE >>> 1;
        var slab = null;
        var offset = SIZE;
        return function pool_alloc(size2) {
          if (size2 < 1 || size2 > MAX)
            return alloc(size2);
          if (offset + size2 > SIZE) {
            slab = alloc(SIZE);
            offset = 0;
          }
          var buf = slice.call(slab, offset, offset += size2);
          if (offset & 7)
            offset = (offset | 7) + 1;
          return buf;
        };
      }
    }
  });

  // node_modules/protobufjs/src/util/longbits.js
  var require_longbits = __commonJS({
    "node_modules/protobufjs/src/util/longbits.js"(exports, module) {
      "use strict";
      module.exports = LongBits;
      var Long;
      function LongBits(lo, hi) {
        this.lo = lo >>> 0;
        this.hi = hi >>> 0;
      }
      var zero = LongBits.zero = new LongBits(0, 0);
      zero.toNumber = function() {
        return 0;
      };
      zero.zzEncode = zero.zzDecode = function() {
        return this;
      };
      zero.length = function() {
        return 1;
      };
      var zeroHash = LongBits.zeroHash = "\0\0\0\0\0\0\0\0";
      LongBits.fromNumber = function fromNumber(value) {
        if (value === 0)
          return zero;
        var sign = value < 0;
        if (sign)
          value = -value;
        var lo = value >>> 0, hi = (value - lo) / 4294967296 >>> 0;
        if (sign) {
          hi = ~hi >>> 0;
          lo = ~lo >>> 0;
          if (++lo > 4294967295) {
            lo = 0;
            if (++hi > 4294967295)
              hi = 0;
          }
        }
        return new LongBits(lo, hi);
      };
      LongBits.from = function from(value) {
        if (typeof value === "number")
          return LongBits.fromNumber(value);
        if (typeof value === "string" || value instanceof String) {
          if (Long)
            value = Long.fromString(value);
          else
            return LongBits.fromNumber(parseInt(value, 10));
        }
        return value.low || value.high ? new LongBits(value.low >>> 0, value.high >>> 0) : zero;
      };
      LongBits.prototype.toNumber = function toNumber(unsigned) {
        if (!unsigned && this.hi >>> 31) {
          var lo = ~this.lo + 1 >>> 0, hi = ~this.hi >>> 0;
          if (!lo)
            hi = hi + 1 >>> 0;
          return -(lo + hi * 4294967296);
        }
        return this.lo + this.hi * 4294967296;
      };
      LongBits.prototype.toLong = function toLong(unsigned) {
        return Long ? new Long(this.lo | 0, this.hi | 0, Boolean(unsigned)) : { low: this.lo | 0, high: this.hi | 0, unsigned: Boolean(unsigned) };
      };
      var charCodeAt = String.prototype.charCodeAt;
      LongBits.fromHash = function fromHash(hash) {
        if (hash === zeroHash)
          return zero;
        return new LongBits(
          (charCodeAt.call(hash, 0) | charCodeAt.call(hash, 1) << 8 | charCodeAt.call(hash, 2) << 16 | charCodeAt.call(hash, 3) << 24) >>> 0,
          (charCodeAt.call(hash, 4) | charCodeAt.call(hash, 5) << 8 | charCodeAt.call(hash, 6) << 16 | charCodeAt.call(hash, 7) << 24) >>> 0
        );
      };
      LongBits.prototype.toHash = function toHash() {
        return String.fromCharCode(
          this.lo & 255,
          this.lo >>> 8 & 255,
          this.lo >>> 16 & 255,
          this.lo >>> 24,
          this.hi & 255,
          this.hi >>> 8 & 255,
          this.hi >>> 16 & 255,
          this.hi >>> 24
        );
      };
      LongBits.prototype.zzEncode = function zzEncode() {
        var mask = this.hi >> 31;
        this.hi = ((this.hi << 1 | this.lo >>> 31) ^ mask) >>> 0;
        this.lo = (this.lo << 1 ^ mask) >>> 0;
        return this;
      };
      LongBits.prototype.zzDecode = function zzDecode() {
        var mask = -(this.lo & 1);
        this.lo = ((this.lo >>> 1 | this.hi << 31) ^ mask) >>> 0;
        this.hi = (this.hi >>> 1 ^ mask) >>> 0;
        return this;
      };
      LongBits.prototype.length = function length() {
        var part0 = this.lo, part1 = (this.lo >>> 28 | this.hi << 4) >>> 0, part2 = this.hi >>> 24;
        return part2 === 0 ? part1 === 0 ? part0 < 16384 ? part0 < 128 ? 1 : 2 : part0 < 2097152 ? 3 : 4 : part1 < 16384 ? part1 < 128 ? 5 : 6 : part1 < 2097152 ? 7 : 8 : part2 < 128 ? 9 : 10;
      };
      LongBits._configure = function(Long_) {
        Long = Long_;
      };
    }
  });

  // node_modules/long/umd/index.js
  var require_umd = __commonJS({
    "node_modules/long/umd/index.js"(exports, module) {
      (function(global2, factory) {
        function preferDefault(exports2) {
          return exports2.default || exports2;
        }
        if (typeof define === "function" && define.amd) {
          define([], function() {
            var exports2 = {};
            factory(exports2);
            return preferDefault(exports2);
          });
        } else if (typeof exports === "object") {
          factory(exports);
          if (typeof module === "object") module.exports = preferDefault(exports);
        } else {
          (function() {
            var exports2 = {};
            factory(exports2);
            global2.Long = preferDefault(exports2);
          })();
        }
      })(
        typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : exports,
        function(_exports) {
          "use strict";
          Object.defineProperty(_exports, "__esModule", {
            value: true
          });
          _exports.default = void 0;
          var wasm = null;
          try {
            wasm = new WebAssembly.Instance(
              new WebAssembly.Module(
                new Uint8Array([
                  // \0asm
                  0,
                  97,
                  115,
                  109,
                  // version 1
                  1,
                  0,
                  0,
                  0,
                  // section "type"
                  1,
                  13,
                  2,
                  // 0, () => i32
                  96,
                  0,
                  1,
                  127,
                  // 1, (i32, i32, i32, i32) => i32
                  96,
                  4,
                  127,
                  127,
                  127,
                  127,
                  1,
                  127,
                  // section "function"
                  3,
                  7,
                  6,
                  // 0, type 0
                  0,
                  // 1, type 1
                  1,
                  // 2, type 1
                  1,
                  // 3, type 1
                  1,
                  // 4, type 1
                  1,
                  // 5, type 1
                  1,
                  // section "global"
                  6,
                  6,
                  1,
                  // 0, "high", mutable i32
                  127,
                  1,
                  65,
                  0,
                  11,
                  // section "export"
                  7,
                  50,
                  6,
                  // 0, "mul"
                  3,
                  109,
                  117,
                  108,
                  0,
                  1,
                  // 1, "div_s"
                  5,
                  100,
                  105,
                  118,
                  95,
                  115,
                  0,
                  2,
                  // 2, "div_u"
                  5,
                  100,
                  105,
                  118,
                  95,
                  117,
                  0,
                  3,
                  // 3, "rem_s"
                  5,
                  114,
                  101,
                  109,
                  95,
                  115,
                  0,
                  4,
                  // 4, "rem_u"
                  5,
                  114,
                  101,
                  109,
                  95,
                  117,
                  0,
                  5,
                  // 5, "get_high"
                  8,
                  103,
                  101,
                  116,
                  95,
                  104,
                  105,
                  103,
                  104,
                  0,
                  0,
                  // section "code"
                  10,
                  191,
                  1,
                  6,
                  // 0, "get_high"
                  4,
                  0,
                  35,
                  0,
                  11,
                  // 1, "mul"
                  36,
                  1,
                  1,
                  126,
                  32,
                  0,
                  173,
                  32,
                  1,
                  173,
                  66,
                  32,
                  134,
                  132,
                  32,
                  2,
                  173,
                  32,
                  3,
                  173,
                  66,
                  32,
                  134,
                  132,
                  126,
                  34,
                  4,
                  66,
                  32,
                  135,
                  167,
                  36,
                  0,
                  32,
                  4,
                  167,
                  11,
                  // 2, "div_s"
                  36,
                  1,
                  1,
                  126,
                  32,
                  0,
                  173,
                  32,
                  1,
                  173,
                  66,
                  32,
                  134,
                  132,
                  32,
                  2,
                  173,
                  32,
                  3,
                  173,
                  66,
                  32,
                  134,
                  132,
                  127,
                  34,
                  4,
                  66,
                  32,
                  135,
                  167,
                  36,
                  0,
                  32,
                  4,
                  167,
                  11,
                  // 3, "div_u"
                  36,
                  1,
                  1,
                  126,
                  32,
                  0,
                  173,
                  32,
                  1,
                  173,
                  66,
                  32,
                  134,
                  132,
                  32,
                  2,
                  173,
                  32,
                  3,
                  173,
                  66,
                  32,
                  134,
                  132,
                  128,
                  34,
                  4,
                  66,
                  32,
                  135,
                  167,
                  36,
                  0,
                  32,
                  4,
                  167,
                  11,
                  // 4, "rem_s"
                  36,
                  1,
                  1,
                  126,
                  32,
                  0,
                  173,
                  32,
                  1,
                  173,
                  66,
                  32,
                  134,
                  132,
                  32,
                  2,
                  173,
                  32,
                  3,
                  173,
                  66,
                  32,
                  134,
                  132,
                  129,
                  34,
                  4,
                  66,
                  32,
                  135,
                  167,
                  36,
                  0,
                  32,
                  4,
                  167,
                  11,
                  // 5, "rem_u"
                  36,
                  1,
                  1,
                  126,
                  32,
                  0,
                  173,
                  32,
                  1,
                  173,
                  66,
                  32,
                  134,
                  132,
                  32,
                  2,
                  173,
                  32,
                  3,
                  173,
                  66,
                  32,
                  134,
                  132,
                  130,
                  34,
                  4,
                  66,
                  32,
                  135,
                  167,
                  36,
                  0,
                  32,
                  4,
                  167,
                  11
                ])
              ),
              {}
            ).exports;
          } catch {
          }
          function Long(low, high, unsigned) {
            this.low = low | 0;
            this.high = high | 0;
            this.unsigned = !!unsigned;
          }
          Long.prototype.__isLong__;
          Object.defineProperty(Long.prototype, "__isLong__", {
            value: true
          });
          function isLong(obj) {
            return (obj && obj["__isLong__"]) === true;
          }
          function ctz32(value) {
            var c = Math.clz32(value & -value);
            return value ? 31 - c : c;
          }
          Long.isLong = isLong;
          var INT_CACHE = {};
          var UINT_CACHE = {};
          function fromInt(value, unsigned) {
            var obj, cachedObj, cache;
            if (unsigned) {
              value >>>= 0;
              if (cache = 0 <= value && value < 256) {
                cachedObj = UINT_CACHE[value];
                if (cachedObj) return cachedObj;
              }
              obj = fromBits(value, 0, true);
              if (cache) UINT_CACHE[value] = obj;
              return obj;
            } else {
              value |= 0;
              if (cache = -128 <= value && value < 128) {
                cachedObj = INT_CACHE[value];
                if (cachedObj) return cachedObj;
              }
              obj = fromBits(value, value < 0 ? -1 : 0, false);
              if (cache) INT_CACHE[value] = obj;
              return obj;
            }
          }
          Long.fromInt = fromInt;
          function fromNumber(value, unsigned) {
            if (isNaN(value)) return unsigned ? UZERO : ZERO;
            if (unsigned) {
              if (value < 0) return UZERO;
              if (value >= TWO_PWR_64_DBL) return MAX_UNSIGNED_VALUE;
            } else {
              if (value <= -TWO_PWR_63_DBL) return MIN_VALUE;
              if (value + 1 >= TWO_PWR_63_DBL) return MAX_VALUE;
            }
            if (value < 0) return fromNumber(-value, unsigned).neg();
            return fromBits(
              value % TWO_PWR_32_DBL | 0,
              value / TWO_PWR_32_DBL | 0,
              unsigned
            );
          }
          Long.fromNumber = fromNumber;
          function fromBits(lowBits, highBits, unsigned) {
            return new Long(lowBits, highBits, unsigned);
          }
          Long.fromBits = fromBits;
          var pow_dbl = Math.pow;
          function fromString(str, unsigned, radix) {
            if (str.length === 0) throw Error("empty string");
            if (typeof unsigned === "number") {
              radix = unsigned;
              unsigned = false;
            } else {
              unsigned = !!unsigned;
            }
            if (str === "NaN" || str === "Infinity" || str === "+Infinity" || str === "-Infinity")
              return unsigned ? UZERO : ZERO;
            radix = radix || 10;
            if (radix < 2 || 36 < radix) throw RangeError("radix");
            var p;
            if ((p = str.indexOf("-")) > 0) throw Error("interior hyphen");
            else if (p === 0) {
              return fromString(str.substring(1), unsigned, radix).neg();
            }
            var radixToPower = fromNumber(pow_dbl(radix, 8));
            var result = ZERO;
            for (var i = 0; i < str.length; i += 8) {
              var size = Math.min(8, str.length - i), value = parseInt(str.substring(i, i + size), radix);
              if (size < 8) {
                var power = fromNumber(pow_dbl(radix, size));
                result = result.mul(power).add(fromNumber(value));
              } else {
                result = result.mul(radixToPower);
                result = result.add(fromNumber(value));
              }
            }
            result.unsigned = unsigned;
            return result;
          }
          Long.fromString = fromString;
          function fromValue(val, unsigned) {
            if (typeof val === "number") return fromNumber(val, unsigned);
            if (typeof val === "string") return fromString(val, unsigned);
            return fromBits(
              val.low,
              val.high,
              typeof unsigned === "boolean" ? unsigned : val.unsigned
            );
          }
          Long.fromValue = fromValue;
          var TWO_PWR_16_DBL = 1 << 16;
          var TWO_PWR_24_DBL = 1 << 24;
          var TWO_PWR_32_DBL = TWO_PWR_16_DBL * TWO_PWR_16_DBL;
          var TWO_PWR_64_DBL = TWO_PWR_32_DBL * TWO_PWR_32_DBL;
          var TWO_PWR_63_DBL = TWO_PWR_64_DBL / 2;
          var TWO_PWR_24 = fromInt(TWO_PWR_24_DBL);
          var ZERO = fromInt(0);
          Long.ZERO = ZERO;
          var UZERO = fromInt(0, true);
          Long.UZERO = UZERO;
          var ONE = fromInt(1);
          Long.ONE = ONE;
          var UONE = fromInt(1, true);
          Long.UONE = UONE;
          var NEG_ONE = fromInt(-1);
          Long.NEG_ONE = NEG_ONE;
          var MAX_VALUE = fromBits(4294967295 | 0, 2147483647 | 0, false);
          Long.MAX_VALUE = MAX_VALUE;
          var MAX_UNSIGNED_VALUE = fromBits(4294967295 | 0, 4294967295 | 0, true);
          Long.MAX_UNSIGNED_VALUE = MAX_UNSIGNED_VALUE;
          var MIN_VALUE = fromBits(0, 2147483648 | 0, false);
          Long.MIN_VALUE = MIN_VALUE;
          var LongPrototype = Long.prototype;
          LongPrototype.toInt = function toInt() {
            return this.unsigned ? this.low >>> 0 : this.low;
          };
          LongPrototype.toNumber = function toNumber() {
            if (this.unsigned)
              return (this.high >>> 0) * TWO_PWR_32_DBL + (this.low >>> 0);
            return this.high * TWO_PWR_32_DBL + (this.low >>> 0);
          };
          LongPrototype.toString = function toString(radix) {
            radix = radix || 10;
            if (radix < 2 || 36 < radix) throw RangeError("radix");
            if (this.isZero()) return "0";
            if (this.isNegative()) {
              if (this.eq(MIN_VALUE)) {
                var radixLong = fromNumber(radix), div = this.div(radixLong), rem1 = div.mul(radixLong).sub(this);
                return div.toString(radix) + rem1.toInt().toString(radix);
              } else return "-" + this.neg().toString(radix);
            }
            var radixToPower = fromNumber(pow_dbl(radix, 6), this.unsigned), rem = this;
            var result = "";
            while (true) {
              var remDiv = rem.div(radixToPower), intval = rem.sub(remDiv.mul(radixToPower)).toInt() >>> 0, digits = intval.toString(radix);
              rem = remDiv;
              if (rem.isZero()) return digits + result;
              else {
                while (digits.length < 6) digits = "0" + digits;
                result = "" + digits + result;
              }
            }
          };
          LongPrototype.getHighBits = function getHighBits() {
            return this.high;
          };
          LongPrototype.getHighBitsUnsigned = function getHighBitsUnsigned() {
            return this.high >>> 0;
          };
          LongPrototype.getLowBits = function getLowBits() {
            return this.low;
          };
          LongPrototype.getLowBitsUnsigned = function getLowBitsUnsigned() {
            return this.low >>> 0;
          };
          LongPrototype.getNumBitsAbs = function getNumBitsAbs() {
            if (this.isNegative())
              return this.eq(MIN_VALUE) ? 64 : this.neg().getNumBitsAbs();
            var val = this.high != 0 ? this.high : this.low;
            for (var bit = 31; bit > 0; bit--) if ((val & 1 << bit) != 0) break;
            return this.high != 0 ? bit + 33 : bit + 1;
          };
          LongPrototype.isSafeInteger = function isSafeInteger() {
            var top11Bits = this.high >> 21;
            if (!top11Bits) return true;
            if (this.unsigned) return false;
            return top11Bits === -1 && !(this.low === 0 && this.high === -2097152);
          };
          LongPrototype.isZero = function isZero() {
            return this.high === 0 && this.low === 0;
          };
          LongPrototype.eqz = LongPrototype.isZero;
          LongPrototype.isNegative = function isNegative() {
            return !this.unsigned && this.high < 0;
          };
          LongPrototype.isPositive = function isPositive() {
            return this.unsigned || this.high >= 0;
          };
          LongPrototype.isOdd = function isOdd() {
            return (this.low & 1) === 1;
          };
          LongPrototype.isEven = function isEven() {
            return (this.low & 1) === 0;
          };
          LongPrototype.equals = function equals(other) {
            if (!isLong(other)) other = fromValue(other);
            if (this.unsigned !== other.unsigned && this.high >>> 31 === 1 && other.high >>> 31 === 1)
              return false;
            return this.high === other.high && this.low === other.low;
          };
          LongPrototype.eq = LongPrototype.equals;
          LongPrototype.notEquals = function notEquals(other) {
            return !this.eq(
              /* validates */
              other
            );
          };
          LongPrototype.neq = LongPrototype.notEquals;
          LongPrototype.ne = LongPrototype.notEquals;
          LongPrototype.lessThan = function lessThan(other) {
            return this.comp(
              /* validates */
              other
            ) < 0;
          };
          LongPrototype.lt = LongPrototype.lessThan;
          LongPrototype.lessThanOrEqual = function lessThanOrEqual(other) {
            return this.comp(
              /* validates */
              other
            ) <= 0;
          };
          LongPrototype.lte = LongPrototype.lessThanOrEqual;
          LongPrototype.le = LongPrototype.lessThanOrEqual;
          LongPrototype.greaterThan = function greaterThan(other) {
            return this.comp(
              /* validates */
              other
            ) > 0;
          };
          LongPrototype.gt = LongPrototype.greaterThan;
          LongPrototype.greaterThanOrEqual = function greaterThanOrEqual(other) {
            return this.comp(
              /* validates */
              other
            ) >= 0;
          };
          LongPrototype.gte = LongPrototype.greaterThanOrEqual;
          LongPrototype.ge = LongPrototype.greaterThanOrEqual;
          LongPrototype.compare = function compare(other) {
            if (!isLong(other)) other = fromValue(other);
            if (this.eq(other)) return 0;
            var thisNeg = this.isNegative(), otherNeg = other.isNegative();
            if (thisNeg && !otherNeg) return -1;
            if (!thisNeg && otherNeg) return 1;
            if (!this.unsigned) return this.sub(other).isNegative() ? -1 : 1;
            return other.high >>> 0 > this.high >>> 0 || other.high === this.high && other.low >>> 0 > this.low >>> 0 ? -1 : 1;
          };
          LongPrototype.comp = LongPrototype.compare;
          LongPrototype.negate = function negate() {
            if (!this.unsigned && this.eq(MIN_VALUE)) return MIN_VALUE;
            return this.not().add(ONE);
          };
          LongPrototype.neg = LongPrototype.negate;
          LongPrototype.add = function add(addend) {
            if (!isLong(addend)) addend = fromValue(addend);
            var a48 = this.high >>> 16;
            var a32 = this.high & 65535;
            var a16 = this.low >>> 16;
            var a00 = this.low & 65535;
            var b48 = addend.high >>> 16;
            var b32 = addend.high & 65535;
            var b16 = addend.low >>> 16;
            var b00 = addend.low & 65535;
            var c48 = 0, c32 = 0, c16 = 0, c00 = 0;
            c00 += a00 + b00;
            c16 += c00 >>> 16;
            c00 &= 65535;
            c16 += a16 + b16;
            c32 += c16 >>> 16;
            c16 &= 65535;
            c32 += a32 + b32;
            c48 += c32 >>> 16;
            c32 &= 65535;
            c48 += a48 + b48;
            c48 &= 65535;
            return fromBits(c16 << 16 | c00, c48 << 16 | c32, this.unsigned);
          };
          LongPrototype.subtract = function subtract(subtrahend) {
            if (!isLong(subtrahend)) subtrahend = fromValue(subtrahend);
            return this.add(subtrahend.neg());
          };
          LongPrototype.sub = LongPrototype.subtract;
          LongPrototype.multiply = function multiply(multiplier) {
            if (this.isZero()) return this;
            if (!isLong(multiplier)) multiplier = fromValue(multiplier);
            if (wasm) {
              var low = wasm["mul"](
                this.low,
                this.high,
                multiplier.low,
                multiplier.high
              );
              return fromBits(low, wasm["get_high"](), this.unsigned);
            }
            if (multiplier.isZero()) return this.unsigned ? UZERO : ZERO;
            if (this.eq(MIN_VALUE)) return multiplier.isOdd() ? MIN_VALUE : ZERO;
            if (multiplier.eq(MIN_VALUE)) return this.isOdd() ? MIN_VALUE : ZERO;
            if (this.isNegative()) {
              if (multiplier.isNegative()) return this.neg().mul(multiplier.neg());
              else return this.neg().mul(multiplier).neg();
            } else if (multiplier.isNegative())
              return this.mul(multiplier.neg()).neg();
            if (this.lt(TWO_PWR_24) && multiplier.lt(TWO_PWR_24))
              return fromNumber(
                this.toNumber() * multiplier.toNumber(),
                this.unsigned
              );
            var a48 = this.high >>> 16;
            var a32 = this.high & 65535;
            var a16 = this.low >>> 16;
            var a00 = this.low & 65535;
            var b48 = multiplier.high >>> 16;
            var b32 = multiplier.high & 65535;
            var b16 = multiplier.low >>> 16;
            var b00 = multiplier.low & 65535;
            var c48 = 0, c32 = 0, c16 = 0, c00 = 0;
            c00 += a00 * b00;
            c16 += c00 >>> 16;
            c00 &= 65535;
            c16 += a16 * b00;
            c32 += c16 >>> 16;
            c16 &= 65535;
            c16 += a00 * b16;
            c32 += c16 >>> 16;
            c16 &= 65535;
            c32 += a32 * b00;
            c48 += c32 >>> 16;
            c32 &= 65535;
            c32 += a16 * b16;
            c48 += c32 >>> 16;
            c32 &= 65535;
            c32 += a00 * b32;
            c48 += c32 >>> 16;
            c32 &= 65535;
            c48 += a48 * b00 + a32 * b16 + a16 * b32 + a00 * b48;
            c48 &= 65535;
            return fromBits(c16 << 16 | c00, c48 << 16 | c32, this.unsigned);
          };
          LongPrototype.mul = LongPrototype.multiply;
          LongPrototype.divide = function divide(divisor) {
            if (!isLong(divisor)) divisor = fromValue(divisor);
            if (divisor.isZero()) throw Error("division by zero");
            if (wasm) {
              if (!this.unsigned && this.high === -2147483648 && divisor.low === -1 && divisor.high === -1) {
                return this;
              }
              var low = (this.unsigned ? wasm["div_u"] : wasm["div_s"])(
                this.low,
                this.high,
                divisor.low,
                divisor.high
              );
              return fromBits(low, wasm["get_high"](), this.unsigned);
            }
            if (this.isZero()) return this.unsigned ? UZERO : ZERO;
            var approx, rem, res;
            if (!this.unsigned) {
              if (this.eq(MIN_VALUE)) {
                if (divisor.eq(ONE) || divisor.eq(NEG_ONE))
                  return MIN_VALUE;
                else if (divisor.eq(MIN_VALUE)) return ONE;
                else {
                  var halfThis = this.shr(1);
                  approx = halfThis.div(divisor).shl(1);
                  if (approx.eq(ZERO)) {
                    return divisor.isNegative() ? ONE : NEG_ONE;
                  } else {
                    rem = this.sub(divisor.mul(approx));
                    res = approx.add(rem.div(divisor));
                    return res;
                  }
                }
              } else if (divisor.eq(MIN_VALUE)) return this.unsigned ? UZERO : ZERO;
              if (this.isNegative()) {
                if (divisor.isNegative()) return this.neg().div(divisor.neg());
                return this.neg().div(divisor).neg();
              } else if (divisor.isNegative()) return this.div(divisor.neg()).neg();
              res = ZERO;
            } else {
              if (!divisor.unsigned) divisor = divisor.toUnsigned();
              if (divisor.gt(this)) return UZERO;
              if (divisor.gt(this.shru(1)))
                return UONE;
              res = UZERO;
            }
            rem = this;
            while (rem.gte(divisor)) {
              approx = Math.max(1, Math.floor(rem.toNumber() / divisor.toNumber()));
              var log2 = Math.ceil(Math.log(approx) / Math.LN2), delta = log2 <= 48 ? 1 : pow_dbl(2, log2 - 48), approxRes = fromNumber(approx), approxRem = approxRes.mul(divisor);
              while (approxRem.isNegative() || approxRem.gt(rem)) {
                approx -= delta;
                approxRes = fromNumber(approx, this.unsigned);
                approxRem = approxRes.mul(divisor);
              }
              if (approxRes.isZero()) approxRes = ONE;
              res = res.add(approxRes);
              rem = rem.sub(approxRem);
            }
            return res;
          };
          LongPrototype.div = LongPrototype.divide;
          LongPrototype.modulo = function modulo(divisor) {
            if (!isLong(divisor)) divisor = fromValue(divisor);
            if (wasm) {
              var low = (this.unsigned ? wasm["rem_u"] : wasm["rem_s"])(
                this.low,
                this.high,
                divisor.low,
                divisor.high
              );
              return fromBits(low, wasm["get_high"](), this.unsigned);
            }
            return this.sub(this.div(divisor).mul(divisor));
          };
          LongPrototype.mod = LongPrototype.modulo;
          LongPrototype.rem = LongPrototype.modulo;
          LongPrototype.not = function not() {
            return fromBits(~this.low, ~this.high, this.unsigned);
          };
          LongPrototype.countLeadingZeros = function countLeadingZeros() {
            return this.high ? Math.clz32(this.high) : Math.clz32(this.low) + 32;
          };
          LongPrototype.clz = LongPrototype.countLeadingZeros;
          LongPrototype.countTrailingZeros = function countTrailingZeros() {
            return this.low ? ctz32(this.low) : ctz32(this.high) + 32;
          };
          LongPrototype.ctz = LongPrototype.countTrailingZeros;
          LongPrototype.and = function and(other) {
            if (!isLong(other)) other = fromValue(other);
            return fromBits(
              this.low & other.low,
              this.high & other.high,
              this.unsigned
            );
          };
          LongPrototype.or = function or(other) {
            if (!isLong(other)) other = fromValue(other);
            return fromBits(
              this.low | other.low,
              this.high | other.high,
              this.unsigned
            );
          };
          LongPrototype.xor = function xor(other) {
            if (!isLong(other)) other = fromValue(other);
            return fromBits(
              this.low ^ other.low,
              this.high ^ other.high,
              this.unsigned
            );
          };
          LongPrototype.shiftLeft = function shiftLeft(numBits) {
            if (isLong(numBits)) numBits = numBits.toInt();
            if ((numBits &= 63) === 0) return this;
            else if (numBits < 32)
              return fromBits(
                this.low << numBits,
                this.high << numBits | this.low >>> 32 - numBits,
                this.unsigned
              );
            else return fromBits(0, this.low << numBits - 32, this.unsigned);
          };
          LongPrototype.shl = LongPrototype.shiftLeft;
          LongPrototype.shiftRight = function shiftRight(numBits) {
            if (isLong(numBits)) numBits = numBits.toInt();
            if ((numBits &= 63) === 0) return this;
            else if (numBits < 32)
              return fromBits(
                this.low >>> numBits | this.high << 32 - numBits,
                this.high >> numBits,
                this.unsigned
              );
            else
              return fromBits(
                this.high >> numBits - 32,
                this.high >= 0 ? 0 : -1,
                this.unsigned
              );
          };
          LongPrototype.shr = LongPrototype.shiftRight;
          LongPrototype.shiftRightUnsigned = function shiftRightUnsigned(numBits) {
            if (isLong(numBits)) numBits = numBits.toInt();
            if ((numBits &= 63) === 0) return this;
            if (numBits < 32)
              return fromBits(
                this.low >>> numBits | this.high << 32 - numBits,
                this.high >>> numBits,
                this.unsigned
              );
            if (numBits === 32) return fromBits(this.high, 0, this.unsigned);
            return fromBits(this.high >>> numBits - 32, 0, this.unsigned);
          };
          LongPrototype.shru = LongPrototype.shiftRightUnsigned;
          LongPrototype.shr_u = LongPrototype.shiftRightUnsigned;
          LongPrototype.rotateLeft = function rotateLeft(numBits) {
            var b;
            if (isLong(numBits)) numBits = numBits.toInt();
            if ((numBits &= 63) === 0) return this;
            if (numBits === 32) return fromBits(this.high, this.low, this.unsigned);
            if (numBits < 32) {
              b = 32 - numBits;
              return fromBits(
                this.low << numBits | this.high >>> b,
                this.high << numBits | this.low >>> b,
                this.unsigned
              );
            }
            numBits -= 32;
            b = 32 - numBits;
            return fromBits(
              this.high << numBits | this.low >>> b,
              this.low << numBits | this.high >>> b,
              this.unsigned
            );
          };
          LongPrototype.rotl = LongPrototype.rotateLeft;
          LongPrototype.rotateRight = function rotateRight(numBits) {
            var b;
            if (isLong(numBits)) numBits = numBits.toInt();
            if ((numBits &= 63) === 0) return this;
            if (numBits === 32) return fromBits(this.high, this.low, this.unsigned);
            if (numBits < 32) {
              b = 32 - numBits;
              return fromBits(
                this.high << b | this.low >>> numBits,
                this.low << b | this.high >>> numBits,
                this.unsigned
              );
            }
            numBits -= 32;
            b = 32 - numBits;
            return fromBits(
              this.low << b | this.high >>> numBits,
              this.high << b | this.low >>> numBits,
              this.unsigned
            );
          };
          LongPrototype.rotr = LongPrototype.rotateRight;
          LongPrototype.toSigned = function toSigned() {
            if (!this.unsigned) return this;
            return fromBits(this.low, this.high, false);
          };
          LongPrototype.toUnsigned = function toUnsigned() {
            if (this.unsigned) return this;
            return fromBits(this.low, this.high, true);
          };
          LongPrototype.toBytes = function toBytes(le) {
            return le ? this.toBytesLE() : this.toBytesBE();
          };
          LongPrototype.toBytesLE = function toBytesLE() {
            var hi = this.high, lo = this.low;
            return [
              lo & 255,
              lo >>> 8 & 255,
              lo >>> 16 & 255,
              lo >>> 24,
              hi & 255,
              hi >>> 8 & 255,
              hi >>> 16 & 255,
              hi >>> 24
            ];
          };
          LongPrototype.toBytesBE = function toBytesBE() {
            var hi = this.high, lo = this.low;
            return [
              hi >>> 24,
              hi >>> 16 & 255,
              hi >>> 8 & 255,
              hi & 255,
              lo >>> 24,
              lo >>> 16 & 255,
              lo >>> 8 & 255,
              lo & 255
            ];
          };
          Long.fromBytes = function fromBytes(bytes, unsigned, le) {
            return le ? Long.fromBytesLE(bytes, unsigned) : Long.fromBytesBE(bytes, unsigned);
          };
          Long.fromBytesLE = function fromBytesLE(bytes, unsigned) {
            return new Long(
              bytes[0] | bytes[1] << 8 | bytes[2] << 16 | bytes[3] << 24,
              bytes[4] | bytes[5] << 8 | bytes[6] << 16 | bytes[7] << 24,
              unsigned
            );
          };
          Long.fromBytesBE = function fromBytesBE(bytes, unsigned) {
            return new Long(
              bytes[4] << 24 | bytes[5] << 16 | bytes[6] << 8 | bytes[7],
              bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3],
              unsigned
            );
          };
          if (typeof BigInt === "function") {
            Long.fromBigInt = function fromBigInt(value, unsigned) {
              var lowBits = Number(BigInt.asIntN(32, value));
              var highBits = Number(BigInt.asIntN(32, value >> BigInt(32)));
              return fromBits(lowBits, highBits, unsigned);
            };
            Long.fromValue = function fromValueWithBigInt(value, unsigned) {
              if (typeof value === "bigint") return Long.fromBigInt(value, unsigned);
              return fromValue(value, unsigned);
            };
            LongPrototype.toBigInt = function toBigInt() {
              var lowBigInt = BigInt(this.low >>> 0);
              var highBigInt = BigInt(this.unsigned ? this.high >>> 0 : this.high);
              return highBigInt << BigInt(32) | lowBigInt;
            };
          }
          var _default = _exports.default = Long;
        }
      );
    }
  });

  // node_modules/protobufjs/src/util/minimal.js
  var require_minimal = __commonJS({
    "node_modules/protobufjs/src/util/minimal.js"(exports) {
      "use strict";
      var util = exports;
      util.asPromise = require_aspromise();
      util.base64 = require_base64();
      util.EventEmitter = require_eventemitter();
      util.float = require_float();
      util.utf8 = require_utf8();
      util.pool = require_pool();
      util.LongBits = require_longbits();
      function isUnsafeProperty(key) {
        return key === "__proto__" || key === "prototype" || key === "constructor";
      }
      util.isUnsafeProperty = isUnsafeProperty;
      util.isNode = Boolean(typeof global !== "undefined" && global && global.process && global.process.versions && global.process.versions.node);
      util.global = util.isNode && global || typeof window !== "undefined" && window || typeof self !== "undefined" && self || typeof globalThis !== "undefined" && globalThis || exports;
      util.emptyArray = Object.freeze ? Object.freeze([]) : (
        /* istanbul ignore next */
        []
      );
      util.emptyObject = Object.freeze ? Object.freeze({}) : (
        /* istanbul ignore next */
        {}
      );
      util.isInteger = Number.isInteger || /* istanbul ignore next */
      function isInteger(value) {
        return typeof value === "number" && isFinite(value) && Math.floor(value) === value;
      };
      util.isString = function isString(value) {
        return typeof value === "string" || value instanceof String;
      };
      util.isObject = function isObject(value) {
        return value && typeof value === "object";
      };
      util.isset = /**
       * Checks if a property on a message is considered to be present.
       * @param {Object} obj Plain object or message instance
       * @param {string} prop Property name
       * @returns {boolean} `true` if considered to be present, otherwise `false`
       */
      util.isSet = function isSet(obj, prop) {
        var value = obj[prop];
        if (value != null && Object.hasOwnProperty.call(obj, prop))
          return typeof value !== "object" || (Array.isArray(value) ? value.length : Object.keys(value).length) > 0;
        return false;
      };
      util.Buffer = (function() {
        try {
          var Buffer2 = util.global.Buffer;
          return Buffer2.prototype.utf8Write || util.isNode ? Buffer2 : (
            /* istanbul ignore next */
            null
          );
        } catch (e) {
          return null;
        }
      })();
      util.newBuffer = function newBuffer(sizeOrArray) {
        var Buffer2 = util.Buffer;
        return typeof sizeOrArray === "number" ? Buffer2 ? Buffer2.allocUnsafe(sizeOrArray) : new Uint8Array(sizeOrArray) : Buffer2 ? Buffer2.from(sizeOrArray) : new Uint8Array(sizeOrArray);
      };
      util.rawField = function rawField(id, wireType, data) {
        var out = [], tag = id << 3 | wireType;
        tag >>>= 0;
        while (tag > 127) {
          out.push(tag & 127 | 128);
          tag >>>= 7;
        }
        out.push(tag);
        for (var i = 0; i < data.length; ++i)
          out.push(data[i]);
        return util.newBuffer(out);
      };
      util.Array = Uint8Array;
      util.Long = /* istanbul ignore next */
      util.global.dcodeIO && /* istanbul ignore next */
      util.global.dcodeIO.Long || /* istanbul ignore next */
      util.global.Long || (function() {
        try {
          var Long = require_umd();
          return Long && Long.isLong ? Long : null;
        } catch (e) {
          return null;
        }
      })();
      util.key2Re = /^(?:true|false|0|1)$/;
      util.key32Re = /^-?(?:0|[1-9][0-9]*)$/;
      util.key64Re = /^(?:[\x00-\xff]{8}|-?(?:0|[1-9][0-9]*))$/;
      util.longToHash = function longToHash(value) {
        return value ? util.LongBits.from(value).toHash() : util.LongBits.zeroHash;
      };
      util.longFromHash = function longFromHash(hash, unsigned) {
        var bits = util.LongBits.fromHash(hash);
        if (util.Long)
          return util.Long.fromBits(bits.lo, bits.hi, unsigned);
        return bits.toNumber(Boolean(unsigned));
      };
      util.longFromKey = function longFromKey(key, unsigned) {
        return util.key64Re.test(key) && !util.key32Re.test(key) ? util.longFromHash(key, unsigned) : key;
      };
      util.boolFromKey = function boolFromKey(key) {
        return key === "true" || key === "1";
      };
      function merge(dst) {
        var ifNotSet = typeof arguments[arguments.length - 1] === "boolean", limit = ifNotSet ? arguments.length - 1 : arguments.length;
        ifNotSet = ifNotSet && arguments[arguments.length - 1];
        for (var a = 1; a < limit; ++a) {
          var src = arguments[a];
          if (!src)
            continue;
          for (var keys = Object.keys(src), i = 0; i < keys.length; ++i)
            if (!isUnsafeProperty(keys[i]) && (!ifNotSet || !Object.prototype.hasOwnProperty.call(dst, keys[i]) || dst[keys[i]] === void 0))
              dst[keys[i]] = src[keys[i]];
        }
        return dst;
      }
      util.merge = merge;
      util.nestingLimit = 32;
      util.recursionLimit = 100;
      util.makeProp = function makeProp(obj, key, enumerable) {
        if (Object.prototype.hasOwnProperty.call(obj, key))
          return;
        Object.defineProperty(obj, key, {
          enumerable: enumerable === void 0 ? true : enumerable,
          configurable: true,
          writable: true
        });
      };
      util.lcFirst = function lcFirst(str) {
        return str.charAt(0).toLowerCase() + str.substring(1);
      };
      function newError(name) {
        function CustomError(message, properties) {
          if (!(this instanceof CustomError))
            return new CustomError(message, properties);
          Object.defineProperty(this, "message", { get: function() {
            return message;
          } });
          if (Error.captureStackTrace)
            Error.captureStackTrace(this, CustomError);
          else
            Object.defineProperty(this, "stack", { value: new Error().stack || "" });
          if (properties)
            merge(this, properties);
        }
        CustomError.prototype = Object.create(Error.prototype, {
          constructor: {
            value: CustomError,
            writable: true,
            enumerable: false,
            configurable: true
          },
          name: {
            get: function get() {
              return name;
            },
            set: void 0,
            enumerable: false,
            // configurable: false would accurately preserve the behavior of
            // the original, but I'm guessing that was not intentional.
            // For an actual error subclass, this property would
            // be configurable.
            configurable: true
          },
          toString: {
            value: function value() {
              return this.name + ": " + this.message;
            },
            writable: true,
            enumerable: false,
            configurable: true
          }
        });
        return CustomError;
      }
      util.newError = newError;
      util.ProtocolError = newError("ProtocolError");
      util.oneOfGetter = function getOneOf(fieldNames) {
        var fieldMap = {};
        for (var i = 0; i < fieldNames.length; ++i)
          fieldMap[fieldNames[i]] = 1;
        return function() {
          for (var keys = Object.keys(this), i2 = keys.length - 1; i2 > -1; --i2)
            if (fieldMap[keys[i2]] === 1 && this[keys[i2]] !== void 0 && this[keys[i2]] !== null)
              return keys[i2];
        };
      };
      util.oneOfSetter = function setOneOf(fieldNames) {
        return function(name) {
          for (var i = 0; i < fieldNames.length; ++i)
            if (fieldNames[i] !== name)
              delete this[fieldNames[i]];
        };
      };
      util.toJSONOptions = {
        longs: String,
        enums: String,
        bytes: String,
        json: true
      };
    }
  });

  // node_modules/protobufjs/src/writer.js
  var require_writer = __commonJS({
    "node_modules/protobufjs/src/writer.js"(exports, module) {
      "use strict";
      module.exports = Writer;
      var util = require_minimal();
      var BufferWriter;
      var LongBits = util.LongBits;
      var base64 = util.base64;
      var utf8 = util.utf8;
      function Writer() {
        this.pos = 0;
        this.buf = this.constructor.alloc(Writer.initialBufferSize);
        this.view = null;
        this.states = null;
      }
      Writer.initialBufferSize = 128;
      Object.defineProperty(Writer.prototype, "len", {
        configurable: true,
        enumerable: true,
        get: function get_len() {
          return this.pos;
        }
      });
      var create = function create2() {
        return util.Buffer ? function create_buffer_setup() {
          return (Writer.create = function create_buffer() {
            return new BufferWriter();
          })();
        } : function create_array() {
          return new Writer();
        };
      };
      Writer.create = create();
      Writer.alloc = function alloc(size) {
        return new Uint8Array(size);
      };
      Writer.alloc = util.pool(Writer.alloc, Uint8Array.prototype.subarray);
      function sizeVarint32(value) {
        return value < 128 ? 1 : value < 16384 ? 2 : value < 2097152 ? 3 : value < 268435456 ? 4 : 5;
      }
      Writer.prototype._reserve = function _reserve(n) {
        var need = this.pos + n;
        if (need > this.buf.length) {
          var size = this.buf.length << 1;
          if (size < need)
            size = need;
          var buf = this.constructor.alloc(size);
          buf.set(this.buf.subarray(0, this.pos), 0);
          this.buf = buf;
          this.view = null;
        }
      };
      function writeStringAscii(val, buf, pos) {
        for (var i = 0; i < val.length; )
          buf[pos++] = val.charCodeAt(i++);
      }
      function writeVarint32(val, buf, pos) {
        while (val > 127) {
          buf[pos++] = val & 127 | 128;
          val >>>= 7;
        }
        buf[pos] = val;
        return pos + 1;
      }
      Writer.prototype.uint32 = function write_uint32(value) {
        value = value >>> 0;
        this._reserve(5);
        var pos = this.pos;
        this.pos = writeVarint32(value, this.buf, pos);
        return this;
      };
      Writer.prototype.int32 = function write_int32(value) {
        if ((value |= 0) < 0) {
          this._reserve(10);
          writeVarint64(LongBits.fromNumber(value), this.buf, this.pos);
          this.pos += 10;
          return this;
        }
        return this.uint32(value);
      };
      Writer.prototype.sint32 = function write_sint32(value) {
        return this.uint32((value << 1 ^ value >> 31) >>> 0);
      };
      function writeVarint64(val, buf, pos) {
        var lo = val.lo, hi = val.hi;
        while (hi) {
          buf[pos++] = lo & 127 | 128;
          lo = (lo >>> 7 | hi << 25) >>> 0;
          hi >>>= 7;
        }
        while (lo > 127) {
          buf[pos++] = lo & 127 | 128;
          lo = lo >>> 7;
        }
        buf[pos] = lo;
        return pos + 1;
      }
      Writer.prototype.uint64 = function write_uint64(value) {
        var bits = LongBits.from(value);
        this._reserve(10);
        var pos = this.pos;
        this.pos = writeVarint64(bits, this.buf, pos);
        return this;
      };
      Writer.prototype.int64 = Writer.prototype.uint64;
      Writer.prototype.sint64 = function write_sint64(value) {
        var bits = LongBits.from(value).zzEncode();
        this._reserve(10);
        var pos = this.pos;
        this.pos = writeVarint64(bits, this.buf, pos);
        return this;
      };
      Writer.prototype.bool = function write_bool(value) {
        this._reserve(1);
        this.buf[this.pos++] = value ? 1 : 0;
        return this;
      };
      function writeFixed32(val, buf, pos) {
        buf[pos] = val & 255;
        buf[pos + 1] = val >>> 8 & 255;
        buf[pos + 2] = val >>> 16 & 255;
        buf[pos + 3] = val >>> 24;
      }
      Writer.prototype.fixed32 = function write_fixed32(value) {
        this._reserve(4);
        writeFixed32(value >>> 0, this.buf, this.pos);
        this.pos += 4;
        return this;
      };
      Writer.prototype.sfixed32 = Writer.prototype.fixed32;
      Writer.prototype.fixed64 = function write_fixed64(value) {
        var bits = LongBits.from(value);
        this._reserve(8);
        writeFixed32(bits.lo, this.buf, this.pos);
        writeFixed32(bits.hi, this.buf, this.pos + 4);
        this.pos += 8;
        return this;
      };
      Writer.prototype.sfixed64 = Writer.prototype.fixed64;
      Writer.prototype.float = function write_float(value) {
        this._reserve(4);
        util.float.writeFloatLE(value, this.buf, this.pos);
        this.pos += 4;
        return this;
      };
      Writer.prototype.double = function write_double(value) {
        this._reserve(8);
        util.float.writeDoubleLE(value, this.buf, this.pos);
        this.pos += 8;
        return this;
      };
      Writer.prototype.bytes = function write_bytes(value) {
        var len = value.length >>> 0;
        if (!len) {
          this._reserve(1);
          this.buf[this.pos++] = 0;
          return this;
        }
        if (util.isString(value)) {
          var buf = Writer.alloc(len = base64.length(value));
          base64.decode(value, buf, 0);
          value = buf;
        }
        this.uint32(len);
        this._reserve(len);
        this.buf.set(value, this.pos);
        this.pos += len;
        return this;
      };
      Writer.prototype.raw = function write_raw(value) {
        var len = value.length >>> 0;
        if (!len)
          return this;
        this._reserve(len);
        this.buf.set(value, this.pos);
        this.pos += len;
        return this;
      };
      Writer.prototype._delim = function _delim(pos, len) {
        var n = sizeVarint32(len);
        if (n > 1)
          this.buf.copyWithin(pos + n, pos + 1, pos + 1 + len);
        writeVarint32(len, this.buf, pos);
        this.pos = pos + n + len;
        return this;
      };
      Writer.prototype.string = function write_string(value) {
        var n = value.length;
        if (!n) {
          this._reserve(1);
          this.buf[this.pos++] = 0;
          return this;
        }
        if (n < 128) {
          this._reserve(n * 3 + 5);
          var lenPos = this.pos;
          return this._delim(lenPos, utf8.write(value, this.buf, lenPos + 1));
        }
        var len = utf8.length(value);
        this.uint32(len);
        this._reserve(len);
        if (len === value.length)
          writeStringAscii(value, this.buf, this.pos);
        else
          utf8.write(value, this.buf, this.pos);
        this.pos += len;
        return this;
      };
      Writer.prototype.uint32s = function write_uint32s(value) {
        var n = value.length;
        this._reserve(n * 5 + 5);
        var buf = this.buf, lenPos = this.pos, p = lenPos + 1;
        for (var i = 0; i < n; ++i)
          p = writeVarint32(value[i] >>> 0, buf, p);
        return this._delim(lenPos, p - lenPos - 1);
      };
      Writer.prototype.int32s = function write_int32s(value) {
        var n = value.length;
        this._reserve(n * 10 + 5);
        var buf = this.buf, lenPos = this.pos, pos = lenPos + 1, val;
        for (var i = 0; i < n; ++i) {
          if ((val = value[i] | 0) < 0) {
            pos = writeVarint64(LongBits.fromNumber(val), buf, pos);
          } else {
            pos = writeVarint32(val, buf, pos);
          }
        }
        return this._delim(lenPos, pos - lenPos - 1);
      };
      Writer.prototype.sint32s = function write_sint32s(value) {
        var n = value.length;
        this._reserve(n * 5 + 5);
        var buf = this.buf, lenPos = this.pos, pos = lenPos + 1;
        for (var i = 0; i < n; ++i)
          pos = writeVarint32((value[i] << 1 ^ value[i] >> 31) >>> 0, buf, pos);
        return this._delim(lenPos, pos - lenPos - 1);
      };
      Writer.prototype.uint64s = function write_uint64s(value) {
        var n = value.length;
        this._reserve(n * 10 + 5);
        var buf = this.buf, lenPos = this.pos, pos = lenPos + 1;
        for (var i = 0; i < n; ++i) {
          pos = writeVarint64(LongBits.from(value[i]), buf, pos);
        }
        return this._delim(lenPos, pos - lenPos - 1);
      };
      Writer.prototype.int64s = Writer.prototype.uint64s;
      Writer.prototype.sint64s = function write_sint64s(value) {
        var n = value.length;
        this._reserve(n * 10 + 5);
        var buf = this.buf, lenPos = this.pos, pos = lenPos + 1;
        for (var i = 0; i < n; ++i) {
          pos = writeVarint64(LongBits.from(value[i]).zzEncode(), buf, pos);
        }
        return this._delim(lenPos, pos - lenPos - 1);
      };
      Writer.prototype.bools = function write_bools(value) {
        var n = value.length;
        this.uint32(n);
        this._reserve(n);
        var buf = this.buf, p = this.pos;
        for (var i = 0; i < n; ++i)
          buf[p++] = value[i] ? 1 : 0;
        this.pos += n;
        return this;
      };
      var VIEW_THRESHOLD_FLOAT = 16;
      var VIEW_THRESHOLD_INT = 128;
      function getLazyView(writer, count, threshold) {
        var view = writer.view;
        if (view || count < threshold)
          return view;
        var buf = writer.buf;
        return writer.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      }
      Writer.prototype.fixed32s = function write_fixed32s(value) {
        var n = value.length, bytes = n * 4;
        this.uint32(bytes);
        this._reserve(bytes);
        var p = this.pos, i, dv = getLazyView(this, n, VIEW_THRESHOLD_INT);
        if (dv)
          for (i = 0; i < n; ++i) {
            dv.setUint32(p, value[i] >>> 0, true);
            p += 4;
          }
        else {
          var buf = this.buf;
          for (i = 0; i < n; ++i) {
            writeFixed32(value[i] >>> 0, buf, p);
            p += 4;
          }
        }
        this.pos += bytes;
        return this;
      };
      Writer.prototype.sfixed32s = Writer.prototype.fixed32s;
      Writer.prototype.fixed64s = function write_fixed64s(value) {
        var n = value.length, bytes = n * 8;
        this.uint32(bytes);
        this._reserve(bytes);
        var p = this.pos, i, bits, dv = getLazyView(this, n, VIEW_THRESHOLD_INT);
        if (dv)
          for (i = 0; i < n; ++i) {
            bits = LongBits.from(value[i]);
            dv.setUint32(p, bits.lo, true);
            dv.setUint32(p + 4, bits.hi, true);
            p += 8;
          }
        else {
          var buf = this.buf;
          for (i = 0; i < n; ++i) {
            bits = LongBits.from(value[i]);
            writeFixed32(bits.lo, buf, p);
            writeFixed32(bits.hi, buf, p + 4);
            p += 8;
          }
        }
        this.pos += bytes;
        return this;
      };
      Writer.prototype.sfixed64s = Writer.prototype.fixed64s;
      Writer.prototype.floats = function write_floats(value) {
        var n = value.length, bytes = n * 4;
        this.uint32(bytes);
        this._reserve(bytes);
        var p = this.pos, i, dv = getLazyView(this, n, VIEW_THRESHOLD_FLOAT);
        if (dv)
          for (i = 0; i < n; ++i) {
            dv.setFloat32(p, value[i], true);
            p += 4;
          }
        else {
          var buf = this.buf;
          for (i = 0; i < n; ++i) {
            util.float.writeFloatLE(value[i], buf, p);
            p += 4;
          }
        }
        this.pos += bytes;
        return this;
      };
      Writer.prototype.doubles = function write_doubles(value) {
        var n = value.length, bytes = n * 8;
        this.uint32(bytes);
        this._reserve(bytes);
        var p = this.pos, i, dv = getLazyView(this, n, VIEW_THRESHOLD_FLOAT);
        if (dv)
          for (i = 0; i < n; ++i) {
            dv.setFloat64(p, value[i], true);
            p += 8;
          }
        else {
          var buf = this.buf;
          for (i = 0; i < n; ++i) {
            util.float.writeDoubleLE(value[i], buf, p);
            p += 8;
          }
        }
        this.pos += bytes;
        return this;
      };
      Writer.prototype.fork = function fork() {
        this._reserve(1);
        (this.states || (this.states = [])).push(this.pos);
        this.pos += 1;
        return this;
      };
      Writer.prototype.reset = function reset() {
        var states = this.states;
        if (states && states.length) {
          this.pos = states.pop();
        } else {
          this.pos = 0;
        }
        return this;
      };
      Writer.prototype.ldelim = function ldelim() {
        var states = this.states, len, vlen;
        if (states && states.length) {
          var lenPos = states.pop();
          len = this.pos - lenPos - 1;
          vlen = sizeVarint32(len);
          if (vlen > 1) {
            this._reserve(vlen - 1);
            this.buf.copyWithin(lenPos + vlen, lenPos + 1, lenPos + 1 + len);
            this.pos += vlen - 1;
            writeVarint32(len, this.buf, lenPos);
          } else {
            this.buf[lenPos] = len;
          }
        } else {
          len = this.pos;
          vlen = sizeVarint32(len);
          this._reserve(vlen);
          this.buf.copyWithin(vlen, 0, len);
          writeVarint32(len, this.buf, 0);
          this.pos += vlen;
        }
        return this;
      };
      Writer.prototype.finish = function finish(shared) {
        if (shared)
          return this.buf.subarray(0, this.pos);
        var buf = this.constructor.alloc(this.pos);
        buf.set(this.buf.subarray(0, this.pos), 0);
        return buf;
      };
      Writer.prototype.finishInto = function finishInto(buf, offset) {
        if (offset === void 0)
          offset = 0;
        buf.set(this.buf.subarray(0, this.pos), offset);
        return buf;
      };
      Writer._configure = function(BufferWriter_) {
        BufferWriter = BufferWriter_;
        Writer.create = create();
        BufferWriter._configure();
      };
    }
  });

  // node_modules/protobufjs/src/writer_buffer.js
  var require_writer_buffer = __commonJS({
    "node_modules/protobufjs/src/writer_buffer.js"(exports, module) {
      "use strict";
      module.exports = BufferWriter;
      var Writer = require_writer();
      BufferWriter.prototype = Object.create(Writer.prototype, {
        constructor: {
          value: BufferWriter,
          writable: true,
          enumerable: false,
          configurable: true
        }
      });
      var util = require_minimal();
      function BufferWriter() {
        Writer.call(this);
      }
      var writeStringBuffer;
      BufferWriter._configure = function() {
        BufferWriter.alloc = util.Buffer && util.Buffer.allocUnsafe;
        writeStringBuffer = util.Buffer && util.Buffer.prototype.utf8Write ? function writeStringBuffer_utf8Write(val, buf, pos) {
          return buf.utf8Write(val, pos);
        } : function writeStringBuffer_write(val, buf, pos) {
          return buf.write(val, pos);
        };
      };
      BufferWriter.prototype.bytes = function write_bytes_buffer(value) {
        if (util.isString(value))
          value = util.Buffer.from(value, "base64");
        var len = value.length >>> 0;
        this.uint32(len);
        if (len) {
          this._reserve(len);
          this.buf.set(value, this.pos);
          this.pos += len;
        }
        return this;
      };
      BufferWriter.prototype.string = function write_string_buffer(value) {
        var n = value.length;
        if (!n) {
          this._reserve(1);
          this.buf[this.pos++] = 0;
          return this;
        }
        if (n < 128) {
          this._reserve(n * 3 + 5);
          var pos = this.pos, buf = this.buf;
          return this._delim(
            pos,
            n < 40 ? util.utf8.write(value, buf, pos + 1) : writeStringBuffer(value, buf, pos + 1)
          );
        }
        var len = util.Buffer.byteLength(value);
        this.uint32(len);
        this._reserve(len);
        writeStringBuffer(value, this.buf, this.pos);
        this.pos += len;
        return this;
      };
      BufferWriter._configure();
    }
  });

  // node_modules/protobufjs/src/reader.js
  var require_reader = __commonJS({
    "node_modules/protobufjs/src/reader.js"(exports, module) {
      "use strict";
      module.exports = Reader;
      var util = require_minimal();
      var BufferReader;
      var LongBits = util.LongBits;
      var utf8 = util.utf8;
      function indexOutOfRange(reader, writeLength) {
        return RangeError("index out of range: " + reader.pos + " + " + (writeLength || 1) + " > " + reader.len);
      }
      function Reader(buffer) {
        this.buf = buffer;
        this.pos = 0;
        this.len = buffer.length;
        this.view = null;
        this.discardUnknown = Reader.discardUnknown;
      }
      function create_array(buffer) {
        if (Array.isArray(buffer))
          buffer = new Uint8Array(buffer);
        if (buffer instanceof Uint8Array)
          return new Reader(buffer);
        throw Error("illegal buffer");
      }
      var create = function create2() {
        return util.Buffer ? function create_buffer_setup(buffer) {
          return (Reader.create = function create_buffer(buffer2) {
            return util.Buffer.isBuffer(buffer2) ? new BufferReader(buffer2) : create_array(buffer2);
          })(buffer);
        } : create_array;
      };
      Reader.create = create();
      Reader.prototype.raw = function read_raw(start, end) {
        return this.buf.subarray(start, end);
      };
      Reader.prototype.uint32 = function read_uint32() {
        var buf = this.buf, pos = this.pos, value = (buf[pos] & 127) >>> 0;
        if (buf[pos++] < 128) {
          this.pos = pos;
          return value;
        }
        value = (value | (buf[pos] & 127) << 7) >>> 0;
        if (buf[pos++] < 128) {
          this.pos = pos;
          return value;
        }
        value = (value | (buf[pos] & 127) << 14) >>> 0;
        if (buf[pos++] < 128) {
          this.pos = pos;
          return value;
        }
        value = (value | (buf[pos] & 127) << 21) >>> 0;
        if (buf[pos++] < 128) {
          this.pos = pos;
          return value;
        }
        value = (value | (buf[pos] & 15) << 28) >>> 0;
        if (buf[pos++] < 128) {
          this.pos = pos;
          return value;
        }
        for (var i = 0; i < 5; ++i) {
          if (pos >= this.len) {
            this.pos = pos;
            throw indexOutOfRange(this);
          }
          if (buf[pos++] < 128) {
            this.pos = pos;
            return value;
          }
        }
        this.pos = pos;
        throw Error("invalid varint encoding");
      };
      Reader.prototype.tag = function read_tag() {
        var buf = this.buf, pos = this.pos, value = (buf[pos] & 127) >>> 0;
        if (buf[pos++] < 128) {
          this.pos = pos;
          return value;
        }
        value = (value | (buf[pos] & 127) << 7) >>> 0;
        if (buf[pos++] < 128) {
          this.pos = pos;
          return value;
        }
        value = (value | (buf[pos] & 127) << 14) >>> 0;
        if (buf[pos++] < 128) {
          this.pos = pos;
          return value;
        }
        value = (value | (buf[pos] & 127) << 21) >>> 0;
        if (buf[pos++] < 128) {
          this.pos = pos;
          return value;
        }
        value = (value | (buf[pos] & 15) << 28) >>> 0;
        if (buf[pos] < 128 && (buf[pos] & 112) === 0) {
          this.pos = pos + 1;
          return value;
        }
        this.pos = pos + 1;
        throw Error("invalid tag encoding");
      };
      Reader.prototype.int32 = function read_int32() {
        return this.uint32() | 0;
      };
      Reader.prototype.sint32 = function read_sint32() {
        var value = this.uint32();
        return value >>> 1 ^ -(value & 1) | 0;
      };
      function readLongVarint() {
        var bits = new LongBits(0, 0);
        var i = 0;
        if (this.len - this.pos > 4) {
          for (; i < 4; ++i) {
            bits.lo = (bits.lo | (this.buf[this.pos] & 127) << i * 7) >>> 0;
            if (this.buf[this.pos++] < 128)
              return bits;
          }
          bits.lo = (bits.lo | (this.buf[this.pos] & 127) << 28) >>> 0;
          bits.hi = (bits.hi | (this.buf[this.pos] & 127) >> 4) >>> 0;
          if (this.buf[this.pos++] < 128)
            return bits;
          i = 0;
        } else {
          for (; i < 4; ++i) {
            if (this.pos >= this.len)
              throw indexOutOfRange(this);
            bits.lo = (bits.lo | (this.buf[this.pos] & 127) << i * 7) >>> 0;
            if (this.buf[this.pos++] < 128)
              return bits;
          }
          throw indexOutOfRange(this);
        }
        if (this.len - this.pos > 4) {
          for (; i < 5; ++i) {
            bits.hi = (bits.hi | (this.buf[this.pos] & 127) << i * 7 + 3) >>> 0;
            if (this.buf[this.pos++] < 128)
              return bits;
          }
        } else {
          for (; i < 5; ++i) {
            if (this.pos >= this.len)
              throw indexOutOfRange(this);
            bits.hi = (bits.hi | (this.buf[this.pos] & 127) << i * 7 + 3) >>> 0;
            if (this.buf[this.pos++] < 128)
              return bits;
          }
        }
        throw Error("invalid varint encoding");
      }
      Reader.prototype.bool = function read_bool() {
        var value = false, b;
        for (var i = 0; i < 10; ++i) {
          if (this.pos >= this.len)
            throw indexOutOfRange(this);
          b = this.buf[this.pos++];
          if (b & 127)
            value = true;
          if (b < 128)
            return value;
        }
        throw Error("invalid varint encoding");
      };
      function readFixed32_end(buf, end) {
        return (buf[end - 4] | buf[end - 3] << 8 | buf[end - 2] << 16 | buf[end - 1] << 24) >>> 0;
      }
      Reader.prototype.fixed32 = function read_fixed32() {
        if (this.pos + 4 > this.len)
          throw indexOutOfRange(this, 4);
        return readFixed32_end(this.buf, this.pos += 4);
      };
      Reader.prototype.sfixed32 = function read_sfixed32() {
        if (this.pos + 4 > this.len)
          throw indexOutOfRange(this, 4);
        return readFixed32_end(this.buf, this.pos += 4) | 0;
      };
      function readFixed64() {
        if (this.pos + 8 > this.len)
          throw indexOutOfRange(this, 8);
        return new LongBits(readFixed32_end(this.buf, this.pos += 4), readFixed32_end(this.buf, this.pos += 4));
      }
      Reader.prototype.float = function read_float() {
        if (this.pos + 4 > this.len)
          throw indexOutOfRange(this, 4);
        var value = util.float.readFloatLE(this.buf, this.pos);
        this.pos += 4;
        return value;
      };
      Reader.prototype.double = function read_double() {
        if (this.pos + 8 > this.len)
          throw indexOutOfRange(this, 4);
        var value = util.float.readDoubleLE(this.buf, this.pos);
        this.pos += 8;
        return value;
      };
      Reader.prototype.uint32s = function read_uint32s(array) {
        if (array === void 0) array = [];
        var end = this.uint32() + this.pos, buf = this.buf, pos = this.pos, value;
        while (pos < end) {
          value = buf[pos++];
          if (value < 128)
            array.push(value);
          else {
            this.pos = pos - 1;
            array.push(this.uint32());
            pos = this.pos;
          }
        }
        this.pos = pos;
        return array;
      };
      Reader.prototype.int32s = function read_int32s(array) {
        if (array === void 0) array = [];
        var end = this.uint32() + this.pos, buf = this.buf, pos = this.pos, value;
        while (pos < end) {
          value = buf[pos++];
          if (value < 128)
            array.push(value);
          else {
            this.pos = pos - 1;
            array.push(this.int32());
            pos = this.pos;
          }
        }
        this.pos = pos;
        return array;
      };
      Reader.prototype.sint32s = function read_sint32s(array) {
        if (array === void 0) array = [];
        var end = this.uint32() + this.pos;
        while (this.pos < end)
          array.push(this.sint32());
        return array;
      };
      Reader.prototype.bools = function read_bools(array) {
        if (array === void 0) array = [];
        var end = this.uint32() + this.pos, buf = this.buf, pos = this.pos, value;
        while (pos < end) {
          value = buf[pos++];
          if (value < 128)
            array.push(value !== 0);
          else {
            this.pos = pos - 1;
            array.push(this.bool());
            pos = this.pos;
          }
        }
        this.pos = pos;
        return array;
      };
      var VIEW_THRESHOLD_FLOAT = 8;
      var VIEW_THRESHOLD_INT = 128;
      function getLazyView(reader, count, threshold) {
        var view = reader.view;
        if (view || count < threshold)
          return view;
        var buf = reader.buf;
        return reader.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      }
      Reader.prototype.fixed32s = function read_fixed32s(array) {
        if (array === void 0) array = [];
        var len = this.uint32(), end = this.pos + len;
        if (end > this.len) throw indexOutOfRange(this, len);
        var count = len >>> 2, i = array.length, pos = this.pos;
        array.length = i + count;
        var dv = getLazyView(this, count, VIEW_THRESHOLD_INT);
        if (dv)
          for (var k = 0; k < count; ++k, pos += 4) array[i++] = dv.getUint32(pos, true);
        else {
          var buf = this.buf;
          for (var j = 0; j < count; ++j, pos += 4) array[i++] = readFixed32_end(buf, pos + 4);
        }
        this.pos = pos;
        if (pos !== end) throw indexOutOfRange(this, 4);
        return array;
      };
      Reader.prototype.sfixed32s = function read_sfixed32s(array) {
        if (array === void 0) array = [];
        var len = this.uint32(), end = this.pos + len;
        if (end > this.len) throw indexOutOfRange(this, len);
        var count = len >>> 2, i = array.length, pos = this.pos;
        array.length = i + count;
        var dv = getLazyView(this, count, VIEW_THRESHOLD_INT);
        if (dv)
          for (var k = 0; k < count; ++k, pos += 4) array[i++] = dv.getInt32(pos, true);
        else {
          var buf = this.buf;
          for (var j = 0; j < count; ++j, pos += 4) array[i++] = readFixed32_end(buf, pos + 4) | 0;
        }
        this.pos = pos;
        if (pos !== end) throw indexOutOfRange(this, 4);
        return array;
      };
      Reader.prototype.floats = function read_floats(array) {
        if (array === void 0) array = [];
        var len = this.uint32(), end = this.pos + len;
        if (end > this.len) throw indexOutOfRange(this, len);
        var count = len >>> 2, i = array.length, pos = this.pos;
        array.length = i + count;
        var dv = getLazyView(this, count, VIEW_THRESHOLD_FLOAT);
        if (dv)
          for (var k = 0; k < count; ++k, pos += 4) array[i++] = dv.getFloat32(pos, true);
        else {
          var buf = this.buf;
          for (var j = 0; j < count; ++j, pos += 4) array[i++] = util.float.readFloatLE(buf, pos);
        }
        this.pos = pos;
        if (pos !== end) throw indexOutOfRange(this, 4);
        return array;
      };
      Reader.prototype.doubles = function read_doubles(array) {
        if (array === void 0) array = [];
        var len = this.uint32(), end = this.pos + len;
        if (end > this.len) throw indexOutOfRange(this, len);
        var count = len >>> 3, i = array.length, pos = this.pos;
        array.length = i + count;
        var dv = getLazyView(this, count, VIEW_THRESHOLD_FLOAT);
        if (dv)
          for (var k = 0; k < count; ++k, pos += 8) array[i++] = dv.getFloat64(pos, true);
        else {
          var buf = this.buf;
          for (var j = 0; j < count; ++j, pos += 8) array[i++] = util.float.readDoubleLE(buf, pos);
        }
        this.pos = pos;
        if (pos !== end) throw indexOutOfRange(this, 8);
        return array;
      };
      Reader.prototype.uint64s = function read_uint64s(array) {
        if (array === void 0) array = [];
        var end = this.uint32() + this.pos;
        while (this.pos < end)
          array.push(this.uint64());
        return array;
      };
      Reader.prototype.int64s = function read_int64s(array) {
        if (array === void 0) array = [];
        var end = this.uint32() + this.pos;
        while (this.pos < end)
          array.push(this.int64());
        return array;
      };
      Reader.prototype.sint64s = function read_sint64s(array) {
        if (array === void 0) array = [];
        var end = this.uint32() + this.pos;
        while (this.pos < end)
          array.push(this.sint64());
        return array;
      };
      Reader.prototype.fixed64s = function read_fixed64s(array) {
        if (array === void 0) array = [];
        var len = this.uint32(), end = this.pos + len, i = array.length;
        if (end > this.len) throw indexOutOfRange(this, len);
        var count = len >>> 3;
        array.length = i + count;
        for (var j = 0; j < count; ++j)
          array[i++] = this.fixed64();
        if (this.pos !== end) throw indexOutOfRange(this, 8);
        return array;
      };
      Reader.prototype.sfixed64s = function read_sfixed64s(array) {
        if (array === void 0) array = [];
        var len = this.uint32(), end = this.pos + len, i = array.length;
        if (end > this.len) throw indexOutOfRange(this, len);
        var count = len >>> 3;
        array.length = i + count;
        for (var j = 0; j < count; ++j)
          array[i++] = this.sfixed64();
        if (this.pos !== end) throw indexOutOfRange(this, 8);
        return array;
      };
      Reader.prototype.bytes = function read_bytes() {
        var length = this.uint32(), start = this.pos, end = this.pos + length;
        if (end > this.len)
          throw indexOutOfRange(this, length);
        this.pos = end;
        return this.raw(start, end);
      };
      Reader.prototype.string = function read_string() {
        var length = this.uint32(), start = this.pos, end = this.pos + length;
        if (end > this.len)
          throw indexOutOfRange(this, length);
        this.pos = end;
        return utf8.read(this.buf, start, end);
      };
      Reader.prototype.stringVerify = function read_string_verify() {
        var length = this.uint32(), start = this.pos, end = this.pos + length;
        if (end > this.len)
          throw indexOutOfRange(this, length);
        this.pos = end;
        return utf8.readStrict(this.buf, start, end);
      };
      Reader.prototype.skip = function skip(length) {
        if (typeof length === "number") {
          if (this.pos + length > this.len)
            throw indexOutOfRange(this, length);
          this.pos += length;
        } else {
          do {
            if (this.pos >= this.len)
              throw indexOutOfRange(this);
          } while (this.buf[this.pos++] & 128);
        }
        return this;
      };
      Reader.recursionLimit = util.recursionLimit;
      Reader.discardUnknown = true;
      Reader.prototype.skipType = function(wireType, depth, fieldNumber) {
        if (depth === void 0) depth = 0;
        if (depth > Reader.recursionLimit)
          throw Error("max depth exceeded");
        if (fieldNumber === 0)
          throw Error("illegal tag: field number 0");
        switch (wireType) {
          case 0:
            this.skip();
            break;
          case 1:
            this.skip(8);
            break;
          case 2:
            this.skip(this.uint32());
            break;
          case 3:
            while (true) {
              var tag = this.tag();
              var nestedField = tag >>> 3;
              wireType = tag & 7;
              if (!nestedField)
                throw Error("illegal tag: field number 0");
              if (wireType === 4) {
                if (fieldNumber !== void 0 && nestedField !== fieldNumber)
                  throw Error("invalid end group tag");
                break;
              }
              this.skipType(wireType, depth + 1, nestedField);
            }
            break;
          case 5:
            this.skip(4);
            break;
          /* istanbul ignore next */
          default:
            throw Error("invalid wire type " + wireType + " at offset " + this.pos);
        }
        return this;
      };
      Reader._configure = function(BufferReader_) {
        BufferReader = BufferReader_;
        Reader.create = create();
        BufferReader._configure();
        var fn = util.Long ? "toLong" : (
          /* istanbul ignore next */
          "toNumber"
        );
        util.merge(Reader.prototype, {
          int64: function read_int64() {
            return readLongVarint.call(this)[fn](false);
          },
          uint64: function read_uint64() {
            return readLongVarint.call(this)[fn](true);
          },
          sint64: function read_sint64() {
            return readLongVarint.call(this).zzDecode()[fn](false);
          },
          fixed64: function read_fixed64() {
            return readFixed64.call(this)[fn](true);
          },
          sfixed64: function read_sfixed64() {
            return readFixed64.call(this)[fn](false);
          }
        });
      };
    }
  });

  // node_modules/protobufjs/src/reader_buffer.js
  var require_reader_buffer = __commonJS({
    "node_modules/protobufjs/src/reader_buffer.js"(exports, module) {
      "use strict";
      module.exports = BufferReader;
      var Reader = require_reader();
      BufferReader.prototype = Object.create(Reader.prototype, {
        constructor: {
          value: BufferReader,
          writable: true,
          enumerable: false,
          configurable: true
        }
      });
      var util = require_minimal();
      function BufferReader(buffer) {
        Reader.call(this, buffer);
      }
      BufferReader._configure = function() {
        if (util.Buffer)
          BufferReader.prototype._slice = util.Buffer.prototype.slice;
      };
      BufferReader.prototype.raw = function read_raw_buffer(start, end) {
        return this._slice.call(this.buf, start, end);
      };
      BufferReader.prototype.string = function read_string_buffer() {
        var len = this.uint32(), start = this.pos, end = this.pos + len;
        if (end > this.len)
          throw RangeError("index out of range: " + this.pos + " + " + len + " > " + this.len);
        this.pos = end;
        return this.buf.utf8Slice ? this.buf.utf8Slice(start, end) : this.buf.toString("utf-8", start, end);
      };
      BufferReader._configure();
    }
  });

  // node_modules/protobufjs/src/rpc/service.js
  var require_service = __commonJS({
    "node_modules/protobufjs/src/rpc/service.js"(exports, module) {
      "use strict";
      module.exports = Service;
      var util = require_minimal();
      Service.prototype = Object.create(util.EventEmitter.prototype, {
        constructor: {
          value: Service,
          writable: true,
          enumerable: false,
          configurable: true
        }
      });
      function Service(rpcImpl, requestDelimited, responseDelimited) {
        if (typeof rpcImpl !== "function")
          throw TypeError("rpcImpl must be a function");
        util.EventEmitter.call(this);
        this.rpcImpl = rpcImpl;
        this.requestDelimited = Boolean(requestDelimited);
        this.responseDelimited = Boolean(responseDelimited);
      }
      Service.prototype.rpcCall = function rpcCall(method, requestCtor, responseCtor, request, callback) {
        if (!request)
          throw TypeError("request must be specified");
        var self2 = this;
        if (!callback)
          return util.asPromise(rpcCall, self2, method, requestCtor, responseCtor, request);
        if (!self2.rpcImpl) {
          setTimeout(function() {
            callback(Error("already ended"));
          }, 0);
          return void 0;
        }
        try {
          return self2.rpcImpl(
            method,
            requestCtor[self2.requestDelimited ? "encodeDelimited" : "encode"](request).finish(),
            function rpcCallback(err, response) {
              if (err) {
                self2.emit("error", err, method);
                return callback(err);
              }
              if (response === null) {
                self2.end(
                  /* endedByRPC */
                  true
                );
                return void 0;
              }
              if (!(response instanceof responseCtor)) {
                try {
                  response = responseCtor[self2.responseDelimited ? "decodeDelimited" : "decode"](response);
                } catch (err2) {
                  self2.emit("error", err2, method);
                  return callback(err2);
                }
              }
              self2.emit("data", response, method);
              return callback(null, response);
            }
          );
        } catch (err) {
          self2.emit("error", err, method);
          setTimeout(function() {
            callback(err);
          }, 0);
          return void 0;
        }
      };
      Service.prototype.end = function end(endedByRPC) {
        if (this.rpcImpl) {
          if (!endedByRPC)
            this.rpcImpl(null, null, null);
          this.rpcImpl = null;
          this.emit("end").off();
        }
        return this;
      };
    }
  });

  // node_modules/protobufjs/src/rpc.js
  var require_rpc = __commonJS({
    "node_modules/protobufjs/src/rpc.js"(exports) {
      "use strict";
      var rpc = exports;
      rpc.Service = require_service();
    }
  });

  // node_modules/protobufjs/src/roots.js
  var require_roots = __commonJS({
    "node_modules/protobufjs/src/roots.js"(exports, module) {
      "use strict";
      module.exports = /* @__PURE__ */ Object.create(null);
    }
  });

  // node_modules/protobufjs/src/index-minimal.js
  var require_index_minimal = __commonJS({
    "node_modules/protobufjs/src/index-minimal.js"(exports) {
      "use strict";
      exports.build = "minimal";
      exports.Writer = require_writer();
      exports.BufferWriter = require_writer_buffer();
      exports.Reader = require_reader();
      exports.BufferReader = require_reader_buffer();
      exports.util = require_minimal();
      exports.rpc = require_rpc();
      exports.roots = require_roots();
      exports.configure = configure;
      function configure() {
        exports.util.LongBits._configure(exports.util.Long);
        exports.Writer._configure(exports.BufferWriter);
        exports.Reader._configure(exports.BufferReader);
      }
      configure();
    }
  });

  // node_modules/protobufjs/minimal.js
  var require_minimal2 = __commonJS({
    "node_modules/protobufjs/minimal.js"(exports, module) {
      "use strict";
      module.exports = require_index_minimal();
    }
  });

  // src/generated/runtime.js
  var import_minimal = __toESM(require_minimal2(), 1);
  var $Reader = import_minimal.default.Reader;
  var $Writer = import_minimal.default.Writer;
  var $util = import_minimal.default.util;
  var $Object = $util.global.Object;
  var $undefined = $util.global.undefined;
  var $Error = $util.global.Error;
  var $TypeError = $util.global.TypeError;
  var $String = $util.global.String;
  var $Boolean = $util.global.Boolean;
  var $Number = $util.global.Number;
  var $Array = $util.global.Array;
  var $isFinite = $util.global.isFinite;
  var $root = import_minimal.default.roots["default"] || (import_minimal.default.roots["default"] = {});
  var privoke = $root.privoke = (() => {
    const privoke2 = {};
    privoke2.v1 = (function() {
      const v1 = {};
      v1.RuntimeHealthRequest = (function() {
        const RuntimeHealthRequest2 = function(properties) {
          if (properties) {
            for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
              if (properties[keys[i]] != null && keys[i] !== "__proto__")
                this[keys[i]] = properties[keys[i]];
          }
        };
        RuntimeHealthRequest2.create = function(properties) {
          return new RuntimeHealthRequest2(properties);
        };
        RuntimeHealthRequest2.encode = function(message, writer, _depth) {
          if (!writer)
            writer = $Writer.create();
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
            for (let i = 0; i < message.$unknowns.length; ++i)
              writer.raw(message.$unknowns[i]);
          return writer;
        };
        RuntimeHealthRequest2.encodeDelimited = function(message, writer) {
          return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
        };
        RuntimeHealthRequest2.decode = function(reader, length, _end, _depth, _target) {
          if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $Reader.recursionLimit)
            throw $Error("max depth exceeded");
          let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.RuntimeHealthRequest();
          while (reader.pos < end) {
            let start = reader.pos;
            let tag = reader.tag();
            if (tag === _end) {
              _end = $undefined;
              break;
            }
            reader.skipType(tag & 7, _depth, tag);
            if (!reader.discardUnknown) {
              $util.makeProp(message, "$unknowns", false);
              (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
            }
          }
          if (_end !== $undefined)
            throw $Error("missing end group");
          return message;
        };
        RuntimeHealthRequest2.decodeDelimited = function(reader) {
          if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
          return this.decode(reader, reader.uint32());
        };
        RuntimeHealthRequest2.verify = function(message, _depth) {
          if (typeof message !== "object" || message === null)
            return "object expected";
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            return "max depth exceeded";
          return null;
        };
        RuntimeHealthRequest2.fromObject = function(object, _depth) {
          if (object instanceof $root.privoke.v1.RuntimeHealthRequest)
            return object;
          if (!$util.isObject(object))
            throw $TypeError(".privoke.v1.RuntimeHealthRequest: object expected");
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          return new $root.privoke.v1.RuntimeHealthRequest();
        };
        RuntimeHealthRequest2.toObject = function() {
          return {};
        };
        RuntimeHealthRequest2.prototype.toJSON = function() {
          return RuntimeHealthRequest2.toObject(this, import_minimal.default.util.toJSONOptions);
        };
        RuntimeHealthRequest2.getTypeUrl = function(prefix) {
          if (prefix === $undefined)
            prefix = "type.googleapis.com";
          return prefix + "/privoke.v1.RuntimeHealthRequest";
        };
        return RuntimeHealthRequest2;
      })();
      v1.RuntimeHealthResponse = (function() {
        const RuntimeHealthResponse2 = function(properties) {
          if (properties) {
            for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
              if (properties[keys[i]] != null && keys[i] !== "__proto__")
                this[keys[i]] = properties[keys[i]];
          }
        };
        RuntimeHealthResponse2.prototype.service = "";
        RuntimeHealthResponse2.prototype.status = "";
        RuntimeHealthResponse2.create = function(properties) {
          return new RuntimeHealthResponse2(properties);
        };
        RuntimeHealthResponse2.encode = function(message, writer, _depth) {
          if (!writer)
            writer = $Writer.create();
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          if (message.service != null && $Object.hasOwnProperty.call(message, "service") && message.service !== "")
            writer.uint32(
              /* id 1, wireType 2 =*/
              10
            ).string(message.service);
          if (message.status != null && $Object.hasOwnProperty.call(message, "status") && message.status !== "")
            writer.uint32(
              /* id 2, wireType 2 =*/
              18
            ).string(message.status);
          if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
            for (let i = 0; i < message.$unknowns.length; ++i)
              writer.raw(message.$unknowns[i]);
          return writer;
        };
        RuntimeHealthResponse2.encodeDelimited = function(message, writer) {
          return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
        };
        RuntimeHealthResponse2.decode = function(reader, length, _end, _depth, _target) {
          if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $Reader.recursionLimit)
            throw $Error("max depth exceeded");
          let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.RuntimeHealthResponse(), value;
          while (reader.pos < end) {
            let start = reader.pos;
            let tag = reader.tag();
            if (tag === _end) {
              _end = $undefined;
              break;
            }
            let wireType = tag & 7;
            switch (tag >>>= 3) {
              case 1: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.service = value;
                else
                  delete message.service;
                continue;
              }
              case 2: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.status = value;
                else
                  delete message.status;
                continue;
              }
            }
            reader.skipType(wireType, _depth, tag);
            if (!reader.discardUnknown) {
              $util.makeProp(message, "$unknowns", false);
              (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
            }
          }
          if (_end !== $undefined)
            throw $Error("missing end group");
          return message;
        };
        RuntimeHealthResponse2.decodeDelimited = function(reader) {
          if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
          return this.decode(reader, reader.uint32());
        };
        RuntimeHealthResponse2.verify = function(message, _depth) {
          if (typeof message !== "object" || message === null)
            return "object expected";
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            return "max depth exceeded";
          if (message.service != null && $Object.hasOwnProperty.call(message, "service")) {
            if (!$util.isString(message.service))
              return "service: string expected";
          }
          if (message.status != null && $Object.hasOwnProperty.call(message, "status")) {
            if (!$util.isString(message.status))
              return "status: string expected";
          }
          return null;
        };
        RuntimeHealthResponse2.fromObject = function(object, _depth) {
          if (object instanceof $root.privoke.v1.RuntimeHealthResponse)
            return object;
          if (!$util.isObject(object))
            throw $TypeError(".privoke.v1.RuntimeHealthResponse: object expected");
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let message = new $root.privoke.v1.RuntimeHealthResponse();
          if (object.service != null) {
            if (typeof object.service !== "string" || object.service.length)
              message.service = $String(object.service);
          }
          if (object.status != null) {
            if (typeof object.status !== "string" || object.status.length)
              message.status = $String(object.status);
          }
          return message;
        };
        RuntimeHealthResponse2.toObject = function(message, options, _depth) {
          if (!options)
            options = {};
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let object = {};
          if (options.defaults) {
            object.service = "";
            object.status = "";
          }
          if (message.service != null && $Object.hasOwnProperty.call(message, "service"))
            object.service = message.service;
          if (message.status != null && $Object.hasOwnProperty.call(message, "status"))
            object.status = message.status;
          return object;
        };
        RuntimeHealthResponse2.prototype.toJSON = function() {
          return RuntimeHealthResponse2.toObject(this, import_minimal.default.util.toJSONOptions);
        };
        RuntimeHealthResponse2.getTypeUrl = function(prefix) {
          if (prefix === $undefined)
            prefix = "type.googleapis.com";
          return prefix + "/privoke.v1.RuntimeHealthResponse";
        };
        return RuntimeHealthResponse2;
      })();
      v1.SetRuntimeEnabledRequest = (function() {
        const SetRuntimeEnabledRequest2 = function(properties) {
          if (properties) {
            for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
              if (properties[keys[i]] != null && keys[i] !== "__proto__")
                this[keys[i]] = properties[keys[i]];
          }
        };
        SetRuntimeEnabledRequest2.prototype.enabled = false;
        SetRuntimeEnabledRequest2.create = function(properties) {
          return new SetRuntimeEnabledRequest2(properties);
        };
        SetRuntimeEnabledRequest2.encode = function(message, writer, _depth) {
          if (!writer)
            writer = $Writer.create();
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          if (message.enabled != null && $Object.hasOwnProperty.call(message, "enabled") && message.enabled !== false)
            writer.uint32(
              /* id 1, wireType 0 =*/
              8
            ).bool(message.enabled);
          if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
            for (let i = 0; i < message.$unknowns.length; ++i)
              writer.raw(message.$unknowns[i]);
          return writer;
        };
        SetRuntimeEnabledRequest2.encodeDelimited = function(message, writer) {
          return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
        };
        SetRuntimeEnabledRequest2.decode = function(reader, length, _end, _depth, _target) {
          if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $Reader.recursionLimit)
            throw $Error("max depth exceeded");
          let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.SetRuntimeEnabledRequest(), value;
          while (reader.pos < end) {
            let start = reader.pos;
            let tag = reader.tag();
            if (tag === _end) {
              _end = $undefined;
              break;
            }
            let wireType = tag & 7;
            switch (tag >>>= 3) {
              case 1: {
                if (wireType !== 0)
                  break;
                if (value = reader.bool())
                  message.enabled = value;
                else
                  delete message.enabled;
                continue;
              }
            }
            reader.skipType(wireType, _depth, tag);
            if (!reader.discardUnknown) {
              $util.makeProp(message, "$unknowns", false);
              (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
            }
          }
          if (_end !== $undefined)
            throw $Error("missing end group");
          return message;
        };
        SetRuntimeEnabledRequest2.decodeDelimited = function(reader) {
          if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
          return this.decode(reader, reader.uint32());
        };
        SetRuntimeEnabledRequest2.verify = function(message, _depth) {
          if (typeof message !== "object" || message === null)
            return "object expected";
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            return "max depth exceeded";
          if (message.enabled != null && $Object.hasOwnProperty.call(message, "enabled")) {
            if (typeof message.enabled !== "boolean")
              return "enabled: boolean expected";
          }
          return null;
        };
        SetRuntimeEnabledRequest2.fromObject = function(object, _depth) {
          if (object instanceof $root.privoke.v1.SetRuntimeEnabledRequest)
            return object;
          if (!$util.isObject(object))
            throw $TypeError(".privoke.v1.SetRuntimeEnabledRequest: object expected");
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let message = new $root.privoke.v1.SetRuntimeEnabledRequest();
          if (object.enabled != null) {
            if (object.enabled)
              message.enabled = $Boolean(object.enabled);
          }
          return message;
        };
        SetRuntimeEnabledRequest2.toObject = function(message, options, _depth) {
          if (!options)
            options = {};
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let object = {};
          if (options.defaults)
            object.enabled = false;
          if (message.enabled != null && $Object.hasOwnProperty.call(message, "enabled"))
            object.enabled = message.enabled;
          return object;
        };
        SetRuntimeEnabledRequest2.prototype.toJSON = function() {
          return SetRuntimeEnabledRequest2.toObject(this, import_minimal.default.util.toJSONOptions);
        };
        SetRuntimeEnabledRequest2.getTypeUrl = function(prefix) {
          if (prefix === $undefined)
            prefix = "type.googleapis.com";
          return prefix + "/privoke.v1.SetRuntimeEnabledRequest";
        };
        return SetRuntimeEnabledRequest2;
      })();
      v1.RuntimeControlStatus = (function() {
        const RuntimeControlStatus2 = function(properties) {
          if (properties) {
            for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
              if (properties[keys[i]] != null && keys[i] !== "__proto__")
                this[keys[i]] = properties[keys[i]];
          }
        };
        RuntimeControlStatus2.prototype.enabled = false;
        RuntimeControlStatus2.prototype.status = "";
        RuntimeControlStatus2.prototype.message = "";
        RuntimeControlStatus2.prototype.processId = 0;
        RuntimeControlStatus2.create = function(properties) {
          return new RuntimeControlStatus2(properties);
        };
        RuntimeControlStatus2.encode = function(message, writer, _depth) {
          if (!writer)
            writer = $Writer.create();
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          if (message.enabled != null && $Object.hasOwnProperty.call(message, "enabled") && message.enabled !== false)
            writer.uint32(
              /* id 1, wireType 0 =*/
              8
            ).bool(message.enabled);
          if (message.status != null && $Object.hasOwnProperty.call(message, "status") && message.status !== "")
            writer.uint32(
              /* id 2, wireType 2 =*/
              18
            ).string(message.status);
          if (message.message != null && $Object.hasOwnProperty.call(message, "message") && message.message !== "")
            writer.uint32(
              /* id 3, wireType 2 =*/
              26
            ).string(message.message);
          if (message.processId != null && $Object.hasOwnProperty.call(message, "processId") && message.processId !== 0)
            writer.uint32(
              /* id 4, wireType 0 =*/
              32
            ).uint32(message.processId);
          if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
            for (let i = 0; i < message.$unknowns.length; ++i)
              writer.raw(message.$unknowns[i]);
          return writer;
        };
        RuntimeControlStatus2.encodeDelimited = function(message, writer) {
          return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
        };
        RuntimeControlStatus2.decode = function(reader, length, _end, _depth, _target) {
          if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $Reader.recursionLimit)
            throw $Error("max depth exceeded");
          let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.RuntimeControlStatus(), value;
          while (reader.pos < end) {
            let start = reader.pos;
            let tag = reader.tag();
            if (tag === _end) {
              _end = $undefined;
              break;
            }
            let wireType = tag & 7;
            switch (tag >>>= 3) {
              case 1: {
                if (wireType !== 0)
                  break;
                if (value = reader.bool())
                  message.enabled = value;
                else
                  delete message.enabled;
                continue;
              }
              case 2: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.status = value;
                else
                  delete message.status;
                continue;
              }
              case 3: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.message = value;
                else
                  delete message.message;
                continue;
              }
              case 4: {
                if (wireType !== 0)
                  break;
                if (value = reader.uint32())
                  message.processId = value;
                else
                  delete message.processId;
                continue;
              }
            }
            reader.skipType(wireType, _depth, tag);
            if (!reader.discardUnknown) {
              $util.makeProp(message, "$unknowns", false);
              (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
            }
          }
          if (_end !== $undefined)
            throw $Error("missing end group");
          return message;
        };
        RuntimeControlStatus2.decodeDelimited = function(reader) {
          if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
          return this.decode(reader, reader.uint32());
        };
        RuntimeControlStatus2.verify = function(message, _depth) {
          if (typeof message !== "object" || message === null)
            return "object expected";
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            return "max depth exceeded";
          if (message.enabled != null && $Object.hasOwnProperty.call(message, "enabled")) {
            if (typeof message.enabled !== "boolean")
              return "enabled: boolean expected";
          }
          if (message.status != null && $Object.hasOwnProperty.call(message, "status")) {
            if (!$util.isString(message.status))
              return "status: string expected";
          }
          if (message.message != null && $Object.hasOwnProperty.call(message, "message")) {
            if (!$util.isString(message.message))
              return "message: string expected";
          }
          if (message.processId != null && $Object.hasOwnProperty.call(message, "processId")) {
            if (!$util.isInteger(message.processId))
              return "processId: integer expected";
          }
          return null;
        };
        RuntimeControlStatus2.fromObject = function(object, _depth) {
          if (object instanceof $root.privoke.v1.RuntimeControlStatus)
            return object;
          if (!$util.isObject(object))
            throw $TypeError(".privoke.v1.RuntimeControlStatus: object expected");
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let message = new $root.privoke.v1.RuntimeControlStatus();
          if (object.enabled != null) {
            if (object.enabled)
              message.enabled = $Boolean(object.enabled);
          }
          if (object.status != null) {
            if (typeof object.status !== "string" || object.status.length)
              message.status = $String(object.status);
          }
          if (object.message != null) {
            if (typeof object.message !== "string" || object.message.length)
              message.message = $String(object.message);
          }
          if (object.processId != null) {
            if ($Number(object.processId) !== 0)
              message.processId = object.processId >>> 0;
          }
          return message;
        };
        RuntimeControlStatus2.toObject = function(message, options, _depth) {
          if (!options)
            options = {};
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let object = {};
          if (options.defaults) {
            object.enabled = false;
            object.status = "";
            object.message = "";
            object.processId = 0;
          }
          if (message.enabled != null && $Object.hasOwnProperty.call(message, "enabled"))
            object.enabled = message.enabled;
          if (message.status != null && $Object.hasOwnProperty.call(message, "status"))
            object.status = message.status;
          if (message.message != null && $Object.hasOwnProperty.call(message, "message"))
            object.message = message.message;
          if (message.processId != null && $Object.hasOwnProperty.call(message, "processId"))
            object.processId = message.processId;
          return object;
        };
        RuntimeControlStatus2.prototype.toJSON = function() {
          return RuntimeControlStatus2.toObject(this, import_minimal.default.util.toJSONOptions);
        };
        RuntimeControlStatus2.getTypeUrl = function(prefix) {
          if (prefix === $undefined)
            prefix = "type.googleapis.com";
          return prefix + "/privoke.v1.RuntimeControlStatus";
        };
        return RuntimeControlStatus2;
      })();
      v1.DetectionLayer = (function() {
        const valuesById = $Object.create(null), values = $Object.create(valuesById);
        values[valuesById[0] = "DETECTION_LAYER_UNSPECIFIED"] = 0;
        values[valuesById[1] = "DETECTION_LAYER_RUNTIME"] = 1;
        values[valuesById[2] = "DETECTION_LAYER_REGEX"] = 2;
        values[valuesById[3] = "DETECTION_LAYER_NER"] = 3;
        values[valuesById[4] = "DETECTION_LAYER_SEMANTIC"] = 4;
        return values;
      })();
      v1.RegexExecutionOrder = (function() {
        const valuesById = $Object.create(null), values = $Object.create(valuesById);
        values[valuesById[0] = "REGEX_EXECUTION_ORDER_DEFAULT"] = 0;
        values[valuesById[1] = "REGEX_EXECUTION_ORDER_FIRST"] = 1;
        values[valuesById[2] = "REGEX_EXECUTION_ORDER_PARALLEL"] = 2;
        return values;
      })();
      v1.AnalyzePromptRequest = (function() {
        const AnalyzePromptRequest = function(properties) {
          this.metadata = {};
          this.layers = [];
          if (properties) {
            for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
              if (properties[keys[i]] != null && keys[i] !== "__proto__")
                this[keys[i]] = properties[keys[i]];
          }
        };
        AnalyzePromptRequest.prototype.text = "";
        AnalyzePromptRequest.prototype.source = "";
        AnalyzePromptRequest.prototype.targetApp = "";
        AnalyzePromptRequest.prototype.visibilityHint = "";
        AnalyzePromptRequest.prototype.requestId = "";
        AnalyzePromptRequest.prototype.metadata = $util.emptyObject;
        AnalyzePromptRequest.prototype.layers = $util.emptyArray;
        AnalyzePromptRequest.prototype.regexExecutionOrder = 0;
        AnalyzePromptRequest.prototype.semanticModelId = "";
        AnalyzePromptRequest.create = function(properties) {
          return new AnalyzePromptRequest(properties);
        };
        AnalyzePromptRequest.encode = function(message, writer, _depth) {
          if (!writer)
            writer = $Writer.create();
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          if (message.text != null && $Object.hasOwnProperty.call(message, "text") && message.text !== "")
            writer.uint32(
              /* id 1, wireType 2 =*/
              10
            ).string(message.text);
          if (message.source != null && $Object.hasOwnProperty.call(message, "source") && message.source !== "")
            writer.uint32(
              /* id 2, wireType 2 =*/
              18
            ).string(message.source);
          if (message.targetApp != null && $Object.hasOwnProperty.call(message, "targetApp") && message.targetApp !== "")
            writer.uint32(
              /* id 3, wireType 2 =*/
              26
            ).string(message.targetApp);
          if (message.visibilityHint != null && $Object.hasOwnProperty.call(message, "visibilityHint") && message.visibilityHint !== "")
            writer.uint32(
              /* id 4, wireType 2 =*/
              34
            ).string(message.visibilityHint);
          if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId") && message.requestId !== "")
            writer.uint32(
              /* id 5, wireType 2 =*/
              42
            ).string(message.requestId);
          if (message.metadata != null && $Object.hasOwnProperty.call(message, "metadata"))
            for (let keys = $Object.keys(message.metadata), i = 0; i < keys.length; ++i)
              writer.uint32(
                /* id 6, wireType 2 =*/
                50
              ).fork().uint32(
                /* id 1, wireType 2 =*/
                10
              ).string(keys[i]).uint32(
                /* id 2, wireType 2 =*/
                18
              ).string(message.metadata[keys[i]]).ldelim();
          if (message.layers != null && message.layers.length)
            writer.uint32(
              /* id 7, wireType 2 =*/
              58
            ).int32s(message.layers);
          if (message.regexExecutionOrder != null && $Object.hasOwnProperty.call(message, "regexExecutionOrder") && message.regexExecutionOrder !== 0)
            writer.uint32(
              /* id 8, wireType 0 =*/
              64
            ).int32(message.regexExecutionOrder);
          if (message.semanticModelId != null && $Object.hasOwnProperty.call(message, "semanticModelId") && message.semanticModelId !== "")
            writer.uint32(
              /* id 9, wireType 2 =*/
              74
            ).string(message.semanticModelId);
          if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
            for (let i = 0; i < message.$unknowns.length; ++i)
              writer.raw(message.$unknowns[i]);
          return writer;
        };
        AnalyzePromptRequest.encodeDelimited = function(message, writer) {
          return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
        };
        AnalyzePromptRequest.decode = function(reader, length, _end, _depth, _target) {
          if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $Reader.recursionLimit)
            throw $Error("max depth exceeded");
          let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.AnalyzePromptRequest(), key, value;
          while (reader.pos < end) {
            let start = reader.pos;
            let tag = reader.tag();
            if (tag === _end) {
              _end = $undefined;
              break;
            }
            let wireType = tag & 7;
            switch (tag >>>= 3) {
              case 1: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.text = value;
                else
                  delete message.text;
                continue;
              }
              case 2: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.source = value;
                else
                  delete message.source;
                continue;
              }
              case 3: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.targetApp = value;
                else
                  delete message.targetApp;
                continue;
              }
              case 4: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.visibilityHint = value;
                else
                  delete message.visibilityHint;
                continue;
              }
              case 5: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.requestId = value;
                else
                  delete message.requestId;
                continue;
              }
              case 6: {
                if (wireType !== 2)
                  break;
                if (message.metadata === $util.emptyObject)
                  message.metadata = {};
                let end2 = reader.uint32() + reader.pos;
                key = "";
                value = "";
                while (reader.pos < end2) {
                  let tag2 = reader.tag();
                  wireType = tag2 & 7;
                  switch (tag2 >>>= 3) {
                    case 1:
                      if (wireType !== 2)
                        break;
                      key = reader.stringVerify();
                      continue;
                    case 2:
                      if (wireType !== 2)
                        break;
                      value = reader.stringVerify();
                      continue;
                  }
                  reader.skipType(wireType, _depth, tag2);
                }
                if (key === "__proto__")
                  $util.makeProp(message.metadata, key);
                message.metadata[key] = value;
                continue;
              }
              case 7: {
                if (wireType === 2) {
                  if (!(message.layers && message.layers.length))
                    message.layers = [];
                  reader.int32s(message.layers);
                  continue;
                }
                if (wireType !== 0)
                  break;
                if (!(message.layers && message.layers.length))
                  message.layers = [];
                message.layers.push(reader.int32());
                continue;
              }
              case 8: {
                if (wireType !== 0)
                  break;
                if (value = reader.int32())
                  message.regexExecutionOrder = value;
                else
                  delete message.regexExecutionOrder;
                continue;
              }
              case 9: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.semanticModelId = value;
                else
                  delete message.semanticModelId;
                continue;
              }
            }
            reader.skipType(wireType, _depth, tag);
            if (!reader.discardUnknown) {
              $util.makeProp(message, "$unknowns", false);
              (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
            }
          }
          if (_end !== $undefined)
            throw $Error("missing end group");
          return message;
        };
        AnalyzePromptRequest.decodeDelimited = function(reader) {
          if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
          return this.decode(reader, reader.uint32());
        };
        AnalyzePromptRequest.verify = function(message, _depth) {
          if (typeof message !== "object" || message === null)
            return "object expected";
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            return "max depth exceeded";
          if (message.text != null && $Object.hasOwnProperty.call(message, "text")) {
            if (!$util.isString(message.text))
              return "text: string expected";
          }
          if (message.source != null && $Object.hasOwnProperty.call(message, "source")) {
            if (!$util.isString(message.source))
              return "source: string expected";
          }
          if (message.targetApp != null && $Object.hasOwnProperty.call(message, "targetApp")) {
            if (!$util.isString(message.targetApp))
              return "targetApp: string expected";
          }
          if (message.visibilityHint != null && $Object.hasOwnProperty.call(message, "visibilityHint")) {
            if (!$util.isString(message.visibilityHint))
              return "visibilityHint: string expected";
          }
          if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId")) {
            if (!$util.isString(message.requestId))
              return "requestId: string expected";
          }
          if (message.metadata != null && $Object.hasOwnProperty.call(message, "metadata")) {
            if (!$util.isObject(message.metadata))
              return "metadata: object expected";
            let key = $Object.keys(message.metadata);
            for (let i = 0; i < key.length; ++i)
              if (!$util.isString(message.metadata[key[i]]))
                return "metadata: string{k:string} expected";
          }
          if (message.layers != null && $Object.hasOwnProperty.call(message, "layers")) {
            if (!$Array.isArray(message.layers))
              return "layers: array expected";
            for (let i = 0; i < message.layers.length; ++i)
              if (typeof message.layers[i] !== "number" || (message.layers[i] | 0) !== message.layers[i])
                return "layers: enum value[] expected";
          }
          if (message.regexExecutionOrder != null && $Object.hasOwnProperty.call(message, "regexExecutionOrder")) {
            if (typeof message.regexExecutionOrder !== "number" || (message.regexExecutionOrder | 0) !== message.regexExecutionOrder)
              return "regexExecutionOrder: enum value expected";
          }
          if (message.semanticModelId != null && $Object.hasOwnProperty.call(message, "semanticModelId")) {
            if (!$util.isString(message.semanticModelId))
              return "semanticModelId: string expected";
          }
          return null;
        };
        AnalyzePromptRequest.fromObject = function(object, _depth) {
          if (object instanceof $root.privoke.v1.AnalyzePromptRequest)
            return object;
          if (!$util.isObject(object))
            throw $TypeError(".privoke.v1.AnalyzePromptRequest: object expected");
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let message = new $root.privoke.v1.AnalyzePromptRequest();
          if (object.text != null) {
            if (typeof object.text !== "string" || object.text.length)
              message.text = $String(object.text);
          }
          if (object.source != null) {
            if (typeof object.source !== "string" || object.source.length)
              message.source = $String(object.source);
          }
          if (object.targetApp != null) {
            if (typeof object.targetApp !== "string" || object.targetApp.length)
              message.targetApp = $String(object.targetApp);
          }
          if (object.visibilityHint != null) {
            if (typeof object.visibilityHint !== "string" || object.visibilityHint.length)
              message.visibilityHint = $String(object.visibilityHint);
          }
          if (object.requestId != null) {
            if (typeof object.requestId !== "string" || object.requestId.length)
              message.requestId = $String(object.requestId);
          }
          if (object.metadata) {
            if (!$util.isObject(object.metadata))
              throw $TypeError(".privoke.v1.AnalyzePromptRequest.metadata: object expected");
            message.metadata = {};
            for (let keys = $Object.keys(object.metadata), i = 0; i < keys.length; ++i) {
              if (keys[i] === "__proto__")
                $util.makeProp(message.metadata, keys[i]);
              message.metadata[keys[i]] = $String(object.metadata[keys[i]]);
            }
          }
          if (object.layers) {
            if (!$Array.isArray(object.layers))
              throw $TypeError(".privoke.v1.AnalyzePromptRequest.layers: array expected");
            message.layers = [];
            for (let i = 0; i < object.layers.length; ++i)
              switch (object.layers[i]) {
                case "DETECTION_LAYER_UNSPECIFIED":
                case 0:
                  message.layers[message.layers.length] = 0;
                  break;
                case "DETECTION_LAYER_RUNTIME":
                case 1:
                  message.layers[message.layers.length] = 1;
                  break;
                case "DETECTION_LAYER_REGEX":
                case 2:
                  message.layers[message.layers.length] = 2;
                  break;
                case "DETECTION_LAYER_NER":
                case 3:
                  message.layers[message.layers.length] = 3;
                  break;
                case "DETECTION_LAYER_SEMANTIC":
                case 4:
                  message.layers[message.layers.length] = 4;
                  break;
                default:
                  if (typeof object.layers[i] === "number" && (object.layers[i] | 0) === object.layers[i])
                    message.layers[message.layers.length] = object.layers[i];
              }
          }
          if (object.regexExecutionOrder !== 0 && (typeof object.regexExecutionOrder !== "string" || $root.privoke.v1.RegexExecutionOrder[object.regexExecutionOrder] !== 0))
            switch (object.regexExecutionOrder) {
              case "REGEX_EXECUTION_ORDER_DEFAULT":
              case 0:
                message.regexExecutionOrder = 0;
                break;
              case "REGEX_EXECUTION_ORDER_FIRST":
              case 1:
                message.regexExecutionOrder = 1;
                break;
              case "REGEX_EXECUTION_ORDER_PARALLEL":
              case 2:
                message.regexExecutionOrder = 2;
                break;
              default:
                if (typeof object.regexExecutionOrder === "number" && (object.regexExecutionOrder | 0) === object.regexExecutionOrder)
                  message.regexExecutionOrder = object.regexExecutionOrder;
            }
          if (object.semanticModelId != null) {
            if (typeof object.semanticModelId !== "string" || object.semanticModelId.length)
              message.semanticModelId = $String(object.semanticModelId);
          }
          return message;
        };
        AnalyzePromptRequest.toObject = function(message, options, _depth) {
          if (!options)
            options = {};
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let object = {};
          if (options.arrays || options.defaults)
            object.layers = [];
          if (options.objects || options.defaults)
            object.metadata = {};
          if (options.defaults) {
            object.text = "";
            object.source = "";
            object.targetApp = "";
            object.visibilityHint = "";
            object.requestId = "";
            object.regexExecutionOrder = options.enums === $String ? "REGEX_EXECUTION_ORDER_DEFAULT" : 0;
            object.semanticModelId = "";
          }
          if (message.text != null && $Object.hasOwnProperty.call(message, "text"))
            object.text = message.text;
          if (message.source != null && $Object.hasOwnProperty.call(message, "source"))
            object.source = message.source;
          if (message.targetApp != null && $Object.hasOwnProperty.call(message, "targetApp"))
            object.targetApp = message.targetApp;
          if (message.visibilityHint != null && $Object.hasOwnProperty.call(message, "visibilityHint"))
            object.visibilityHint = message.visibilityHint;
          if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId"))
            object.requestId = message.requestId;
          let keys2;
          if (message.metadata && (keys2 = $Object.keys(message.metadata)).length) {
            object.metadata = {};
            for (let j = 0; j < keys2.length; ++j) {
              if (keys2[j] === "__proto__")
                $util.makeProp(object.metadata, keys2[j]);
              object.metadata[keys2[j]] = message.metadata[keys2[j]];
            }
          }
          if (message.layers && message.layers.length) {
            object.layers = $Array(message.layers.length);
            for (let j = 0; j < message.layers.length; ++j)
              object.layers[j] = options.enums === $String ? $root.privoke.v1.DetectionLayer[message.layers[j]] === $undefined ? message.layers[j] : $root.privoke.v1.DetectionLayer[message.layers[j]] : message.layers[j];
          }
          if (message.regexExecutionOrder != null && $Object.hasOwnProperty.call(message, "regexExecutionOrder"))
            object.regexExecutionOrder = options.enums === $String ? $root.privoke.v1.RegexExecutionOrder[message.regexExecutionOrder] === $undefined ? message.regexExecutionOrder : $root.privoke.v1.RegexExecutionOrder[message.regexExecutionOrder] : message.regexExecutionOrder;
          if (message.semanticModelId != null && $Object.hasOwnProperty.call(message, "semanticModelId"))
            object.semanticModelId = message.semanticModelId;
          return object;
        };
        AnalyzePromptRequest.prototype.toJSON = function() {
          return AnalyzePromptRequest.toObject(this, import_minimal.default.util.toJSONOptions);
        };
        AnalyzePromptRequest.getTypeUrl = function(prefix) {
          if (prefix === $undefined)
            prefix = "type.googleapis.com";
          return prefix + "/privoke.v1.AnalyzePromptRequest";
        };
        return AnalyzePromptRequest;
      })();
      v1.RuntimeLayerExecution = (function() {
        const RuntimeLayerExecution = function(properties) {
          this.results = [];
          if (properties) {
            for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
              if (properties[keys[i]] != null && keys[i] !== "__proto__")
                this[keys[i]] = properties[keys[i]];
          }
        };
        RuntimeLayerExecution.prototype.layer = 0;
        RuntimeLayerExecution.prototype.status = "";
        RuntimeLayerExecution.prototype.results = $util.emptyArray;
        RuntimeLayerExecution.prototype.error = "";
        RuntimeLayerExecution.create = function(properties) {
          return new RuntimeLayerExecution(properties);
        };
        RuntimeLayerExecution.encode = function(message, writer, _depth) {
          if (!writer)
            writer = $Writer.create();
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          if (message.layer != null && $Object.hasOwnProperty.call(message, "layer") && message.layer !== 0)
            writer.uint32(
              /* id 1, wireType 0 =*/
              8
            ).int32(message.layer);
          if (message.status != null && $Object.hasOwnProperty.call(message, "status") && message.status !== "")
            writer.uint32(
              /* id 2, wireType 2 =*/
              18
            ).string(message.status);
          if (message.results != null && message.results.length)
            for (let i = 0; i < message.results.length; ++i)
              $root.privoke.v1.RuntimeDetectionResult.encode(message.results[i], writer.uint32(
                /* id 3, wireType 2 =*/
                26
              ).fork(), _depth + 1).ldelim();
          if (message.error != null && $Object.hasOwnProperty.call(message, "error") && message.error !== "")
            writer.uint32(
              /* id 4, wireType 2 =*/
              34
            ).string(message.error);
          if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
            for (let i = 0; i < message.$unknowns.length; ++i)
              writer.raw(message.$unknowns[i]);
          return writer;
        };
        RuntimeLayerExecution.encodeDelimited = function(message, writer) {
          return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
        };
        RuntimeLayerExecution.decode = function(reader, length, _end, _depth, _target) {
          if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $Reader.recursionLimit)
            throw $Error("max depth exceeded");
          let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.RuntimeLayerExecution(), value;
          while (reader.pos < end) {
            let start = reader.pos;
            let tag = reader.tag();
            if (tag === _end) {
              _end = $undefined;
              break;
            }
            let wireType = tag & 7;
            switch (tag >>>= 3) {
              case 1: {
                if (wireType !== 0)
                  break;
                if (value = reader.int32())
                  message.layer = value;
                else
                  delete message.layer;
                continue;
              }
              case 2: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.status = value;
                else
                  delete message.status;
                continue;
              }
              case 3: {
                if (wireType !== 2)
                  break;
                if (!(message.results && message.results.length))
                  message.results = [];
                message.results.push($root.privoke.v1.RuntimeDetectionResult.decode(reader, reader.uint32(), $undefined, _depth + 1));
                continue;
              }
              case 4: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.error = value;
                else
                  delete message.error;
                continue;
              }
            }
            reader.skipType(wireType, _depth, tag);
            if (!reader.discardUnknown) {
              $util.makeProp(message, "$unknowns", false);
              (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
            }
          }
          if (_end !== $undefined)
            throw $Error("missing end group");
          return message;
        };
        RuntimeLayerExecution.decodeDelimited = function(reader) {
          if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
          return this.decode(reader, reader.uint32());
        };
        RuntimeLayerExecution.verify = function(message, _depth) {
          if (typeof message !== "object" || message === null)
            return "object expected";
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            return "max depth exceeded";
          if (message.layer != null && $Object.hasOwnProperty.call(message, "layer")) {
            if (typeof message.layer !== "number" || (message.layer | 0) !== message.layer)
              return "layer: enum value expected";
          }
          if (message.status != null && $Object.hasOwnProperty.call(message, "status")) {
            if (!$util.isString(message.status))
              return "status: string expected";
          }
          if (message.results != null && $Object.hasOwnProperty.call(message, "results")) {
            if (!$Array.isArray(message.results))
              return "results: array expected";
            for (let i = 0; i < message.results.length; ++i) {
              let error = $root.privoke.v1.RuntimeDetectionResult.verify(message.results[i], _depth + 1);
              if (error)
                return "results." + error;
            }
          }
          if (message.error != null && $Object.hasOwnProperty.call(message, "error")) {
            if (!$util.isString(message.error))
              return "error: string expected";
          }
          return null;
        };
        RuntimeLayerExecution.fromObject = function(object, _depth) {
          if (object instanceof $root.privoke.v1.RuntimeLayerExecution)
            return object;
          if (!$util.isObject(object))
            throw $TypeError(".privoke.v1.RuntimeLayerExecution: object expected");
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let message = new $root.privoke.v1.RuntimeLayerExecution();
          if (object.layer !== 0 && (typeof object.layer !== "string" || $root.privoke.v1.DetectionLayer[object.layer] !== 0))
            switch (object.layer) {
              case "DETECTION_LAYER_UNSPECIFIED":
              case 0:
                message.layer = 0;
                break;
              case "DETECTION_LAYER_RUNTIME":
              case 1:
                message.layer = 1;
                break;
              case "DETECTION_LAYER_REGEX":
              case 2:
                message.layer = 2;
                break;
              case "DETECTION_LAYER_NER":
              case 3:
                message.layer = 3;
                break;
              case "DETECTION_LAYER_SEMANTIC":
              case 4:
                message.layer = 4;
                break;
              default:
                if (typeof object.layer === "number" && (object.layer | 0) === object.layer)
                  message.layer = object.layer;
            }
          if (object.status != null) {
            if (typeof object.status !== "string" || object.status.length)
              message.status = $String(object.status);
          }
          if (object.results) {
            if (!$Array.isArray(object.results))
              throw $TypeError(".privoke.v1.RuntimeLayerExecution.results: array expected");
            message.results = $Array(object.results.length);
            for (let i = 0; i < object.results.length; ++i) {
              if (!$util.isObject(object.results[i]))
                throw $TypeError(".privoke.v1.RuntimeLayerExecution.results: object expected");
              message.results[i] = $root.privoke.v1.RuntimeDetectionResult.fromObject(object.results[i], _depth + 1);
            }
          }
          if (object.error != null) {
            if (typeof object.error !== "string" || object.error.length)
              message.error = $String(object.error);
          }
          return message;
        };
        RuntimeLayerExecution.toObject = function(message, options, _depth) {
          if (!options)
            options = {};
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let object = {};
          if (options.arrays || options.defaults)
            object.results = [];
          if (options.defaults) {
            object.layer = options.enums === $String ? "DETECTION_LAYER_UNSPECIFIED" : 0;
            object.status = "";
            object.error = "";
          }
          if (message.layer != null && $Object.hasOwnProperty.call(message, "layer"))
            object.layer = options.enums === $String ? $root.privoke.v1.DetectionLayer[message.layer] === $undefined ? message.layer : $root.privoke.v1.DetectionLayer[message.layer] : message.layer;
          if (message.status != null && $Object.hasOwnProperty.call(message, "status"))
            object.status = message.status;
          if (message.results && message.results.length) {
            object.results = $Array(message.results.length);
            for (let j = 0; j < message.results.length; ++j)
              object.results[j] = $root.privoke.v1.RuntimeDetectionResult.toObject(message.results[j], options, _depth + 1);
          }
          if (message.error != null && $Object.hasOwnProperty.call(message, "error"))
            object.error = message.error;
          return object;
        };
        RuntimeLayerExecution.prototype.toJSON = function() {
          return RuntimeLayerExecution.toObject(this, import_minimal.default.util.toJSONOptions);
        };
        RuntimeLayerExecution.getTypeUrl = function(prefix) {
          if (prefix === $undefined)
            prefix = "type.googleapis.com";
          return prefix + "/privoke.v1.RuntimeLayerExecution";
        };
        return RuntimeLayerExecution;
      })();
      v1.RuntimeClassification = (function() {
        const RuntimeClassification = function(properties) {
          this.categories = [];
          if (properties) {
            for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
              if (properties[keys[i]] != null && keys[i] !== "__proto__")
                this[keys[i]] = properties[keys[i]];
          }
        };
        RuntimeClassification.prototype.sensitivity = "";
        RuntimeClassification.prototype.visibility = "";
        RuntimeClassification.prototype.categories = $util.emptyArray;
        RuntimeClassification.prototype.packed = 0;
        RuntimeClassification.create = function(properties) {
          return new RuntimeClassification(properties);
        };
        RuntimeClassification.encode = function(message, writer, _depth) {
          if (!writer)
            writer = $Writer.create();
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          if (message.sensitivity != null && $Object.hasOwnProperty.call(message, "sensitivity") && message.sensitivity !== "")
            writer.uint32(
              /* id 1, wireType 2 =*/
              10
            ).string(message.sensitivity);
          if (message.visibility != null && $Object.hasOwnProperty.call(message, "visibility") && message.visibility !== "")
            writer.uint32(
              /* id 2, wireType 2 =*/
              18
            ).string(message.visibility);
          if (message.categories != null && message.categories.length)
            for (let i = 0; i < message.categories.length; ++i)
              writer.uint32(
                /* id 3, wireType 2 =*/
                26
              ).string(message.categories[i]);
          if (message.packed != null && $Object.hasOwnProperty.call(message, "packed") && message.packed !== 0)
            writer.uint32(
              /* id 4, wireType 0 =*/
              32
            ).uint32(message.packed);
          if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
            for (let i = 0; i < message.$unknowns.length; ++i)
              writer.raw(message.$unknowns[i]);
          return writer;
        };
        RuntimeClassification.encodeDelimited = function(message, writer) {
          return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
        };
        RuntimeClassification.decode = function(reader, length, _end, _depth, _target) {
          if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $Reader.recursionLimit)
            throw $Error("max depth exceeded");
          let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.RuntimeClassification(), value;
          while (reader.pos < end) {
            let start = reader.pos;
            let tag = reader.tag();
            if (tag === _end) {
              _end = $undefined;
              break;
            }
            let wireType = tag & 7;
            switch (tag >>>= 3) {
              case 1: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.sensitivity = value;
                else
                  delete message.sensitivity;
                continue;
              }
              case 2: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.visibility = value;
                else
                  delete message.visibility;
                continue;
              }
              case 3: {
                if (wireType !== 2)
                  break;
                if (!(message.categories && message.categories.length))
                  message.categories = [];
                message.categories.push(reader.stringVerify());
                continue;
              }
              case 4: {
                if (wireType !== 0)
                  break;
                if (value = reader.uint32())
                  message.packed = value;
                else
                  delete message.packed;
                continue;
              }
            }
            reader.skipType(wireType, _depth, tag);
            if (!reader.discardUnknown) {
              $util.makeProp(message, "$unknowns", false);
              (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
            }
          }
          if (_end !== $undefined)
            throw $Error("missing end group");
          return message;
        };
        RuntimeClassification.decodeDelimited = function(reader) {
          if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
          return this.decode(reader, reader.uint32());
        };
        RuntimeClassification.verify = function(message, _depth) {
          if (typeof message !== "object" || message === null)
            return "object expected";
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            return "max depth exceeded";
          if (message.sensitivity != null && $Object.hasOwnProperty.call(message, "sensitivity")) {
            if (!$util.isString(message.sensitivity))
              return "sensitivity: string expected";
          }
          if (message.visibility != null && $Object.hasOwnProperty.call(message, "visibility")) {
            if (!$util.isString(message.visibility))
              return "visibility: string expected";
          }
          if (message.categories != null && $Object.hasOwnProperty.call(message, "categories")) {
            if (!$Array.isArray(message.categories))
              return "categories: array expected";
            for (let i = 0; i < message.categories.length; ++i)
              if (!$util.isString(message.categories[i]))
                return "categories: string[] expected";
          }
          if (message.packed != null && $Object.hasOwnProperty.call(message, "packed")) {
            if (!$util.isInteger(message.packed))
              return "packed: integer expected";
          }
          return null;
        };
        RuntimeClassification.fromObject = function(object, _depth) {
          if (object instanceof $root.privoke.v1.RuntimeClassification)
            return object;
          if (!$util.isObject(object))
            throw $TypeError(".privoke.v1.RuntimeClassification: object expected");
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let message = new $root.privoke.v1.RuntimeClassification();
          if (object.sensitivity != null) {
            if (typeof object.sensitivity !== "string" || object.sensitivity.length)
              message.sensitivity = $String(object.sensitivity);
          }
          if (object.visibility != null) {
            if (typeof object.visibility !== "string" || object.visibility.length)
              message.visibility = $String(object.visibility);
          }
          if (object.categories) {
            if (!$Array.isArray(object.categories))
              throw $TypeError(".privoke.v1.RuntimeClassification.categories: array expected");
            message.categories = $Array(object.categories.length);
            for (let i = 0; i < object.categories.length; ++i)
              message.categories[i] = $String(object.categories[i]);
          }
          if (object.packed != null) {
            if ($Number(object.packed) !== 0)
              message.packed = object.packed >>> 0;
          }
          return message;
        };
        RuntimeClassification.toObject = function(message, options, _depth) {
          if (!options)
            options = {};
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let object = {};
          if (options.arrays || options.defaults)
            object.categories = [];
          if (options.defaults) {
            object.sensitivity = "";
            object.visibility = "";
            object.packed = 0;
          }
          if (message.sensitivity != null && $Object.hasOwnProperty.call(message, "sensitivity"))
            object.sensitivity = message.sensitivity;
          if (message.visibility != null && $Object.hasOwnProperty.call(message, "visibility"))
            object.visibility = message.visibility;
          if (message.categories && message.categories.length) {
            object.categories = $Array(message.categories.length);
            for (let j = 0; j < message.categories.length; ++j)
              object.categories[j] = message.categories[j];
          }
          if (message.packed != null && $Object.hasOwnProperty.call(message, "packed"))
            object.packed = message.packed;
          return object;
        };
        RuntimeClassification.prototype.toJSON = function() {
          return RuntimeClassification.toObject(this, import_minimal.default.util.toJSONOptions);
        };
        RuntimeClassification.getTypeUrl = function(prefix) {
          if (prefix === $undefined)
            prefix = "type.googleapis.com";
          return prefix + "/privoke.v1.RuntimeClassification";
        };
        return RuntimeClassification;
      })();
      v1.RuntimeDetectionResult = (function() {
        const RuntimeDetectionResult = function(properties) {
          this.metadata = {};
          if (properties) {
            for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
              if (properties[keys[i]] != null && keys[i] !== "__proto__")
                this[keys[i]] = properties[keys[i]];
          }
        };
        RuntimeDetectionResult.prototype.classification = null;
        RuntimeDetectionResult.prototype.action = "";
        RuntimeDetectionResult.prototype.sectionOfText = "";
        RuntimeDetectionResult.prototype.spanStart = 0;
        RuntimeDetectionResult.prototype.spanEnd = 0;
        RuntimeDetectionResult.prototype.hasSpan = false;
        RuntimeDetectionResult.prototype.confidence = 0;
        RuntimeDetectionResult.prototype.hasConfidence = false;
        RuntimeDetectionResult.prototype.reasoning = "";
        RuntimeDetectionResult.prototype.metadata = $util.emptyObject;
        RuntimeDetectionResult.create = function(properties) {
          return new RuntimeDetectionResult(properties);
        };
        RuntimeDetectionResult.encode = function(message, writer, _depth) {
          if (!writer)
            writer = $Writer.create();
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          if (message.classification != null && $Object.hasOwnProperty.call(message, "classification"))
            $root.privoke.v1.RuntimeClassification.encode(message.classification, writer.uint32(
              /* id 1, wireType 2 =*/
              10
            ).fork(), _depth + 1).ldelim();
          if (message.action != null && $Object.hasOwnProperty.call(message, "action") && message.action !== "")
            writer.uint32(
              /* id 2, wireType 2 =*/
              18
            ).string(message.action);
          if (message.sectionOfText != null && $Object.hasOwnProperty.call(message, "sectionOfText") && message.sectionOfText !== "")
            writer.uint32(
              /* id 3, wireType 2 =*/
              26
            ).string(message.sectionOfText);
          if (message.spanStart != null && $Object.hasOwnProperty.call(message, "spanStart") && message.spanStart !== 0)
            writer.uint32(
              /* id 4, wireType 0 =*/
              32
            ).int32(message.spanStart);
          if (message.spanEnd != null && $Object.hasOwnProperty.call(message, "spanEnd") && message.spanEnd !== 0)
            writer.uint32(
              /* id 5, wireType 0 =*/
              40
            ).int32(message.spanEnd);
          if (message.hasSpan != null && $Object.hasOwnProperty.call(message, "hasSpan") && message.hasSpan !== false)
            writer.uint32(
              /* id 6, wireType 0 =*/
              48
            ).bool(message.hasSpan);
          if (message.confidence != null && $Object.hasOwnProperty.call(message, "confidence") && !$Object.is(message.confidence, 0))
            writer.uint32(
              /* id 7, wireType 1 =*/
              57
            ).double(message.confidence);
          if (message.hasConfidence != null && $Object.hasOwnProperty.call(message, "hasConfidence") && message.hasConfidence !== false)
            writer.uint32(
              /* id 8, wireType 0 =*/
              64
            ).bool(message.hasConfidence);
          if (message.reasoning != null && $Object.hasOwnProperty.call(message, "reasoning") && message.reasoning !== "")
            writer.uint32(
              /* id 9, wireType 2 =*/
              74
            ).string(message.reasoning);
          if (message.metadata != null && $Object.hasOwnProperty.call(message, "metadata"))
            for (let keys = $Object.keys(message.metadata), i = 0; i < keys.length; ++i)
              writer.uint32(
                /* id 10, wireType 2 =*/
                82
              ).fork().uint32(
                /* id 1, wireType 2 =*/
                10
              ).string(keys[i]).uint32(
                /* id 2, wireType 2 =*/
                18
              ).string(message.metadata[keys[i]]).ldelim();
          if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
            for (let i = 0; i < message.$unknowns.length; ++i)
              writer.raw(message.$unknowns[i]);
          return writer;
        };
        RuntimeDetectionResult.encodeDelimited = function(message, writer) {
          return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
        };
        RuntimeDetectionResult.decode = function(reader, length, _end, _depth, _target) {
          if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $Reader.recursionLimit)
            throw $Error("max depth exceeded");
          let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.RuntimeDetectionResult(), key, value;
          while (reader.pos < end) {
            let start = reader.pos;
            let tag = reader.tag();
            if (tag === _end) {
              _end = $undefined;
              break;
            }
            let wireType = tag & 7;
            switch (tag >>>= 3) {
              case 1: {
                if (wireType !== 2)
                  break;
                message.classification = $root.privoke.v1.RuntimeClassification.decode(reader, reader.uint32(), $undefined, _depth + 1, message.classification);
                continue;
              }
              case 2: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.action = value;
                else
                  delete message.action;
                continue;
              }
              case 3: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.sectionOfText = value;
                else
                  delete message.sectionOfText;
                continue;
              }
              case 4: {
                if (wireType !== 0)
                  break;
                if (value = reader.int32())
                  message.spanStart = value;
                else
                  delete message.spanStart;
                continue;
              }
              case 5: {
                if (wireType !== 0)
                  break;
                if (value = reader.int32())
                  message.spanEnd = value;
                else
                  delete message.spanEnd;
                continue;
              }
              case 6: {
                if (wireType !== 0)
                  break;
                if (value = reader.bool())
                  message.hasSpan = value;
                else
                  delete message.hasSpan;
                continue;
              }
              case 7: {
                if (wireType !== 1)
                  break;
                if (!$Object.is(value = reader.double(), 0))
                  message.confidence = value;
                else
                  delete message.confidence;
                continue;
              }
              case 8: {
                if (wireType !== 0)
                  break;
                if (value = reader.bool())
                  message.hasConfidence = value;
                else
                  delete message.hasConfidence;
                continue;
              }
              case 9: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.reasoning = value;
                else
                  delete message.reasoning;
                continue;
              }
              case 10: {
                if (wireType !== 2)
                  break;
                if (message.metadata === $util.emptyObject)
                  message.metadata = {};
                let end2 = reader.uint32() + reader.pos;
                key = "";
                value = "";
                while (reader.pos < end2) {
                  let tag2 = reader.tag();
                  wireType = tag2 & 7;
                  switch (tag2 >>>= 3) {
                    case 1:
                      if (wireType !== 2)
                        break;
                      key = reader.stringVerify();
                      continue;
                    case 2:
                      if (wireType !== 2)
                        break;
                      value = reader.stringVerify();
                      continue;
                  }
                  reader.skipType(wireType, _depth, tag2);
                }
                if (key === "__proto__")
                  $util.makeProp(message.metadata, key);
                message.metadata[key] = value;
                continue;
              }
            }
            reader.skipType(wireType, _depth, tag);
            if (!reader.discardUnknown) {
              $util.makeProp(message, "$unknowns", false);
              (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
            }
          }
          if (_end !== $undefined)
            throw $Error("missing end group");
          return message;
        };
        RuntimeDetectionResult.decodeDelimited = function(reader) {
          if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
          return this.decode(reader, reader.uint32());
        };
        RuntimeDetectionResult.verify = function(message, _depth) {
          if (typeof message !== "object" || message === null)
            return "object expected";
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            return "max depth exceeded";
          if (message.classification != null && $Object.hasOwnProperty.call(message, "classification")) {
            let error = $root.privoke.v1.RuntimeClassification.verify(message.classification, _depth + 1);
            if (error)
              return "classification." + error;
          }
          if (message.action != null && $Object.hasOwnProperty.call(message, "action")) {
            if (!$util.isString(message.action))
              return "action: string expected";
          }
          if (message.sectionOfText != null && $Object.hasOwnProperty.call(message, "sectionOfText")) {
            if (!$util.isString(message.sectionOfText))
              return "sectionOfText: string expected";
          }
          if (message.spanStart != null && $Object.hasOwnProperty.call(message, "spanStart")) {
            if (!$util.isInteger(message.spanStart))
              return "spanStart: integer expected";
          }
          if (message.spanEnd != null && $Object.hasOwnProperty.call(message, "spanEnd")) {
            if (!$util.isInteger(message.spanEnd))
              return "spanEnd: integer expected";
          }
          if (message.hasSpan != null && $Object.hasOwnProperty.call(message, "hasSpan")) {
            if (typeof message.hasSpan !== "boolean")
              return "hasSpan: boolean expected";
          }
          if (message.confidence != null && $Object.hasOwnProperty.call(message, "confidence")) {
            if (typeof message.confidence !== "number")
              return "confidence: number expected";
          }
          if (message.hasConfidence != null && $Object.hasOwnProperty.call(message, "hasConfidence")) {
            if (typeof message.hasConfidence !== "boolean")
              return "hasConfidence: boolean expected";
          }
          if (message.reasoning != null && $Object.hasOwnProperty.call(message, "reasoning")) {
            if (!$util.isString(message.reasoning))
              return "reasoning: string expected";
          }
          if (message.metadata != null && $Object.hasOwnProperty.call(message, "metadata")) {
            if (!$util.isObject(message.metadata))
              return "metadata: object expected";
            let key = $Object.keys(message.metadata);
            for (let i = 0; i < key.length; ++i)
              if (!$util.isString(message.metadata[key[i]]))
                return "metadata: string{k:string} expected";
          }
          return null;
        };
        RuntimeDetectionResult.fromObject = function(object, _depth) {
          if (object instanceof $root.privoke.v1.RuntimeDetectionResult)
            return object;
          if (!$util.isObject(object))
            throw $TypeError(".privoke.v1.RuntimeDetectionResult: object expected");
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let message = new $root.privoke.v1.RuntimeDetectionResult();
          if (object.classification != null) {
            if (!$util.isObject(object.classification))
              throw $TypeError(".privoke.v1.RuntimeDetectionResult.classification: object expected");
            message.classification = $root.privoke.v1.RuntimeClassification.fromObject(object.classification, _depth + 1);
          }
          if (object.action != null) {
            if (typeof object.action !== "string" || object.action.length)
              message.action = $String(object.action);
          }
          if (object.sectionOfText != null) {
            if (typeof object.sectionOfText !== "string" || object.sectionOfText.length)
              message.sectionOfText = $String(object.sectionOfText);
          }
          if (object.spanStart != null) {
            if ($Number(object.spanStart) !== 0)
              message.spanStart = object.spanStart | 0;
          }
          if (object.spanEnd != null) {
            if ($Number(object.spanEnd) !== 0)
              message.spanEnd = object.spanEnd | 0;
          }
          if (object.hasSpan != null) {
            if (object.hasSpan)
              message.hasSpan = $Boolean(object.hasSpan);
          }
          if (object.confidence != null) {
            if (!$Object.is($Number(object.confidence), 0))
              message.confidence = $Number(object.confidence);
          }
          if (object.hasConfidence != null) {
            if (object.hasConfidence)
              message.hasConfidence = $Boolean(object.hasConfidence);
          }
          if (object.reasoning != null) {
            if (typeof object.reasoning !== "string" || object.reasoning.length)
              message.reasoning = $String(object.reasoning);
          }
          if (object.metadata) {
            if (!$util.isObject(object.metadata))
              throw $TypeError(".privoke.v1.RuntimeDetectionResult.metadata: object expected");
            message.metadata = {};
            for (let keys = $Object.keys(object.metadata), i = 0; i < keys.length; ++i) {
              if (keys[i] === "__proto__")
                $util.makeProp(message.metadata, keys[i]);
              message.metadata[keys[i]] = $String(object.metadata[keys[i]]);
            }
          }
          return message;
        };
        RuntimeDetectionResult.toObject = function(message, options, _depth) {
          if (!options)
            options = {};
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let object = {};
          if (options.objects || options.defaults)
            object.metadata = {};
          if (options.defaults) {
            object.classification = null;
            object.action = "";
            object.sectionOfText = "";
            object.spanStart = 0;
            object.spanEnd = 0;
            object.hasSpan = false;
            object.confidence = 0;
            object.hasConfidence = false;
            object.reasoning = "";
          }
          if (message.classification != null && $Object.hasOwnProperty.call(message, "classification"))
            object.classification = $root.privoke.v1.RuntimeClassification.toObject(message.classification, options, _depth + 1);
          if (message.action != null && $Object.hasOwnProperty.call(message, "action"))
            object.action = message.action;
          if (message.sectionOfText != null && $Object.hasOwnProperty.call(message, "sectionOfText"))
            object.sectionOfText = message.sectionOfText;
          if (message.spanStart != null && $Object.hasOwnProperty.call(message, "spanStart"))
            object.spanStart = message.spanStart;
          if (message.spanEnd != null && $Object.hasOwnProperty.call(message, "spanEnd"))
            object.spanEnd = message.spanEnd;
          if (message.hasSpan != null && $Object.hasOwnProperty.call(message, "hasSpan"))
            object.hasSpan = message.hasSpan;
          if (message.confidence != null && $Object.hasOwnProperty.call(message, "confidence"))
            object.confidence = options.json && !$isFinite(message.confidence) ? $String(message.confidence) : message.confidence;
          if (message.hasConfidence != null && $Object.hasOwnProperty.call(message, "hasConfidence"))
            object.hasConfidence = message.hasConfidence;
          if (message.reasoning != null && $Object.hasOwnProperty.call(message, "reasoning"))
            object.reasoning = message.reasoning;
          let keys2;
          if (message.metadata && (keys2 = $Object.keys(message.metadata)).length) {
            object.metadata = {};
            for (let j = 0; j < keys2.length; ++j) {
              if (keys2[j] === "__proto__")
                $util.makeProp(object.metadata, keys2[j]);
              object.metadata[keys2[j]] = message.metadata[keys2[j]];
            }
          }
          return object;
        };
        RuntimeDetectionResult.prototype.toJSON = function() {
          return RuntimeDetectionResult.toObject(this, import_minimal.default.util.toJSONOptions);
        };
        RuntimeDetectionResult.getTypeUrl = function(prefix) {
          if (prefix === $undefined)
            prefix = "type.googleapis.com";
          return prefix + "/privoke.v1.RuntimeDetectionResult";
        };
        return RuntimeDetectionResult;
      })();
      v1.AnalyzePromptResponse = (function() {
        const AnalyzePromptResponse = function(properties) {
          this.metadata = {};
          this.layers = [];
          if (properties) {
            for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
              if (properties[keys[i]] != null && keys[i] !== "__proto__")
                this[keys[i]] = properties[keys[i]];
          }
        };
        AnalyzePromptResponse.prototype.requestId = "";
        AnalyzePromptResponse.prototype.action = "";
        AnalyzePromptResponse.prototype.allowed = false;
        AnalyzePromptResponse.prototype.maskedText = "";
        AnalyzePromptResponse.prototype.classification = null;
        AnalyzePromptResponse.prototype.reason = "";
        AnalyzePromptResponse.prototype.evidence = null;
        AnalyzePromptResponse.prototype.metadata = $util.emptyObject;
        AnalyzePromptResponse.prototype.layers = $util.emptyArray;
        AnalyzePromptResponse.prototype.elapsedMs = 0;
        AnalyzePromptResponse.prototype.error = "";
        AnalyzePromptResponse.create = function(properties) {
          return new AnalyzePromptResponse(properties);
        };
        AnalyzePromptResponse.encode = function(message, writer, _depth) {
          if (!writer)
            writer = $Writer.create();
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId") && message.requestId !== "")
            writer.uint32(
              /* id 1, wireType 2 =*/
              10
            ).string(message.requestId);
          if (message.action != null && $Object.hasOwnProperty.call(message, "action") && message.action !== "")
            writer.uint32(
              /* id 2, wireType 2 =*/
              18
            ).string(message.action);
          if (message.allowed != null && $Object.hasOwnProperty.call(message, "allowed") && message.allowed !== false)
            writer.uint32(
              /* id 3, wireType 0 =*/
              24
            ).bool(message.allowed);
          if (message.maskedText != null && $Object.hasOwnProperty.call(message, "maskedText") && message.maskedText !== "")
            writer.uint32(
              /* id 4, wireType 2 =*/
              34
            ).string(message.maskedText);
          if (message.classification != null && $Object.hasOwnProperty.call(message, "classification"))
            $root.privoke.v1.RuntimeClassification.encode(message.classification, writer.uint32(
              /* id 5, wireType 2 =*/
              42
            ).fork(), _depth + 1).ldelim();
          if (message.reason != null && $Object.hasOwnProperty.call(message, "reason") && message.reason !== "")
            writer.uint32(
              /* id 6, wireType 2 =*/
              50
            ).string(message.reason);
          if (message.evidence != null && $Object.hasOwnProperty.call(message, "evidence"))
            $root.privoke.v1.RuntimeDetectionResult.encode(message.evidence, writer.uint32(
              /* id 7, wireType 2 =*/
              58
            ).fork(), _depth + 1).ldelim();
          if (message.metadata != null && $Object.hasOwnProperty.call(message, "metadata"))
            for (let keys = $Object.keys(message.metadata), i = 0; i < keys.length; ++i)
              writer.uint32(
                /* id 8, wireType 2 =*/
                66
              ).fork().uint32(
                /* id 1, wireType 2 =*/
                10
              ).string(keys[i]).uint32(
                /* id 2, wireType 2 =*/
                18
              ).string(message.metadata[keys[i]]).ldelim();
          if (message.layers != null && message.layers.length)
            for (let i = 0; i < message.layers.length; ++i)
              $root.privoke.v1.RuntimeLayerExecution.encode(message.layers[i], writer.uint32(
                /* id 10, wireType 2 =*/
                82
              ).fork(), _depth + 1).ldelim();
          if (message.elapsedMs != null && $Object.hasOwnProperty.call(message, "elapsedMs") && !$Object.is(message.elapsedMs, 0))
            writer.uint32(
              /* id 11, wireType 1 =*/
              89
            ).double(message.elapsedMs);
          if (message.error != null && $Object.hasOwnProperty.call(message, "error") && message.error !== "")
            writer.uint32(
              /* id 12, wireType 2 =*/
              98
            ).string(message.error);
          if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
            for (let i = 0; i < message.$unknowns.length; ++i)
              writer.raw(message.$unknowns[i]);
          return writer;
        };
        AnalyzePromptResponse.encodeDelimited = function(message, writer) {
          return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
        };
        AnalyzePromptResponse.decode = function(reader, length, _end, _depth, _target) {
          if (!(reader instanceof $Reader))
            reader = $Reader.create(reader);
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $Reader.recursionLimit)
            throw $Error("max depth exceeded");
          let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.AnalyzePromptResponse(), key, value;
          while (reader.pos < end) {
            let start = reader.pos;
            let tag = reader.tag();
            if (tag === _end) {
              _end = $undefined;
              break;
            }
            let wireType = tag & 7;
            switch (tag >>>= 3) {
              case 1: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.requestId = value;
                else
                  delete message.requestId;
                continue;
              }
              case 2: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.action = value;
                else
                  delete message.action;
                continue;
              }
              case 3: {
                if (wireType !== 0)
                  break;
                if (value = reader.bool())
                  message.allowed = value;
                else
                  delete message.allowed;
                continue;
              }
              case 4: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.maskedText = value;
                else
                  delete message.maskedText;
                continue;
              }
              case 5: {
                if (wireType !== 2)
                  break;
                message.classification = $root.privoke.v1.RuntimeClassification.decode(reader, reader.uint32(), $undefined, _depth + 1, message.classification);
                continue;
              }
              case 6: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.reason = value;
                else
                  delete message.reason;
                continue;
              }
              case 7: {
                if (wireType !== 2)
                  break;
                message.evidence = $root.privoke.v1.RuntimeDetectionResult.decode(reader, reader.uint32(), $undefined, _depth + 1, message.evidence);
                continue;
              }
              case 8: {
                if (wireType !== 2)
                  break;
                if (message.metadata === $util.emptyObject)
                  message.metadata = {};
                let end2 = reader.uint32() + reader.pos;
                key = "";
                value = "";
                while (reader.pos < end2) {
                  let tag2 = reader.tag();
                  wireType = tag2 & 7;
                  switch (tag2 >>>= 3) {
                    case 1:
                      if (wireType !== 2)
                        break;
                      key = reader.stringVerify();
                      continue;
                    case 2:
                      if (wireType !== 2)
                        break;
                      value = reader.stringVerify();
                      continue;
                  }
                  reader.skipType(wireType, _depth, tag2);
                }
                if (key === "__proto__")
                  $util.makeProp(message.metadata, key);
                message.metadata[key] = value;
                continue;
              }
              case 10: {
                if (wireType !== 2)
                  break;
                if (!(message.layers && message.layers.length))
                  message.layers = [];
                message.layers.push($root.privoke.v1.RuntimeLayerExecution.decode(reader, reader.uint32(), $undefined, _depth + 1));
                continue;
              }
              case 11: {
                if (wireType !== 1)
                  break;
                if (!$Object.is(value = reader.double(), 0))
                  message.elapsedMs = value;
                else
                  delete message.elapsedMs;
                continue;
              }
              case 12: {
                if (wireType !== 2)
                  break;
                if ((value = reader.stringVerify()).length)
                  message.error = value;
                else
                  delete message.error;
                continue;
              }
            }
            reader.skipType(wireType, _depth, tag);
            if (!reader.discardUnknown) {
              $util.makeProp(message, "$unknowns", false);
              (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
            }
          }
          if (_end !== $undefined)
            throw $Error("missing end group");
          return message;
        };
        AnalyzePromptResponse.decodeDelimited = function(reader) {
          if (!(reader instanceof $Reader))
            reader = new $Reader(reader);
          return this.decode(reader, reader.uint32());
        };
        AnalyzePromptResponse.verify = function(message, _depth) {
          if (typeof message !== "object" || message === null)
            return "object expected";
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            return "max depth exceeded";
          if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId")) {
            if (!$util.isString(message.requestId))
              return "requestId: string expected";
          }
          if (message.action != null && $Object.hasOwnProperty.call(message, "action")) {
            if (!$util.isString(message.action))
              return "action: string expected";
          }
          if (message.allowed != null && $Object.hasOwnProperty.call(message, "allowed")) {
            if (typeof message.allowed !== "boolean")
              return "allowed: boolean expected";
          }
          if (message.maskedText != null && $Object.hasOwnProperty.call(message, "maskedText")) {
            if (!$util.isString(message.maskedText))
              return "maskedText: string expected";
          }
          if (message.classification != null && $Object.hasOwnProperty.call(message, "classification")) {
            let error = $root.privoke.v1.RuntimeClassification.verify(message.classification, _depth + 1);
            if (error)
              return "classification." + error;
          }
          if (message.reason != null && $Object.hasOwnProperty.call(message, "reason")) {
            if (!$util.isString(message.reason))
              return "reason: string expected";
          }
          if (message.evidence != null && $Object.hasOwnProperty.call(message, "evidence")) {
            let error = $root.privoke.v1.RuntimeDetectionResult.verify(message.evidence, _depth + 1);
            if (error)
              return "evidence." + error;
          }
          if (message.metadata != null && $Object.hasOwnProperty.call(message, "metadata")) {
            if (!$util.isObject(message.metadata))
              return "metadata: object expected";
            let key = $Object.keys(message.metadata);
            for (let i = 0; i < key.length; ++i)
              if (!$util.isString(message.metadata[key[i]]))
                return "metadata: string{k:string} expected";
          }
          if (message.layers != null && $Object.hasOwnProperty.call(message, "layers")) {
            if (!$Array.isArray(message.layers))
              return "layers: array expected";
            for (let i = 0; i < message.layers.length; ++i) {
              let error = $root.privoke.v1.RuntimeLayerExecution.verify(message.layers[i], _depth + 1);
              if (error)
                return "layers." + error;
            }
          }
          if (message.elapsedMs != null && $Object.hasOwnProperty.call(message, "elapsedMs")) {
            if (typeof message.elapsedMs !== "number")
              return "elapsedMs: number expected";
          }
          if (message.error != null && $Object.hasOwnProperty.call(message, "error")) {
            if (!$util.isString(message.error))
              return "error: string expected";
          }
          return null;
        };
        AnalyzePromptResponse.fromObject = function(object, _depth) {
          if (object instanceof $root.privoke.v1.AnalyzePromptResponse)
            return object;
          if (!$util.isObject(object))
            throw $TypeError(".privoke.v1.AnalyzePromptResponse: object expected");
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let message = new $root.privoke.v1.AnalyzePromptResponse();
          if (object.requestId != null) {
            if (typeof object.requestId !== "string" || object.requestId.length)
              message.requestId = $String(object.requestId);
          }
          if (object.action != null) {
            if (typeof object.action !== "string" || object.action.length)
              message.action = $String(object.action);
          }
          if (object.allowed != null) {
            if (object.allowed)
              message.allowed = $Boolean(object.allowed);
          }
          if (object.maskedText != null) {
            if (typeof object.maskedText !== "string" || object.maskedText.length)
              message.maskedText = $String(object.maskedText);
          }
          if (object.classification != null) {
            if (!$util.isObject(object.classification))
              throw $TypeError(".privoke.v1.AnalyzePromptResponse.classification: object expected");
            message.classification = $root.privoke.v1.RuntimeClassification.fromObject(object.classification, _depth + 1);
          }
          if (object.reason != null) {
            if (typeof object.reason !== "string" || object.reason.length)
              message.reason = $String(object.reason);
          }
          if (object.evidence != null) {
            if (!$util.isObject(object.evidence))
              throw $TypeError(".privoke.v1.AnalyzePromptResponse.evidence: object expected");
            message.evidence = $root.privoke.v1.RuntimeDetectionResult.fromObject(object.evidence, _depth + 1);
          }
          if (object.metadata) {
            if (!$util.isObject(object.metadata))
              throw $TypeError(".privoke.v1.AnalyzePromptResponse.metadata: object expected");
            message.metadata = {};
            for (let keys = $Object.keys(object.metadata), i = 0; i < keys.length; ++i) {
              if (keys[i] === "__proto__")
                $util.makeProp(message.metadata, keys[i]);
              message.metadata[keys[i]] = $String(object.metadata[keys[i]]);
            }
          }
          if (object.layers) {
            if (!$Array.isArray(object.layers))
              throw $TypeError(".privoke.v1.AnalyzePromptResponse.layers: array expected");
            message.layers = $Array(object.layers.length);
            for (let i = 0; i < object.layers.length; ++i) {
              if (!$util.isObject(object.layers[i]))
                throw $TypeError(".privoke.v1.AnalyzePromptResponse.layers: object expected");
              message.layers[i] = $root.privoke.v1.RuntimeLayerExecution.fromObject(object.layers[i], _depth + 1);
            }
          }
          if (object.elapsedMs != null) {
            if (!$Object.is($Number(object.elapsedMs), 0))
              message.elapsedMs = $Number(object.elapsedMs);
          }
          if (object.error != null) {
            if (typeof object.error !== "string" || object.error.length)
              message.error = $String(object.error);
          }
          return message;
        };
        AnalyzePromptResponse.toObject = function(message, options, _depth) {
          if (!options)
            options = {};
          if (_depth === $undefined)
            _depth = 0;
          if (_depth > $util.recursionLimit)
            throw $Error("max depth exceeded");
          let object = {};
          if (options.arrays || options.defaults)
            object.layers = [];
          if (options.objects || options.defaults)
            object.metadata = {};
          if (options.defaults) {
            object.requestId = "";
            object.action = "";
            object.allowed = false;
            object.maskedText = "";
            object.classification = null;
            object.reason = "";
            object.evidence = null;
            object.elapsedMs = 0;
            object.error = "";
          }
          if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId"))
            object.requestId = message.requestId;
          if (message.action != null && $Object.hasOwnProperty.call(message, "action"))
            object.action = message.action;
          if (message.allowed != null && $Object.hasOwnProperty.call(message, "allowed"))
            object.allowed = message.allowed;
          if (message.maskedText != null && $Object.hasOwnProperty.call(message, "maskedText"))
            object.maskedText = message.maskedText;
          if (message.classification != null && $Object.hasOwnProperty.call(message, "classification"))
            object.classification = $root.privoke.v1.RuntimeClassification.toObject(message.classification, options, _depth + 1);
          if (message.reason != null && $Object.hasOwnProperty.call(message, "reason"))
            object.reason = message.reason;
          if (message.evidence != null && $Object.hasOwnProperty.call(message, "evidence"))
            object.evidence = $root.privoke.v1.RuntimeDetectionResult.toObject(message.evidence, options, _depth + 1);
          let keys2;
          if (message.metadata && (keys2 = $Object.keys(message.metadata)).length) {
            object.metadata = {};
            for (let j = 0; j < keys2.length; ++j) {
              if (keys2[j] === "__proto__")
                $util.makeProp(object.metadata, keys2[j]);
              object.metadata[keys2[j]] = message.metadata[keys2[j]];
            }
          }
          if (message.layers && message.layers.length) {
            object.layers = $Array(message.layers.length);
            for (let j = 0; j < message.layers.length; ++j)
              object.layers[j] = $root.privoke.v1.RuntimeLayerExecution.toObject(message.layers[j], options, _depth + 1);
          }
          if (message.elapsedMs != null && $Object.hasOwnProperty.call(message, "elapsedMs"))
            object.elapsedMs = options.json && !$isFinite(message.elapsedMs) ? $String(message.elapsedMs) : message.elapsedMs;
          if (message.error != null && $Object.hasOwnProperty.call(message, "error"))
            object.error = message.error;
          return object;
        };
        AnalyzePromptResponse.prototype.toJSON = function() {
          return AnalyzePromptResponse.toObject(this, import_minimal.default.util.toJSONOptions);
        };
        AnalyzePromptResponse.getTypeUrl = function(prefix) {
          if (prefix === $undefined)
            prefix = "type.googleapis.com";
          return prefix + "/privoke.v1.AnalyzePromptResponse";
        };
        return AnalyzePromptResponse;
      })();
      v1.PrivokeRuntimeService = (function() {
        const PrivokeRuntimeService = function(rpcImpl, requestDelimited, responseDelimited) {
          import_minimal.default.rpc.Service.call(this, rpcImpl, requestDelimited, responseDelimited);
        };
        $Object.defineProperty(PrivokeRuntimeService.prototype = $Object.create(import_minimal.default.rpc.Service.prototype), "constructor", { value: PrivokeRuntimeService, writable: true, enumerable: false, configurable: true });
        PrivokeRuntimeService.create = function(rpcImpl, requestDelimited, responseDelimited) {
          return new this(rpcImpl, requestDelimited, responseDelimited);
        };
        $Object.defineProperties(PrivokeRuntimeService.prototype.analyzePrompt = function(request, callback) {
          return import_minimal.default.rpc.Service.prototype.rpcCall.call(this, PrivokeRuntimeService.prototype.analyzePrompt, $root.privoke.v1.AnalyzePromptRequest, $root.privoke.v1.AnalyzePromptResponse, request, callback);
        }, {
          name: { value: "AnalyzePrompt" },
          path: { value: "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt" },
          requestType: { value: "AnalyzePromptRequest" },
          responseType: { value: "AnalyzePromptResponse" },
          requestStream: { value: $undefined },
          responseStream: { value: $undefined }
        });
        $Object.defineProperties(PrivokeRuntimeService.prototype.health = function(request, callback) {
          return import_minimal.default.rpc.Service.prototype.rpcCall.call(this, PrivokeRuntimeService.prototype.health, $root.privoke.v1.RuntimeHealthRequest, $root.privoke.v1.RuntimeHealthResponse, request, callback);
        }, {
          name: { value: "Health" },
          path: { value: "/privoke.v1.PrivokeRuntimeService/Health" },
          requestType: { value: "RuntimeHealthRequest" },
          responseType: { value: "RuntimeHealthResponse" },
          requestStream: { value: $undefined },
          responseStream: { value: $undefined }
        });
        return PrivokeRuntimeService;
      })();
      v1.PrivokeRuntimeControlService = (function() {
        const PrivokeRuntimeControlService = function(rpcImpl, requestDelimited, responseDelimited) {
          import_minimal.default.rpc.Service.call(this, rpcImpl, requestDelimited, responseDelimited);
        };
        $Object.defineProperty(PrivokeRuntimeControlService.prototype = $Object.create(import_minimal.default.rpc.Service.prototype), "constructor", { value: PrivokeRuntimeControlService, writable: true, enumerable: false, configurable: true });
        PrivokeRuntimeControlService.create = function(rpcImpl, requestDelimited, responseDelimited) {
          return new this(rpcImpl, requestDelimited, responseDelimited);
        };
        $Object.defineProperties(PrivokeRuntimeControlService.prototype.setRuntimeEnabled = function(request, callback) {
          return import_minimal.default.rpc.Service.prototype.rpcCall.call(this, PrivokeRuntimeControlService.prototype.setRuntimeEnabled, $root.privoke.v1.SetRuntimeEnabledRequest, $root.privoke.v1.RuntimeControlStatus, request, callback);
        }, {
          name: { value: "SetRuntimeEnabled" },
          path: { value: "/privoke.v1.PrivokeRuntimeControlService/SetRuntimeEnabled" },
          requestType: { value: "SetRuntimeEnabledRequest" },
          responseType: { value: "RuntimeControlStatus" },
          requestStream: { value: $undefined },
          responseStream: { value: $undefined }
        });
        $Object.defineProperties(PrivokeRuntimeControlService.prototype.status = function(request, callback) {
          return import_minimal.default.rpc.Service.prototype.rpcCall.call(this, PrivokeRuntimeControlService.prototype.status, $root.privoke.v1.RuntimeHealthRequest, $root.privoke.v1.RuntimeControlStatus, request, callback);
        }, {
          name: { value: "Status" },
          path: { value: "/privoke.v1.PrivokeRuntimeControlService/Status" },
          requestType: { value: "RuntimeHealthRequest" },
          responseType: { value: "RuntimeControlStatus" },
          requestStream: { value: $undefined },
          responseStream: { value: $undefined }
        });
        $Object.defineProperties(PrivokeRuntimeControlService.prototype.modelStreamingHealth = function(request, callback) {
          return import_minimal.default.rpc.Service.prototype.rpcCall.call(this, PrivokeRuntimeControlService.prototype.modelStreamingHealth, $root.privoke.v1.RuntimeHealthRequest, $root.privoke.v1.RuntimeHealthResponse, request, callback);
        }, {
          name: { value: "ModelStreamingHealth" },
          path: { value: "/privoke.v1.PrivokeRuntimeControlService/ModelStreamingHealth" },
          requestType: { value: "RuntimeHealthRequest" },
          responseType: { value: "RuntimeHealthResponse" },
          requestStream: { value: $undefined },
          responseStream: { value: $undefined }
        });
        return PrivokeRuntimeControlService;
      })();
      return v1;
    })();
    return privoke2;
  })();

  // src/analysis-request.js
  var EXPLICIT_DETECTION_LAYERS = /* @__PURE__ */ new Set([
    "DETECTION_LAYER_REGEX",
    "DETECTION_LAYER_NER",
    "DETECTION_LAYER_SEMANTIC"
  ]);
  function requireExplicitLayers(values) {
    if (!Array.isArray(values?.layers) || values.layers.length === 0) {
      throw new Error("Analysis requests must explicitly specify at least one detection layer.");
    }
    const unsupported = values.layers.find((layer) => !EXPLICIT_DETECTION_LAYERS.has(layer));
    if (unsupported) {
      throw new Error(`Analysis request contains an unsupported detection layer: ${unsupported}.`);
    }
  }

  // src/grpc-web.js
  var DATA_FRAME = 0;
  var TRAILER_FRAME = 128;
  function frameGrpcWebMessage(message) {
    const payload = message instanceof Uint8Array ? message : new Uint8Array(message);
    const framed = new Uint8Array(payload.length + 5);
    const view = new DataView(framed.buffer);
    framed[0] = DATA_FRAME;
    view.setUint32(1, payload.length, false);
    framed.set(payload, 5);
    return framed;
  }
  function parseGrpcWebResponse(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const messages = [];
    let trailers = {};
    let offset = 0;
    while (offset < bytes.length) {
      if (offset + 5 > bytes.length) {
        throw new Error("The gRPC-Web response ended inside a frame header.");
      }
      const flags = bytes[offset];
      const length = new DataView(bytes.buffer, bytes.byteOffset + offset + 1, 4).getUint32(0, false);
      const end = offset + 5 + length;
      if (end > bytes.length) {
        throw new Error("The gRPC-Web response ended inside a frame body.");
      }
      const payload = bytes.subarray(offset + 5, end);
      if ((flags & TRAILER_FRAME) === TRAILER_FRAME) {
        trailers = parseTrailers(new TextDecoder().decode(payload));
      } else if (flags === DATA_FRAME) {
        messages.push(payload);
      } else {
        throw new Error(`Unsupported compressed gRPC-Web frame: ${flags}.`);
      }
      offset = end;
    }
    return { messages, trailers };
  }
  function parseTrailers(value) {
    const trailers = {};
    for (const line of value.split(/\r?\n/)) {
      const separator = line.indexOf(":");
      if (separator > 0) {
        trailers[line.slice(0, separator).trim().toLowerCase()] = line.slice(separator + 1).trim();
      }
    }
    return trailers;
  }

  // src/runtime-client.js
  var RPC_PATH = "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt";
  var STREAMING_HEALTH_PATH = "/privoke.v1.PrivokeRuntimeControlService/ModelStreamingHealth";
  var RUNTIME_CONTROL_PATH = "/privoke.v1.PrivokeRuntimeControlService/SetRuntimeEnabled";
  var RUNTIME_STATUS_PATH = "/privoke.v1.PrivokeRuntimeControlService/Status";
  var {
    AnalyzePromptRequest: Request,
    AnalyzePromptResponse: Response,
    RuntimeHealthRequest,
    RuntimeHealthResponse,
    SetRuntimeEnabledRequest,
    RuntimeControlStatus
  } = privoke.v1;
  var RuntimeClient = class {
    constructor(baseUrl = "http://127.0.0.1:8080") {
      this.baseUrl = baseUrl.replace(/\/$/, "");
    }
    async analyzePrompt(values, { signal } = {}) {
      requireExplicitLayers(values);
      return this.#unary(RPC_PATH, Request, Response, values, { signal });
    }
    async streamingHealth({ signal } = {}) {
      return this.#unary(
        STREAMING_HEALTH_PATH,
        RuntimeHealthRequest,
        RuntimeHealthResponse,
        {},
        { signal }
      );
    }
    async setRuntimeEnabled(enabled, { signal } = {}) {
      return this.#unary(
        RUNTIME_CONTROL_PATH,
        SetRuntimeEnabledRequest,
        RuntimeControlStatus,
        { enabled },
        { signal }
      );
    }
    async runtimeStatus({ signal } = {}) {
      return this.#unary(
        RUNTIME_STATUS_PATH,
        RuntimeHealthRequest,
        RuntimeControlStatus,
        {},
        { signal }
      );
    }
    async #unary(path, requestType, responseType, values, { signal } = {}) {
      const request = requestType.fromObject(values);
      const body = frameGrpcWebMessage(requestType.encode(request).finish());
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/grpc-web+proto",
          "X-Grpc-Web": "1",
          "X-User-Agent": "privoke-extension/0.1"
        },
        body,
        signal
      });
      if (!response.ok) {
        throw new Error(`Runtime bridge returned HTTP ${response.status}.`);
      }
      const { messages, trailers } = parseGrpcWebResponse(await response.arrayBuffer());
      const grpcStatus = trailers["grpc-status"] ?? response.headers.get("grpc-status") ?? "0";
      if (grpcStatus !== "0") {
        const grpcMessage = trailers["grpc-message"] ?? response.headers.get("grpc-message");
        throw new Error(grpcMessage ? decodeURIComponent(grpcMessage) : `gRPC status ${grpcStatus}.`);
      }
      if (messages.length !== 1) {
        throw new Error(`Expected one runtime response, received ${messages.length}.`);
      }
      return responseType.toObject(responseType.decode(messages[0]), {
        defaults: true,
        enums: String,
        arrays: true,
        objects: true
      });
    }
  };

  // src/webextension-api.js
  function webExtensionApi(root = globalThis) {
    const api = root.browser ?? root.chrome;
    if (!api?.runtime) {
      throw new Error("WebExtensions runtime API is unavailable.");
    }
    return api;
  }
  function addRuntimeMessageListener(handler, root = globalThis) {
    const api = webExtensionApi(root);
    if (root.browser) {
      api.runtime.onMessage.addListener((message, sender) => handler(message, sender));
      return;
    }
    api.runtime.onMessage.addListener((message, sender, sendResponse) => {
      Promise.resolve(handler(message, sender)).then(
        sendResponse,
        (error) => sendResponse({ ok: false, error: errorMessage(error) })
      );
      return true;
    });
  }
  function addRuntimeLifecycleListeners(handler, root = globalThis) {
    const runtime = webExtensionApi(root).runtime;
    runtime.onStartup?.addListener(handler);
    runtime.onInstalled?.addListener(handler);
  }
  function sendNativeMessage(hostName, message, root = globalThis) {
    const api = webExtensionApi(root);
    if (root.browser) return api.runtime.sendNativeMessage(hostName, message);
    return callbackResult(
      api.runtime,
      (callback) => api.runtime.sendNativeMessage(hostName, message, callback)
    );
  }
  function localStorageArea(root = globalThis) {
    const storage = webExtensionApi(root).storage?.local;
    if (!storage) throw new Error("WebExtensions local storage API is unavailable.");
    return storage;
  }
  function storageGet(storage, key, root = globalThis) {
    if (root.browser || storage !== root.chrome?.storage?.local) return storage.get(key);
    return callbackResult(root.chrome.runtime, (callback) => storage.get(key, callback));
  }
  function storageSet(storage, values, root = globalThis) {
    if (root.browser || storage !== root.chrome?.storage?.local) return storage.set(values);
    return callbackResult(root.chrome.runtime, (callback) => storage.set(values, callback));
  }
  function callbackResult(runtime, invoke) {
    return new Promise((resolve, reject) => {
      invoke((result) => {
        const runtimeError = runtime.lastError;
        if (runtimeError) {
          reject(new Error(runtimeError.message));
          return;
        }
        resolve(result);
      });
    });
  }
  function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
  }

  // src/supervisor-launcher.js
  var NATIVE_LAUNCHER_HOST = "org.privoke.runtime_launcher";
  var DEFAULT_ATTEMPTS = 24;
  var DEFAULT_RETRY_DELAY_MS = 250;
  async function ensureSupervisorRunning(runtimeClient, {
    launch = launchSupervisorNativeHost,
    attempts = DEFAULT_ATTEMPTS,
    retryDelayMs = DEFAULT_RETRY_DELAY_MS
  } = {}) {
    try {
      return await runtimeClient.runtimeStatus({
        signal: AbortSignal.timeout(1500)
      });
    } catch (initialError) {
      let launchResult;
      try {
        launchResult = await launch();
      } catch (launchError) {
        throw new Error(
          `The PriVoke supervisor is not running and its native launcher could not be reached: ${errorMessage2(launchError)}. Install the PriVoke native messaging host for this extension.`
        );
      }
      if (!launchResult?.ok) {
        throw new Error(
          launchResult?.message || `The PriVoke supervisor could not be launched: ${errorMessage2(initialError)}`
        );
      }
    }
    let lastError;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        return await runtimeClient.runtimeStatus({
          signal: AbortSignal.timeout(1500)
        });
      } catch (error) {
        lastError = error;
        if (attempt + 1 < attempts) await delay(retryDelayMs);
      }
    }
    throw new Error(
      `The PriVoke supervisor was launched but its bridge did not become ready: ${errorMessage2(lastError)}`
    );
  }
  function launchSupervisorNativeHost() {
    return sendNativeMessage(NATIVE_LAUNCHER_HOST, { action: "ensure_supervisor" });
  }
  function delay(milliseconds) {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
  }
  function errorMessage2(error) {
    return error instanceof Error ? error.message : String(error);
  }

  // src/runtime-lifecycle.js
  async function restoreConfiguredRuntime(runtimeClient, settings, { ensureSupervisor = ensureSupervisorRunning } = {}) {
    if (!settings.enabled) return null;
    await ensureSupervisor(runtimeClient);
    const runtime = await runtimeClient.setRuntimeEnabled(true, {
      signal: AbortSignal.timeout(36e3)
    });
    if (!runtime.enabled) {
      throw new Error(runtime.message || "The client runtime failed to start.");
    }
    return runtime;
  }

  // src/settings.js
  var DEFAULT_SETTINGS = Object.freeze({
    enabled: true,
    layers: Object.freeze({ regex: true, ner: true, llm: false }),
    waitForRegex: true,
    modelId: "privoke-baseline"
  });
  var STORAGE_KEY = "privokeSettings";
  var MAX_MODEL_ID_LENGTH = 128;
  function normaliseSettings(value = {}) {
    const layers = value.layers ?? {};
    const modelId = typeof value.modelId === "string" ? value.modelId.trim().slice(0, MAX_MODEL_ID_LENGTH) : "";
    return {
      enabled: booleanOrDefault(value.enabled, DEFAULT_SETTINGS.enabled),
      layers: {
        regex: booleanOrDefault(layers.regex, DEFAULT_SETTINGS.layers.regex),
        ner: booleanOrDefault(layers.ner, DEFAULT_SETTINGS.layers.ner),
        llm: booleanOrDefault(layers.llm, DEFAULT_SETTINGS.layers.llm)
      },
      waitForRegex: booleanOrDefault(
        value.waitForRegex,
        DEFAULT_SETTINGS.waitForRegex
      ),
      modelId: modelId || DEFAULT_SETTINGS.modelId
    };
  }
  function mergeSettings(current, patch) {
    return normaliseSettings({
      ...current,
      ...patch,
      layers: { ...current?.layers, ...patch?.layers }
    });
  }
  function detectionLayers(settings) {
    const layers = [];
    if (settings.layers.regex) layers.push("DETECTION_LAYER_REGEX");
    if (settings.layers.ner) layers.push("DETECTION_LAYER_NER");
    if (settings.layers.llm) layers.push("DETECTION_LAYER_SEMANTIC");
    return layers;
  }
  async function loadSettings(storage = localStorageArea()) {
    const stored = await storageGet(storage, STORAGE_KEY);
    return normaliseSettings(stored[STORAGE_KEY]);
  }
  async function updateSettings(patch, storage = localStorageArea()) {
    const current = await loadSettings(storage);
    const settings = mergeSettings(current, patch);
    await storageSet(storage, { [STORAGE_KEY]: settings });
    return settings;
  }
  function booleanOrDefault(value, fallback) {
    return typeof value === "boolean" ? value : fallback;
  }

  // src/background.js
  var client = new RuntimeClient();
  var runtimeControlTail = Promise.resolve();
  addRuntimeMessageListener(handleMessage);
  addRuntimeLifecycleListeners(() => {
    void restoreEnabledRuntime().catch(reportStartupFailure);
  });
  void restoreEnabledRuntime().catch(reportStartupFailure);
  async function handleMessage(message, sender) {
    switch (message?.type) {
      case "GET_SETTINGS":
        return { ok: true, settings: await loadSettings() };
      case "UPDATE_SETTINGS":
        return { ok: true, settings: await updateSettings(message.patch ?? {}) };
      case "SET_MASTER_ENABLED":
        return enqueueRuntimeControl(() => setMasterEnabled(Boolean(message.enabled)));
      case "GET_RUNTIME_STATUS":
        return getRuntimeStatus();
      case "CHECK_STREAMING_HEALTH":
        return checkStreamingHealth();
      case "ANALYZE_PROMPT":
        return analyzePrompt(message, sender);
      default:
        return { ok: false, error: "Unsupported extension message." };
    }
  }
  async function checkStreamingHealth() {
    try {
      const response = await client.streamingHealth({
        signal: AbortSignal.timeout(3500)
      });
      const serving = response.status?.toUpperCase() === "SERVING";
      return {
        ok: serving,
        health: response,
        error: serving ? void 0 : "PriVoke servers are offline."
      };
    } catch (error) {
      return {
        ok: false,
        error: "PriVoke servers are offline.",
        detail: errorMessage3(error)
      };
    }
  }
  async function setMasterEnabled(enabled) {
    if (!enabled) {
      const settings = await updateSettings({ enabled: false });
      try {
        const runtime = await client.setRuntimeEnabled(false, {
          signal: AbortSignal.timeout(15e3)
        });
        return { ok: true, settings, runtime };
      } catch (error) {
        return {
          ok: true,
          settings,
          warning: "The extension is off, but the client runtime could not be stopped.",
          detail: errorMessage3(error)
        };
      }
    }
    try {
      const runtime = await restoreConfiguredRuntime(client, { enabled: true });
      const settings = await updateSettings({ enabled: true });
      return { ok: true, settings, runtime };
    } catch (error) {
      const settings = await updateSettings({ enabled: false });
      const detail = errorMessage3(error);
      return {
        ok: false,
        settings,
        error: `The client runtime could not be started: ${detail}`,
        detail
      };
    }
  }
  async function getRuntimeStatus() {
    const settings = await loadSettings();
    if (settings.enabled) {
      try {
        const runtime = await restoreEnabledRuntime();
        return { ok: true, runtime };
      } catch (error) {
        return { ok: false, error: errorMessage3(error) };
      }
    }
    try {
      const runtime = await client.runtimeStatus({
        signal: AbortSignal.timeout(3500)
      });
      return { ok: true, runtime };
    } catch (error) {
      return { ok: false, error: errorMessage3(error) };
    }
  }
  function restoreEnabledRuntime() {
    return enqueueRuntimeControl(async () => {
      const settings = await loadSettings();
      return restoreConfiguredRuntime(client, settings);
    });
  }
  function enqueueRuntimeControl(operation) {
    const result = runtimeControlTail.then(operation, operation);
    runtimeControlTail = result.catch(() => {
    });
    return result;
  }
  function reportStartupFailure(error) {
    console.warn(`PriVoke could not restore the enabled runtime: ${errorMessage3(error)}`);
  }
  async function analyzePrompt(message, sender) {
    const text = typeof message.text === "string" ? message.text.trim() : "";
    if (!text) return { ok: false, error: "Prompt text is required." };
    const settings = await loadSettings();
    if (!settings.enabled) {
      void client.setRuntimeEnabled(false, {
        signal: AbortSignal.timeout(15e3)
      }).catch(() => {
      });
      return { ok: true, response: disabledExtensionResponse() };
    }
    const layers = detectionLayers(settings);
    if (layers.length === 0) {
      return { ok: true, response: disabledLayersResponse() };
    }
    const targetApp = cleanText(message.targetApp, 80) || appFromUrl(sender?.url) || "unknown_web_app";
    const response = await client.analyzePrompt({
      text,
      source: message.source === "manual" ? "extension_popup" : "browser_interceptor",
      targetApp,
      requestId: crypto.randomUUID(),
      layers,
      regexExecutionOrder: settings.waitForRegex ? "REGEX_EXECUTION_ORDER_FIRST" : "REGEX_EXECUTION_ORDER_PARALLEL",
      semanticModelId: settings.modelId,
      metadata: {
        client: "privoke-local-extension",
        client_version: "0.1.0",
        intercepted: message.source === "manual" ? "false" : "true"
      }
    }, { signal: AbortSignal.timeout(3e4) });
    return { ok: true, response };
  }
  function disabledExtensionResponse() {
    return {
      disabled: true,
      masterDisabled: true,
      action: "ALLOW",
      allowed: true,
      reason: "PriVoke is turned off.",
      elapsedMs: 0
    };
  }
  function disabledLayersResponse() {
    return {
      disabled: true,
      action: "ALLOW",
      allowed: true,
      reason: "No protection layers are enabled.",
      elapsedMs: 0,
      classification: {
        sensitivity: "S0",
        visibility: "PU",
        categories: []
      },
      layers: []
    };
  }
  function appFromUrl(rawUrl) {
    try {
      const host = new URL(rawUrl).hostname;
      if (host === "chatgpt.com" || host === "chat.openai.com") return "chatgpt";
      if (host === "claude.ai") return "claude";
      if (host === "gemini.google.com") return "gemini";
      if (host === "copilot.microsoft.com") return "copilot";
      if (host === "api.openai.com") return "openai_api";
    } catch {
      return "";
    }
    return "";
  }
  function cleanText(value, maxLength) {
    return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
  }
  function errorMessage3(error) {
    return error instanceof Error ? error.message : String(error);
  }
})();
/*! Bundled license information:

long/umd/index.js:
  (**
   * @license
   * Copyright 2009 The Closure Library Authors
   * Copyright 2020 Daniel Wirtz / The long.js Authors.
   *
   * Licensed under the Apache License, Version 2.0 (the "License");
   * you may not use this file except in compliance with the License.
   * You may obtain a copy of the License at
   *
   *     http://www.apache.org/licenses/LICENSE-2.0
   *
   * Unless required by applicable law or agreed to in writing, software
   * distributed under the License is distributed on an "AS IS" BASIS,
   * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   * See the License for the specific language governing permissions and
   * limitations under the License.
   *
   * SPDX-License-Identifier: Apache-2.0
   *)
*/
//# sourceMappingURL=background.js.map
