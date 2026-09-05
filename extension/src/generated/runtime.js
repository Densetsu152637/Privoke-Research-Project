/*eslint-disable block-scoped-var, id-length, no-control-regex, no-magic-numbers, no-mixed-operators, no-prototype-builtins, no-redeclare, no-shadow, no-var, sort-vars, default-case, jsdoc/require-param*/
import $protobuf from "protobufjs/minimal.js";

// Common aliases
const $Reader = $protobuf.Reader, $Writer = $protobuf.Writer, $util = $protobuf.util;
const $Object = $util.global.Object, $undefined = $util.global.undefined, $Error = $util.global.Error, $TypeError = $util.global.TypeError, $String = $util.global.String, $Boolean = $util.global.Boolean, $Number = $util.global.Number, $Array = $util.global.Array, $isFinite = $util.global.isFinite;

// Exported root namespace
const $root = $protobuf.roots["default"] || ($protobuf.roots["default"] = {});

export const privoke = $root.privoke = (() => {

    /**
     * Namespace privoke.
     * @exports privoke
     * @namespace
     */
    const privoke = {};

    privoke.v1 = (function() {

        /**
         * Namespace v1.
         * @memberof privoke
         * @namespace
         */
        const v1 = {};

        v1.RuntimeHealthRequest = (function() {

            /**
             * Properties of a RuntimeHealthRequest.
             * @typedef {Object} privoke.v1.RuntimeHealthRequest.$Properties
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a RuntimeHealthRequest.
             * @memberof privoke.v1
             * @interface IRuntimeHealthRequest
             * @augments privoke.v1.RuntimeHealthRequest.$Properties
             * @deprecated Use privoke.v1.RuntimeHealthRequest.$Properties instead.
             */

            /**
             * Shape of a RuntimeHealthRequest.
             * @typedef {privoke.v1.RuntimeHealthRequest.$Properties} privoke.v1.RuntimeHealthRequest.$Shape
             */

            /**
             * Constructs a new RuntimeHealthRequest.
             * @memberof privoke.v1
             * @classdesc Represents a RuntimeHealthRequest.
             * @constructor
             * @param {privoke.v1.RuntimeHealthRequest.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const RuntimeHealthRequest = function (properties) {
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * Creates a new RuntimeHealthRequest instance using the specified properties.
             * @function create
             * @memberof privoke.v1.RuntimeHealthRequest
             * @static
             * @param {privoke.v1.RuntimeHealthRequest.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.RuntimeHealthRequest} RuntimeHealthRequest instance
             * @type {{
             *   (properties: privoke.v1.RuntimeHealthRequest.$Shape): privoke.v1.RuntimeHealthRequest & privoke.v1.RuntimeHealthRequest.$Shape;
             *   (properties?: privoke.v1.RuntimeHealthRequest.$Properties): privoke.v1.RuntimeHealthRequest;
             * }}
             */
            RuntimeHealthRequest.create = function(properties) {
                return new RuntimeHealthRequest(properties);
            };

            /**
             * Encodes the specified RuntimeHealthRequest message. Does not implicitly {@link privoke.v1.RuntimeHealthRequest.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.RuntimeHealthRequest
             * @static
             * @param {privoke.v1.RuntimeHealthRequest.$Properties} message RuntimeHealthRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeHealthRequest.encode = function (message, writer, _depth) {
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

            /**
             * Encodes the specified RuntimeHealthRequest message, length delimited. Does not implicitly {@link privoke.v1.RuntimeHealthRequest.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.RuntimeHealthRequest
             * @static
             * @param {privoke.v1.RuntimeHealthRequest.$Properties} message RuntimeHealthRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeHealthRequest.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a RuntimeHealthRequest message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.RuntimeHealthRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.RuntimeHealthRequest & privoke.v1.RuntimeHealthRequest.$Shape} RuntimeHealthRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeHealthRequest.decode = function (reader, length, _end, _depth, _target) {
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

            /**
             * Decodes a RuntimeHealthRequest message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.RuntimeHealthRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.RuntimeHealthRequest & privoke.v1.RuntimeHealthRequest.$Shape} RuntimeHealthRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeHealthRequest.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a RuntimeHealthRequest message.
             * @function verify
             * @memberof privoke.v1.RuntimeHealthRequest
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            RuntimeHealthRequest.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                return null;
            };

            /**
             * Creates a RuntimeHealthRequest message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.RuntimeHealthRequest
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.RuntimeHealthRequest} RuntimeHealthRequest
             */
            RuntimeHealthRequest.fromObject = function (object, _depth) {
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

            /**
             * Creates a plain object from a RuntimeHealthRequest message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.RuntimeHealthRequest
             * @static
             * @param {privoke.v1.RuntimeHealthRequest} message RuntimeHealthRequest
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            RuntimeHealthRequest.toObject = function () {
                return {};
            };

            /**
             * Converts this RuntimeHealthRequest to JSON.
             * @function toJSON
             * @memberof privoke.v1.RuntimeHealthRequest
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            RuntimeHealthRequest.prototype.toJSON = function() {
                return RuntimeHealthRequest.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for RuntimeHealthRequest
             * @function getTypeUrl
             * @memberof privoke.v1.RuntimeHealthRequest
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            RuntimeHealthRequest.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.RuntimeHealthRequest";
            };

            return RuntimeHealthRequest;
        })();

        v1.RuntimeHealthResponse = (function() {

            /**
             * Properties of a RuntimeHealthResponse.
             * @typedef {Object} privoke.v1.RuntimeHealthResponse.$Properties
             * @property {string|null} [service] RuntimeHealthResponse service
             * @property {string|null} [status] RuntimeHealthResponse status
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a RuntimeHealthResponse.
             * @memberof privoke.v1
             * @interface IRuntimeHealthResponse
             * @augments privoke.v1.RuntimeHealthResponse.$Properties
             * @deprecated Use privoke.v1.RuntimeHealthResponse.$Properties instead.
             */

            /**
             * Shape of a RuntimeHealthResponse.
             * @typedef {privoke.v1.RuntimeHealthResponse.$Properties} privoke.v1.RuntimeHealthResponse.$Shape
             */

            /**
             * Constructs a new RuntimeHealthResponse.
             * @memberof privoke.v1
             * @classdesc Represents a RuntimeHealthResponse.
             * @constructor
             * @param {privoke.v1.RuntimeHealthResponse.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const RuntimeHealthResponse = function (properties) {
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * RuntimeHealthResponse service.
             * @member {string} service
             * @memberof privoke.v1.RuntimeHealthResponse
             * @instance
             */
            RuntimeHealthResponse.prototype.service = "";

            /**
             * RuntimeHealthResponse status.
             * @member {string} status
             * @memberof privoke.v1.RuntimeHealthResponse
             * @instance
             */
            RuntimeHealthResponse.prototype.status = "";

            /**
             * Creates a new RuntimeHealthResponse instance using the specified properties.
             * @function create
             * @memberof privoke.v1.RuntimeHealthResponse
             * @static
             * @param {privoke.v1.RuntimeHealthResponse.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.RuntimeHealthResponse} RuntimeHealthResponse instance
             * @type {{
             *   (properties: privoke.v1.RuntimeHealthResponse.$Shape): privoke.v1.RuntimeHealthResponse & privoke.v1.RuntimeHealthResponse.$Shape;
             *   (properties?: privoke.v1.RuntimeHealthResponse.$Properties): privoke.v1.RuntimeHealthResponse;
             * }}
             */
            RuntimeHealthResponse.create = function(properties) {
                return new RuntimeHealthResponse(properties);
            };

            /**
             * Encodes the specified RuntimeHealthResponse message. Does not implicitly {@link privoke.v1.RuntimeHealthResponse.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.RuntimeHealthResponse
             * @static
             * @param {privoke.v1.RuntimeHealthResponse.$Properties} message RuntimeHealthResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeHealthResponse.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.service != null && $Object.hasOwnProperty.call(message, "service") && message.service !== "")
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.service);
                if (message.status != null && $Object.hasOwnProperty.call(message, "status") && message.status !== "")
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.status);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified RuntimeHealthResponse message, length delimited. Does not implicitly {@link privoke.v1.RuntimeHealthResponse.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.RuntimeHealthResponse
             * @static
             * @param {privoke.v1.RuntimeHealthResponse.$Properties} message RuntimeHealthResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeHealthResponse.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a RuntimeHealthResponse message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.RuntimeHealthResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.RuntimeHealthResponse & privoke.v1.RuntimeHealthResponse.$Shape} RuntimeHealthResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeHealthResponse.decode = function (reader, length, _end, _depth, _target) {
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

            /**
             * Decodes a RuntimeHealthResponse message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.RuntimeHealthResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.RuntimeHealthResponse & privoke.v1.RuntimeHealthResponse.$Shape} RuntimeHealthResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeHealthResponse.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a RuntimeHealthResponse message.
             * @function verify
             * @memberof privoke.v1.RuntimeHealthResponse
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            RuntimeHealthResponse.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                if (message.service != null && $Object.hasOwnProperty.call(message, "service"))
                    if (!$util.isString(message.service))
                        return "service: string expected";
                if (message.status != null && $Object.hasOwnProperty.call(message, "status"))
                    if (!$util.isString(message.status))
                        return "status: string expected";
                return null;
            };

            /**
             * Creates a RuntimeHealthResponse message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.RuntimeHealthResponse
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.RuntimeHealthResponse} RuntimeHealthResponse
             */
            RuntimeHealthResponse.fromObject = function (object, _depth) {
                if (object instanceof $root.privoke.v1.RuntimeHealthResponse)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".privoke.v1.RuntimeHealthResponse: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.privoke.v1.RuntimeHealthResponse();
                if (object.service != null)
                    if (typeof object.service !== "string" || object.service.length)
                        message.service = $String(object.service);
                if (object.status != null)
                    if (typeof object.status !== "string" || object.status.length)
                        message.status = $String(object.status);
                return message;
            };

            /**
             * Creates a plain object from a RuntimeHealthResponse message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.RuntimeHealthResponse
             * @static
             * @param {privoke.v1.RuntimeHealthResponse} message RuntimeHealthResponse
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            RuntimeHealthResponse.toObject = function (message, options, _depth) {
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

            /**
             * Converts this RuntimeHealthResponse to JSON.
             * @function toJSON
             * @memberof privoke.v1.RuntimeHealthResponse
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            RuntimeHealthResponse.prototype.toJSON = function() {
                return RuntimeHealthResponse.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for RuntimeHealthResponse
             * @function getTypeUrl
             * @memberof privoke.v1.RuntimeHealthResponse
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            RuntimeHealthResponse.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.RuntimeHealthResponse";
            };

            return RuntimeHealthResponse;
        })();

        v1.SetRuntimeEnabledRequest = (function() {

            /**
             * Properties of a SetRuntimeEnabledRequest.
             * @typedef {Object} privoke.v1.SetRuntimeEnabledRequest.$Properties
             * @property {boolean|null} [enabled] SetRuntimeEnabledRequest enabled
             * @property {boolean|null} [useLocalStack] SetRuntimeEnabledRequest useLocalStack
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a SetRuntimeEnabledRequest.
             * @memberof privoke.v1
             * @interface ISetRuntimeEnabledRequest
             * @augments privoke.v1.SetRuntimeEnabledRequest.$Properties
             * @deprecated Use privoke.v1.SetRuntimeEnabledRequest.$Properties instead.
             */

            /**
             * Shape of a SetRuntimeEnabledRequest.
             * @typedef {privoke.v1.SetRuntimeEnabledRequest.$Properties} privoke.v1.SetRuntimeEnabledRequest.$Shape
             */

            /**
             * Constructs a new SetRuntimeEnabledRequest.
             * @memberof privoke.v1
             * @classdesc Represents a SetRuntimeEnabledRequest.
             * @constructor
             * @param {privoke.v1.SetRuntimeEnabledRequest.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const SetRuntimeEnabledRequest = function (properties) {
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * SetRuntimeEnabledRequest enabled.
             * @member {boolean} enabled
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @instance
             */
            SetRuntimeEnabledRequest.prototype.enabled = false;

            /**
             * SetRuntimeEnabledRequest useLocalStack.
             * @member {boolean|null|undefined} useLocalStack
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @instance
             */
            SetRuntimeEnabledRequest.prototype.useLocalStack = null;

            // OneOf field names bound to virtual getters and setters
            let $oneOfFields;

            // Virtual OneOf for proto3 optional field
            $Object.defineProperty(SetRuntimeEnabledRequest.prototype, "_useLocalStack", {
                get: $util.oneOfGetter($oneOfFields = ["useLocalStack"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            /**
             * Creates a new SetRuntimeEnabledRequest instance using the specified properties.
             * @function create
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @static
             * @param {privoke.v1.SetRuntimeEnabledRequest.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.SetRuntimeEnabledRequest} SetRuntimeEnabledRequest instance
             * @type {{
             *   (properties: privoke.v1.SetRuntimeEnabledRequest.$Shape): privoke.v1.SetRuntimeEnabledRequest & privoke.v1.SetRuntimeEnabledRequest.$Shape;
             *   (properties?: privoke.v1.SetRuntimeEnabledRequest.$Properties): privoke.v1.SetRuntimeEnabledRequest;
             * }}
             */
            SetRuntimeEnabledRequest.create = function(properties) {
                return new SetRuntimeEnabledRequest(properties);
            };

            /**
             * Encodes the specified SetRuntimeEnabledRequest message. Does not implicitly {@link privoke.v1.SetRuntimeEnabledRequest.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @static
             * @param {privoke.v1.SetRuntimeEnabledRequest.$Properties} message SetRuntimeEnabledRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            SetRuntimeEnabledRequest.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.enabled != null && $Object.hasOwnProperty.call(message, "enabled") && message.enabled !== false)
                    writer.uint32(/* id 1, wireType 0 =*/8).bool(message.enabled);
                if (message.useLocalStack != null && $Object.hasOwnProperty.call(message, "useLocalStack"))
                    writer.uint32(/* id 2, wireType 0 =*/16).bool(message.useLocalStack);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified SetRuntimeEnabledRequest message, length delimited. Does not implicitly {@link privoke.v1.SetRuntimeEnabledRequest.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @static
             * @param {privoke.v1.SetRuntimeEnabledRequest.$Properties} message SetRuntimeEnabledRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            SetRuntimeEnabledRequest.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a SetRuntimeEnabledRequest message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.SetRuntimeEnabledRequest & privoke.v1.SetRuntimeEnabledRequest.$Shape} SetRuntimeEnabledRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            SetRuntimeEnabledRequest.decode = function (reader, length, _end, _depth, _target) {
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
                    case 2: {
                            if (wireType !== 0)
                                break;
                            message.useLocalStack = reader.bool();
                            message._useLocalStack = "useLocalStack";
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

            /**
             * Decodes a SetRuntimeEnabledRequest message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.SetRuntimeEnabledRequest & privoke.v1.SetRuntimeEnabledRequest.$Shape} SetRuntimeEnabledRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            SetRuntimeEnabledRequest.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a SetRuntimeEnabledRequest message.
             * @function verify
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            SetRuntimeEnabledRequest.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                let properties = {};
                if (message.enabled != null && $Object.hasOwnProperty.call(message, "enabled"))
                    if (typeof message.enabled !== "boolean")
                        return "enabled: boolean expected";
                if (message.useLocalStack != null && $Object.hasOwnProperty.call(message, "useLocalStack")) {
                    properties._useLocalStack = 1;
                    if (typeof message.useLocalStack !== "boolean")
                        return "useLocalStack: boolean expected";
                }
                return null;
            };

            /**
             * Creates a SetRuntimeEnabledRequest message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.SetRuntimeEnabledRequest} SetRuntimeEnabledRequest
             */
            SetRuntimeEnabledRequest.fromObject = function (object, _depth) {
                if (object instanceof $root.privoke.v1.SetRuntimeEnabledRequest)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".privoke.v1.SetRuntimeEnabledRequest: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.privoke.v1.SetRuntimeEnabledRequest();
                if (object.enabled != null)
                    if (object.enabled)
                        message.enabled = $Boolean(object.enabled);
                if (object.useLocalStack != null)
                    message.useLocalStack = $Boolean(object.useLocalStack);
                return message;
            };

            /**
             * Creates a plain object from a SetRuntimeEnabledRequest message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @static
             * @param {privoke.v1.SetRuntimeEnabledRequest} message SetRuntimeEnabledRequest
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            SetRuntimeEnabledRequest.toObject = function (message, options, _depth) {
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
                if (message.useLocalStack != null && $Object.hasOwnProperty.call(message, "useLocalStack"))
                    object.useLocalStack = message.useLocalStack;
                return object;
            };

            /**
             * Converts this SetRuntimeEnabledRequest to JSON.
             * @function toJSON
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            SetRuntimeEnabledRequest.prototype.toJSON = function() {
                return SetRuntimeEnabledRequest.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for SetRuntimeEnabledRequest
             * @function getTypeUrl
             * @memberof privoke.v1.SetRuntimeEnabledRequest
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            SetRuntimeEnabledRequest.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.SetRuntimeEnabledRequest";
            };

            return SetRuntimeEnabledRequest;
        })();

        v1.RuntimeControlStatus = (function() {

            /**
             * Properties of a RuntimeControlStatus.
             * @typedef {Object} privoke.v1.RuntimeControlStatus.$Properties
             * @property {boolean|null} [enabled] RuntimeControlStatus enabled
             * @property {string|null} [status] RuntimeControlStatus status
             * @property {string|null} [message] RuntimeControlStatus message
             * @property {number|null} [processId] RuntimeControlStatus processId
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a RuntimeControlStatus.
             * @memberof privoke.v1
             * @interface IRuntimeControlStatus
             * @augments privoke.v1.RuntimeControlStatus.$Properties
             * @deprecated Use privoke.v1.RuntimeControlStatus.$Properties instead.
             */

            /**
             * Shape of a RuntimeControlStatus.
             * @typedef {privoke.v1.RuntimeControlStatus.$Properties} privoke.v1.RuntimeControlStatus.$Shape
             */

            /**
             * Constructs a new RuntimeControlStatus.
             * @memberof privoke.v1
             * @classdesc Represents a RuntimeControlStatus.
             * @constructor
             * @param {privoke.v1.RuntimeControlStatus.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const RuntimeControlStatus = function (properties) {
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * RuntimeControlStatus enabled.
             * @member {boolean} enabled
             * @memberof privoke.v1.RuntimeControlStatus
             * @instance
             */
            RuntimeControlStatus.prototype.enabled = false;

            /**
             * RuntimeControlStatus status.
             * @member {string} status
             * @memberof privoke.v1.RuntimeControlStatus
             * @instance
             */
            RuntimeControlStatus.prototype.status = "";

            /**
             * RuntimeControlStatus message.
             * @member {string} message
             * @memberof privoke.v1.RuntimeControlStatus
             * @instance
             */
            RuntimeControlStatus.prototype.message = "";

            /**
             * RuntimeControlStatus processId.
             * @member {number} processId
             * @memberof privoke.v1.RuntimeControlStatus
             * @instance
             */
            RuntimeControlStatus.prototype.processId = 0;

            /**
             * Creates a new RuntimeControlStatus instance using the specified properties.
             * @function create
             * @memberof privoke.v1.RuntimeControlStatus
             * @static
             * @param {privoke.v1.RuntimeControlStatus.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.RuntimeControlStatus} RuntimeControlStatus instance
             * @type {{
             *   (properties: privoke.v1.RuntimeControlStatus.$Shape): privoke.v1.RuntimeControlStatus & privoke.v1.RuntimeControlStatus.$Shape;
             *   (properties?: privoke.v1.RuntimeControlStatus.$Properties): privoke.v1.RuntimeControlStatus;
             * }}
             */
            RuntimeControlStatus.create = function(properties) {
                return new RuntimeControlStatus(properties);
            };

            /**
             * Encodes the specified RuntimeControlStatus message. Does not implicitly {@link privoke.v1.RuntimeControlStatus.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.RuntimeControlStatus
             * @static
             * @param {privoke.v1.RuntimeControlStatus.$Properties} message RuntimeControlStatus message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeControlStatus.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.enabled != null && $Object.hasOwnProperty.call(message, "enabled") && message.enabled !== false)
                    writer.uint32(/* id 1, wireType 0 =*/8).bool(message.enabled);
                if (message.status != null && $Object.hasOwnProperty.call(message, "status") && message.status !== "")
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.status);
                if (message.message != null && $Object.hasOwnProperty.call(message, "message") && message.message !== "")
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.message);
                if (message.processId != null && $Object.hasOwnProperty.call(message, "processId") && message.processId !== 0)
                    writer.uint32(/* id 4, wireType 0 =*/32).uint32(message.processId);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified RuntimeControlStatus message, length delimited. Does not implicitly {@link privoke.v1.RuntimeControlStatus.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.RuntimeControlStatus
             * @static
             * @param {privoke.v1.RuntimeControlStatus.$Properties} message RuntimeControlStatus message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeControlStatus.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a RuntimeControlStatus message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.RuntimeControlStatus
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.RuntimeControlStatus & privoke.v1.RuntimeControlStatus.$Shape} RuntimeControlStatus
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeControlStatus.decode = function (reader, length, _end, _depth, _target) {
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

            /**
             * Decodes a RuntimeControlStatus message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.RuntimeControlStatus
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.RuntimeControlStatus & privoke.v1.RuntimeControlStatus.$Shape} RuntimeControlStatus
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeControlStatus.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a RuntimeControlStatus message.
             * @function verify
             * @memberof privoke.v1.RuntimeControlStatus
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            RuntimeControlStatus.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                if (message.enabled != null && $Object.hasOwnProperty.call(message, "enabled"))
                    if (typeof message.enabled !== "boolean")
                        return "enabled: boolean expected";
                if (message.status != null && $Object.hasOwnProperty.call(message, "status"))
                    if (!$util.isString(message.status))
                        return "status: string expected";
                if (message.message != null && $Object.hasOwnProperty.call(message, "message"))
                    if (!$util.isString(message.message))
                        return "message: string expected";
                if (message.processId != null && $Object.hasOwnProperty.call(message, "processId"))
                    if (!$util.isInteger(message.processId))
                        return "processId: integer expected";
                return null;
            };

            /**
             * Creates a RuntimeControlStatus message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.RuntimeControlStatus
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.RuntimeControlStatus} RuntimeControlStatus
             */
            RuntimeControlStatus.fromObject = function (object, _depth) {
                if (object instanceof $root.privoke.v1.RuntimeControlStatus)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".privoke.v1.RuntimeControlStatus: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.privoke.v1.RuntimeControlStatus();
                if (object.enabled != null)
                    if (object.enabled)
                        message.enabled = $Boolean(object.enabled);
                if (object.status != null)
                    if (typeof object.status !== "string" || object.status.length)
                        message.status = $String(object.status);
                if (object.message != null)
                    if (typeof object.message !== "string" || object.message.length)
                        message.message = $String(object.message);
                if (object.processId != null)
                    if ($Number(object.processId) !== 0)
                        message.processId = object.processId >>> 0;
                return message;
            };

            /**
             * Creates a plain object from a RuntimeControlStatus message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.RuntimeControlStatus
             * @static
             * @param {privoke.v1.RuntimeControlStatus} message RuntimeControlStatus
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            RuntimeControlStatus.toObject = function (message, options, _depth) {
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

            /**
             * Converts this RuntimeControlStatus to JSON.
             * @function toJSON
             * @memberof privoke.v1.RuntimeControlStatus
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            RuntimeControlStatus.prototype.toJSON = function() {
                return RuntimeControlStatus.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for RuntimeControlStatus
             * @function getTypeUrl
             * @memberof privoke.v1.RuntimeControlStatus
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            RuntimeControlStatus.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.RuntimeControlStatus";
            };

            return RuntimeControlStatus;
        })();

        /**
         * DetectionLayer enum.
         * @name privoke.v1.DetectionLayer
         * @enum {number}
         * @property {number} DETECTION_LAYER_UNSPECIFIED=0 DETECTION_LAYER_UNSPECIFIED value
         * @property {number} DETECTION_LAYER_RUNTIME=1 DETECTION_LAYER_RUNTIME value
         * @property {number} DETECTION_LAYER_REGEX=2 DETECTION_LAYER_REGEX value
         * @property {number} DETECTION_LAYER_NER=3 DETECTION_LAYER_NER value
         * @property {number} DETECTION_LAYER_SEMANTIC=4 DETECTION_LAYER_SEMANTIC value
         */
        v1.DetectionLayer = (function() {
            const valuesById = $Object.create(null), values = $Object.create(valuesById);
            values[valuesById[0] = "DETECTION_LAYER_UNSPECIFIED"] = 0;
            values[valuesById[1] = "DETECTION_LAYER_RUNTIME"] = 1;
            values[valuesById[2] = "DETECTION_LAYER_REGEX"] = 2;
            values[valuesById[3] = "DETECTION_LAYER_NER"] = 3;
            values[valuesById[4] = "DETECTION_LAYER_SEMANTIC"] = 4;
            return values;
        })();

        /**
         * RegexExecutionOrder enum.
         * @name privoke.v1.RegexExecutionOrder
         * @enum {number}
         * @property {number} REGEX_EXECUTION_ORDER_DEFAULT=0 REGEX_EXECUTION_ORDER_DEFAULT value
         * @property {number} REGEX_EXECUTION_ORDER_FIRST=1 REGEX_EXECUTION_ORDER_FIRST value
         * @property {number} REGEX_EXECUTION_ORDER_PARALLEL=2 REGEX_EXECUTION_ORDER_PARALLEL value
         */
        v1.RegexExecutionOrder = (function() {
            const valuesById = $Object.create(null), values = $Object.create(valuesById);
            values[valuesById[0] = "REGEX_EXECUTION_ORDER_DEFAULT"] = 0;
            values[valuesById[1] = "REGEX_EXECUTION_ORDER_FIRST"] = 1;
            values[valuesById[2] = "REGEX_EXECUTION_ORDER_PARALLEL"] = 2;
            return values;
        })();

        v1.AnalyzePromptRequest = (function() {

            /**
             * Properties of an AnalyzePromptRequest.
             * @typedef {Object} privoke.v1.AnalyzePromptRequest.$Properties
             * @property {string|null} [text] AnalyzePromptRequest text
             * @property {string|null} [source] AnalyzePromptRequest source
             * @property {string|null} [targetApp] AnalyzePromptRequest targetApp
             * @property {string|null} [visibilityHint] AnalyzePromptRequest visibilityHint
             * @property {string|null} [requestId] AnalyzePromptRequest requestId
             * @property {Object.<string,string>|null} [metadata] AnalyzePromptRequest metadata
             * @property {Array.<privoke.v1.DetectionLayer>|null} [layers] AnalyzePromptRequest layers
             * @property {privoke.v1.RegexExecutionOrder|null} [regexExecutionOrder] AnalyzePromptRequest regexExecutionOrder
             * @property {string|null} [semanticModelId] AnalyzePromptRequest semanticModelId
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of an AnalyzePromptRequest.
             * @memberof privoke.v1
             * @interface IAnalyzePromptRequest
             * @augments privoke.v1.AnalyzePromptRequest.$Properties
             * @deprecated Use privoke.v1.AnalyzePromptRequest.$Properties instead.
             */

            /**
             * Shape of an AnalyzePromptRequest.
             * @typedef {privoke.v1.AnalyzePromptRequest.$Properties} privoke.v1.AnalyzePromptRequest.$Shape
             */

            /**
             * Constructs a new AnalyzePromptRequest.
             * @memberof privoke.v1
             * @classdesc Represents an AnalyzePromptRequest.
             * @constructor
             * @param {privoke.v1.AnalyzePromptRequest.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const AnalyzePromptRequest = function (properties) {
                this.metadata = {};
                this.layers = [];
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * AnalyzePromptRequest text.
             * @member {string} text
             * @memberof privoke.v1.AnalyzePromptRequest
             * @instance
             */
            AnalyzePromptRequest.prototype.text = "";

            /**
             * AnalyzePromptRequest source.
             * @member {string} source
             * @memberof privoke.v1.AnalyzePromptRequest
             * @instance
             */
            AnalyzePromptRequest.prototype.source = "";

            /**
             * AnalyzePromptRequest targetApp.
             * @member {string} targetApp
             * @memberof privoke.v1.AnalyzePromptRequest
             * @instance
             */
            AnalyzePromptRequest.prototype.targetApp = "";

            /**
             * AnalyzePromptRequest visibilityHint.
             * @member {string} visibilityHint
             * @memberof privoke.v1.AnalyzePromptRequest
             * @instance
             */
            AnalyzePromptRequest.prototype.visibilityHint = "";

            /**
             * AnalyzePromptRequest requestId.
             * @member {string} requestId
             * @memberof privoke.v1.AnalyzePromptRequest
             * @instance
             */
            AnalyzePromptRequest.prototype.requestId = "";

            /**
             * AnalyzePromptRequest metadata.
             * @member {Object.<string,string>} metadata
             * @memberof privoke.v1.AnalyzePromptRequest
             * @instance
             */
            AnalyzePromptRequest.prototype.metadata = $util.emptyObject;

            /**
             * AnalyzePromptRequest layers.
             * @member {Array.<privoke.v1.DetectionLayer>} layers
             * @memberof privoke.v1.AnalyzePromptRequest
             * @instance
             */
            AnalyzePromptRequest.prototype.layers = $util.emptyArray;

            /**
             * AnalyzePromptRequest regexExecutionOrder.
             * @member {privoke.v1.RegexExecutionOrder} regexExecutionOrder
             * @memberof privoke.v1.AnalyzePromptRequest
             * @instance
             */
            AnalyzePromptRequest.prototype.regexExecutionOrder = 0;

            /**
             * AnalyzePromptRequest semanticModelId.
             * @member {string} semanticModelId
             * @memberof privoke.v1.AnalyzePromptRequest
             * @instance
             */
            AnalyzePromptRequest.prototype.semanticModelId = "";

            /**
             * Creates a new AnalyzePromptRequest instance using the specified properties.
             * @function create
             * @memberof privoke.v1.AnalyzePromptRequest
             * @static
             * @param {privoke.v1.AnalyzePromptRequest.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.AnalyzePromptRequest} AnalyzePromptRequest instance
             * @type {{
             *   (properties: privoke.v1.AnalyzePromptRequest.$Shape): privoke.v1.AnalyzePromptRequest & privoke.v1.AnalyzePromptRequest.$Shape;
             *   (properties?: privoke.v1.AnalyzePromptRequest.$Properties): privoke.v1.AnalyzePromptRequest;
             * }}
             */
            AnalyzePromptRequest.create = function(properties) {
                return new AnalyzePromptRequest(properties);
            };

            /**
             * Encodes the specified AnalyzePromptRequest message. Does not implicitly {@link privoke.v1.AnalyzePromptRequest.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.AnalyzePromptRequest
             * @static
             * @param {privoke.v1.AnalyzePromptRequest.$Properties} message AnalyzePromptRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            AnalyzePromptRequest.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.text != null && $Object.hasOwnProperty.call(message, "text") && message.text !== "")
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.text);
                if (message.source != null && $Object.hasOwnProperty.call(message, "source") && message.source !== "")
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.source);
                if (message.targetApp != null && $Object.hasOwnProperty.call(message, "targetApp") && message.targetApp !== "")
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.targetApp);
                if (message.visibilityHint != null && $Object.hasOwnProperty.call(message, "visibilityHint") && message.visibilityHint !== "")
                    writer.uint32(/* id 4, wireType 2 =*/34).string(message.visibilityHint);
                if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId") && message.requestId !== "")
                    writer.uint32(/* id 5, wireType 2 =*/42).string(message.requestId);
                if (message.metadata != null && $Object.hasOwnProperty.call(message, "metadata"))
                    for (let keys = $Object.keys(message.metadata), i = 0; i < keys.length; ++i)
                        writer.uint32(/* id 6, wireType 2 =*/50).fork().uint32(/* id 1, wireType 2 =*/10).string(keys[i]).uint32(/* id 2, wireType 2 =*/18).string(message.metadata[keys[i]]).ldelim();
                if (message.layers != null && message.layers.length)
                    writer.uint32(/* id 7, wireType 2 =*/58).int32s(message.layers);
                if (message.regexExecutionOrder != null && $Object.hasOwnProperty.call(message, "regexExecutionOrder") && message.regexExecutionOrder !== 0)
                    writer.uint32(/* id 8, wireType 0 =*/64).int32(message.regexExecutionOrder);
                if (message.semanticModelId != null && $Object.hasOwnProperty.call(message, "semanticModelId") && message.semanticModelId !== "")
                    writer.uint32(/* id 9, wireType 2 =*/74).string(message.semanticModelId);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified AnalyzePromptRequest message, length delimited. Does not implicitly {@link privoke.v1.AnalyzePromptRequest.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.AnalyzePromptRequest
             * @static
             * @param {privoke.v1.AnalyzePromptRequest.$Properties} message AnalyzePromptRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            AnalyzePromptRequest.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes an AnalyzePromptRequest message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.AnalyzePromptRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.AnalyzePromptRequest & privoke.v1.AnalyzePromptRequest.$Shape} AnalyzePromptRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            AnalyzePromptRequest.decode = function (reader, length, _end, _depth, _target) {
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

            /**
             * Decodes an AnalyzePromptRequest message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.AnalyzePromptRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.AnalyzePromptRequest & privoke.v1.AnalyzePromptRequest.$Shape} AnalyzePromptRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            AnalyzePromptRequest.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies an AnalyzePromptRequest message.
             * @function verify
             * @memberof privoke.v1.AnalyzePromptRequest
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            AnalyzePromptRequest.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                if (message.text != null && $Object.hasOwnProperty.call(message, "text"))
                    if (!$util.isString(message.text))
                        return "text: string expected";
                if (message.source != null && $Object.hasOwnProperty.call(message, "source"))
                    if (!$util.isString(message.source))
                        return "source: string expected";
                if (message.targetApp != null && $Object.hasOwnProperty.call(message, "targetApp"))
                    if (!$util.isString(message.targetApp))
                        return "targetApp: string expected";
                if (message.visibilityHint != null && $Object.hasOwnProperty.call(message, "visibilityHint"))
                    if (!$util.isString(message.visibilityHint))
                        return "visibilityHint: string expected";
                if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId"))
                    if (!$util.isString(message.requestId))
                        return "requestId: string expected";
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
                if (message.regexExecutionOrder != null && $Object.hasOwnProperty.call(message, "regexExecutionOrder"))
                    if (typeof message.regexExecutionOrder !== "number" || (message.regexExecutionOrder | 0) !== message.regexExecutionOrder)
                        return "regexExecutionOrder: enum value expected";
                if (message.semanticModelId != null && $Object.hasOwnProperty.call(message, "semanticModelId"))
                    if (!$util.isString(message.semanticModelId))
                        return "semanticModelId: string expected";
                return null;
            };

            /**
             * Creates an AnalyzePromptRequest message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.AnalyzePromptRequest
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.AnalyzePromptRequest} AnalyzePromptRequest
             */
            AnalyzePromptRequest.fromObject = function (object, _depth) {
                if (object instanceof $root.privoke.v1.AnalyzePromptRequest)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".privoke.v1.AnalyzePromptRequest: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.privoke.v1.AnalyzePromptRequest();
                if (object.text != null)
                    if (typeof object.text !== "string" || object.text.length)
                        message.text = $String(object.text);
                if (object.source != null)
                    if (typeof object.source !== "string" || object.source.length)
                        message.source = $String(object.source);
                if (object.targetApp != null)
                    if (typeof object.targetApp !== "string" || object.targetApp.length)
                        message.targetApp = $String(object.targetApp);
                if (object.visibilityHint != null)
                    if (typeof object.visibilityHint !== "string" || object.visibilityHint.length)
                        message.visibilityHint = $String(object.visibilityHint);
                if (object.requestId != null)
                    if (typeof object.requestId !== "string" || object.requestId.length)
                        message.requestId = $String(object.requestId);
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
                if (object.semanticModelId != null)
                    if (typeof object.semanticModelId !== "string" || object.semanticModelId.length)
                        message.semanticModelId = $String(object.semanticModelId);
                return message;
            };

            /**
             * Creates a plain object from an AnalyzePromptRequest message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.AnalyzePromptRequest
             * @static
             * @param {privoke.v1.AnalyzePromptRequest} message AnalyzePromptRequest
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            AnalyzePromptRequest.toObject = function (message, options, _depth) {
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

            /**
             * Converts this AnalyzePromptRequest to JSON.
             * @function toJSON
             * @memberof privoke.v1.AnalyzePromptRequest
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            AnalyzePromptRequest.prototype.toJSON = function() {
                return AnalyzePromptRequest.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for AnalyzePromptRequest
             * @function getTypeUrl
             * @memberof privoke.v1.AnalyzePromptRequest
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            AnalyzePromptRequest.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.AnalyzePromptRequest";
            };

            return AnalyzePromptRequest;
        })();

        v1.RuntimeLayerExecution = (function() {

            /**
             * Properties of a RuntimeLayerExecution.
             * @typedef {Object} privoke.v1.RuntimeLayerExecution.$Properties
             * @property {privoke.v1.DetectionLayer|null} [layer] RuntimeLayerExecution layer
             * @property {string|null} [status] RuntimeLayerExecution status
             * @property {Array.<privoke.v1.RuntimeDetectionResult.$Properties>|null} [results] RuntimeLayerExecution results
             * @property {string|null} [error] RuntimeLayerExecution error
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a RuntimeLayerExecution.
             * @memberof privoke.v1
             * @interface IRuntimeLayerExecution
             * @augments privoke.v1.RuntimeLayerExecution.$Properties
             * @deprecated Use privoke.v1.RuntimeLayerExecution.$Properties instead.
             */

            /**
             * Shape of a RuntimeLayerExecution.
             * @typedef {privoke.v1.RuntimeLayerExecution.$Properties} privoke.v1.RuntimeLayerExecution.$Shape
             */

            /**
             * Constructs a new RuntimeLayerExecution.
             * @memberof privoke.v1
             * @classdesc Represents a RuntimeLayerExecution.
             * @constructor
             * @param {privoke.v1.RuntimeLayerExecution.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const RuntimeLayerExecution = function (properties) {
                this.results = [];
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * RuntimeLayerExecution layer.
             * @member {privoke.v1.DetectionLayer} layer
             * @memberof privoke.v1.RuntimeLayerExecution
             * @instance
             */
            RuntimeLayerExecution.prototype.layer = 0;

            /**
             * RuntimeLayerExecution status.
             * @member {string} status
             * @memberof privoke.v1.RuntimeLayerExecution
             * @instance
             */
            RuntimeLayerExecution.prototype.status = "";

            /**
             * RuntimeLayerExecution results.
             * @member {Array.<privoke.v1.RuntimeDetectionResult.$Properties>} results
             * @memberof privoke.v1.RuntimeLayerExecution
             * @instance
             */
            RuntimeLayerExecution.prototype.results = $util.emptyArray;

            /**
             * RuntimeLayerExecution error.
             * @member {string} error
             * @memberof privoke.v1.RuntimeLayerExecution
             * @instance
             */
            RuntimeLayerExecution.prototype.error = "";

            /**
             * Creates a new RuntimeLayerExecution instance using the specified properties.
             * @function create
             * @memberof privoke.v1.RuntimeLayerExecution
             * @static
             * @param {privoke.v1.RuntimeLayerExecution.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.RuntimeLayerExecution} RuntimeLayerExecution instance
             * @type {{
             *   (properties: privoke.v1.RuntimeLayerExecution.$Shape): privoke.v1.RuntimeLayerExecution & privoke.v1.RuntimeLayerExecution.$Shape;
             *   (properties?: privoke.v1.RuntimeLayerExecution.$Properties): privoke.v1.RuntimeLayerExecution;
             * }}
             */
            RuntimeLayerExecution.create = function(properties) {
                return new RuntimeLayerExecution(properties);
            };

            /**
             * Encodes the specified RuntimeLayerExecution message. Does not implicitly {@link privoke.v1.RuntimeLayerExecution.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.RuntimeLayerExecution
             * @static
             * @param {privoke.v1.RuntimeLayerExecution.$Properties} message RuntimeLayerExecution message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeLayerExecution.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.layer != null && $Object.hasOwnProperty.call(message, "layer") && message.layer !== 0)
                    writer.uint32(/* id 1, wireType 0 =*/8).int32(message.layer);
                if (message.status != null && $Object.hasOwnProperty.call(message, "status") && message.status !== "")
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.status);
                if (message.results != null && message.results.length)
                    for (let i = 0; i < message.results.length; ++i)
                        $root.privoke.v1.RuntimeDetectionResult.encode(message.results[i], writer.uint32(/* id 3, wireType 2 =*/26).fork(), _depth + 1).ldelim();
                if (message.error != null && $Object.hasOwnProperty.call(message, "error") && message.error !== "")
                    writer.uint32(/* id 4, wireType 2 =*/34).string(message.error);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified RuntimeLayerExecution message, length delimited. Does not implicitly {@link privoke.v1.RuntimeLayerExecution.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.RuntimeLayerExecution
             * @static
             * @param {privoke.v1.RuntimeLayerExecution.$Properties} message RuntimeLayerExecution message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeLayerExecution.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a RuntimeLayerExecution message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.RuntimeLayerExecution
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.RuntimeLayerExecution & privoke.v1.RuntimeLayerExecution.$Shape} RuntimeLayerExecution
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeLayerExecution.decode = function (reader, length, _end, _depth, _target) {
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

            /**
             * Decodes a RuntimeLayerExecution message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.RuntimeLayerExecution
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.RuntimeLayerExecution & privoke.v1.RuntimeLayerExecution.$Shape} RuntimeLayerExecution
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeLayerExecution.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a RuntimeLayerExecution message.
             * @function verify
             * @memberof privoke.v1.RuntimeLayerExecution
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            RuntimeLayerExecution.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                if (message.layer != null && $Object.hasOwnProperty.call(message, "layer"))
                    if (typeof message.layer !== "number" || (message.layer | 0) !== message.layer)
                        return "layer: enum value expected";
                if (message.status != null && $Object.hasOwnProperty.call(message, "status"))
                    if (!$util.isString(message.status))
                        return "status: string expected";
                if (message.results != null && $Object.hasOwnProperty.call(message, "results")) {
                    if (!$Array.isArray(message.results))
                        return "results: array expected";
                    for (let i = 0; i < message.results.length; ++i) {
                        let error = $root.privoke.v1.RuntimeDetectionResult.verify(message.results[i], _depth + 1);
                        if (error)
                            return "results." + error;
                    }
                }
                if (message.error != null && $Object.hasOwnProperty.call(message, "error"))
                    if (!$util.isString(message.error))
                        return "error: string expected";
                return null;
            };

            /**
             * Creates a RuntimeLayerExecution message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.RuntimeLayerExecution
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.RuntimeLayerExecution} RuntimeLayerExecution
             */
            RuntimeLayerExecution.fromObject = function (object, _depth) {
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
                if (object.status != null)
                    if (typeof object.status !== "string" || object.status.length)
                        message.status = $String(object.status);
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
                if (object.error != null)
                    if (typeof object.error !== "string" || object.error.length)
                        message.error = $String(object.error);
                return message;
            };

            /**
             * Creates a plain object from a RuntimeLayerExecution message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.RuntimeLayerExecution
             * @static
             * @param {privoke.v1.RuntimeLayerExecution} message RuntimeLayerExecution
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            RuntimeLayerExecution.toObject = function (message, options, _depth) {
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

            /**
             * Converts this RuntimeLayerExecution to JSON.
             * @function toJSON
             * @memberof privoke.v1.RuntimeLayerExecution
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            RuntimeLayerExecution.prototype.toJSON = function() {
                return RuntimeLayerExecution.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for RuntimeLayerExecution
             * @function getTypeUrl
             * @memberof privoke.v1.RuntimeLayerExecution
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            RuntimeLayerExecution.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.RuntimeLayerExecution";
            };

            return RuntimeLayerExecution;
        })();

        v1.RuntimeClassification = (function() {

            /**
             * Properties of a RuntimeClassification.
             * @typedef {Object} privoke.v1.RuntimeClassification.$Properties
             * @property {string|null} [sensitivity] RuntimeClassification sensitivity
             * @property {string|null} [visibility] RuntimeClassification visibility
             * @property {Array.<string>|null} [categories] RuntimeClassification categories
             * @property {number|null} [packed] RuntimeClassification packed
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a RuntimeClassification.
             * @memberof privoke.v1
             * @interface IRuntimeClassification
             * @augments privoke.v1.RuntimeClassification.$Properties
             * @deprecated Use privoke.v1.RuntimeClassification.$Properties instead.
             */

            /**
             * Shape of a RuntimeClassification.
             * @typedef {privoke.v1.RuntimeClassification.$Properties} privoke.v1.RuntimeClassification.$Shape
             */

            /**
             * Constructs a new RuntimeClassification.
             * @memberof privoke.v1
             * @classdesc Represents a RuntimeClassification.
             * @constructor
             * @param {privoke.v1.RuntimeClassification.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const RuntimeClassification = function (properties) {
                this.categories = [];
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * RuntimeClassification sensitivity.
             * @member {string} sensitivity
             * @memberof privoke.v1.RuntimeClassification
             * @instance
             */
            RuntimeClassification.prototype.sensitivity = "";

            /**
             * RuntimeClassification visibility.
             * @member {string} visibility
             * @memberof privoke.v1.RuntimeClassification
             * @instance
             */
            RuntimeClassification.prototype.visibility = "";

            /**
             * RuntimeClassification categories.
             * @member {Array.<string>} categories
             * @memberof privoke.v1.RuntimeClassification
             * @instance
             */
            RuntimeClassification.prototype.categories = $util.emptyArray;

            /**
             * RuntimeClassification packed.
             * @member {number} packed
             * @memberof privoke.v1.RuntimeClassification
             * @instance
             */
            RuntimeClassification.prototype.packed = 0;

            /**
             * Creates a new RuntimeClassification instance using the specified properties.
             * @function create
             * @memberof privoke.v1.RuntimeClassification
             * @static
             * @param {privoke.v1.RuntimeClassification.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.RuntimeClassification} RuntimeClassification instance
             * @type {{
             *   (properties: privoke.v1.RuntimeClassification.$Shape): privoke.v1.RuntimeClassification & privoke.v1.RuntimeClassification.$Shape;
             *   (properties?: privoke.v1.RuntimeClassification.$Properties): privoke.v1.RuntimeClassification;
             * }}
             */
            RuntimeClassification.create = function(properties) {
                return new RuntimeClassification(properties);
            };

            /**
             * Encodes the specified RuntimeClassification message. Does not implicitly {@link privoke.v1.RuntimeClassification.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.RuntimeClassification
             * @static
             * @param {privoke.v1.RuntimeClassification.$Properties} message RuntimeClassification message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeClassification.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.sensitivity != null && $Object.hasOwnProperty.call(message, "sensitivity") && message.sensitivity !== "")
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.sensitivity);
                if (message.visibility != null && $Object.hasOwnProperty.call(message, "visibility") && message.visibility !== "")
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.visibility);
                if (message.categories != null && message.categories.length)
                    for (let i = 0; i < message.categories.length; ++i)
                        writer.uint32(/* id 3, wireType 2 =*/26).string(message.categories[i]);
                if (message.packed != null && $Object.hasOwnProperty.call(message, "packed") && message.packed !== 0)
                    writer.uint32(/* id 4, wireType 0 =*/32).uint32(message.packed);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified RuntimeClassification message, length delimited. Does not implicitly {@link privoke.v1.RuntimeClassification.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.RuntimeClassification
             * @static
             * @param {privoke.v1.RuntimeClassification.$Properties} message RuntimeClassification message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeClassification.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a RuntimeClassification message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.RuntimeClassification
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.RuntimeClassification & privoke.v1.RuntimeClassification.$Shape} RuntimeClassification
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeClassification.decode = function (reader, length, _end, _depth, _target) {
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

            /**
             * Decodes a RuntimeClassification message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.RuntimeClassification
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.RuntimeClassification & privoke.v1.RuntimeClassification.$Shape} RuntimeClassification
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeClassification.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a RuntimeClassification message.
             * @function verify
             * @memberof privoke.v1.RuntimeClassification
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            RuntimeClassification.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                if (message.sensitivity != null && $Object.hasOwnProperty.call(message, "sensitivity"))
                    if (!$util.isString(message.sensitivity))
                        return "sensitivity: string expected";
                if (message.visibility != null && $Object.hasOwnProperty.call(message, "visibility"))
                    if (!$util.isString(message.visibility))
                        return "visibility: string expected";
                if (message.categories != null && $Object.hasOwnProperty.call(message, "categories")) {
                    if (!$Array.isArray(message.categories))
                        return "categories: array expected";
                    for (let i = 0; i < message.categories.length; ++i)
                        if (!$util.isString(message.categories[i]))
                            return "categories: string[] expected";
                }
                if (message.packed != null && $Object.hasOwnProperty.call(message, "packed"))
                    if (!$util.isInteger(message.packed))
                        return "packed: integer expected";
                return null;
            };

            /**
             * Creates a RuntimeClassification message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.RuntimeClassification
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.RuntimeClassification} RuntimeClassification
             */
            RuntimeClassification.fromObject = function (object, _depth) {
                if (object instanceof $root.privoke.v1.RuntimeClassification)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".privoke.v1.RuntimeClassification: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.privoke.v1.RuntimeClassification();
                if (object.sensitivity != null)
                    if (typeof object.sensitivity !== "string" || object.sensitivity.length)
                        message.sensitivity = $String(object.sensitivity);
                if (object.visibility != null)
                    if (typeof object.visibility !== "string" || object.visibility.length)
                        message.visibility = $String(object.visibility);
                if (object.categories) {
                    if (!$Array.isArray(object.categories))
                        throw $TypeError(".privoke.v1.RuntimeClassification.categories: array expected");
                    message.categories = $Array(object.categories.length);
                    for (let i = 0; i < object.categories.length; ++i)
                        message.categories[i] = $String(object.categories[i]);
                }
                if (object.packed != null)
                    if ($Number(object.packed) !== 0)
                        message.packed = object.packed >>> 0;
                return message;
            };

            /**
             * Creates a plain object from a RuntimeClassification message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.RuntimeClassification
             * @static
             * @param {privoke.v1.RuntimeClassification} message RuntimeClassification
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            RuntimeClassification.toObject = function (message, options, _depth) {
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

            /**
             * Converts this RuntimeClassification to JSON.
             * @function toJSON
             * @memberof privoke.v1.RuntimeClassification
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            RuntimeClassification.prototype.toJSON = function() {
                return RuntimeClassification.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for RuntimeClassification
             * @function getTypeUrl
             * @memberof privoke.v1.RuntimeClassification
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            RuntimeClassification.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.RuntimeClassification";
            };

            return RuntimeClassification;
        })();

        v1.RuntimeDetectionResult = (function() {

            /**
             * Properties of a RuntimeDetectionResult.
             * @typedef {Object} privoke.v1.RuntimeDetectionResult.$Properties
             * @property {privoke.v1.RuntimeClassification.$Properties|null} [classification] RuntimeDetectionResult classification
             * @property {string|null} [action] RuntimeDetectionResult action
             * @property {string|null} [sectionOfText] RuntimeDetectionResult sectionOfText
             * @property {number|null} [spanStart] RuntimeDetectionResult spanStart
             * @property {number|null} [spanEnd] RuntimeDetectionResult spanEnd
             * @property {boolean|null} [hasSpan] RuntimeDetectionResult hasSpan
             * @property {number|null} [confidence] RuntimeDetectionResult confidence
             * @property {boolean|null} [hasConfidence] RuntimeDetectionResult hasConfidence
             * @property {string|null} [reasoning] RuntimeDetectionResult reasoning
             * @property {Object.<string,string>|null} [metadata] RuntimeDetectionResult metadata
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a RuntimeDetectionResult.
             * @memberof privoke.v1
             * @interface IRuntimeDetectionResult
             * @augments privoke.v1.RuntimeDetectionResult.$Properties
             * @deprecated Use privoke.v1.RuntimeDetectionResult.$Properties instead.
             */

            /**
             * Shape of a RuntimeDetectionResult.
             * @typedef {privoke.v1.RuntimeDetectionResult.$Properties} privoke.v1.RuntimeDetectionResult.$Shape
             */

            /**
             * Constructs a new RuntimeDetectionResult.
             * @memberof privoke.v1
             * @classdesc Represents a RuntimeDetectionResult.
             * @constructor
             * @param {privoke.v1.RuntimeDetectionResult.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const RuntimeDetectionResult = function (properties) {
                this.metadata = {};
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * RuntimeDetectionResult classification.
             * @member {privoke.v1.RuntimeClassification.$Properties|null|undefined} classification
             * @memberof privoke.v1.RuntimeDetectionResult
             * @instance
             */
            RuntimeDetectionResult.prototype.classification = null;

            /**
             * RuntimeDetectionResult action.
             * @member {string} action
             * @memberof privoke.v1.RuntimeDetectionResult
             * @instance
             */
            RuntimeDetectionResult.prototype.action = "";

            /**
             * RuntimeDetectionResult sectionOfText.
             * @member {string} sectionOfText
             * @memberof privoke.v1.RuntimeDetectionResult
             * @instance
             */
            RuntimeDetectionResult.prototype.sectionOfText = "";

            /**
             * RuntimeDetectionResult spanStart.
             * @member {number} spanStart
             * @memberof privoke.v1.RuntimeDetectionResult
             * @instance
             */
            RuntimeDetectionResult.prototype.spanStart = 0;

            /**
             * RuntimeDetectionResult spanEnd.
             * @member {number} spanEnd
             * @memberof privoke.v1.RuntimeDetectionResult
             * @instance
             */
            RuntimeDetectionResult.prototype.spanEnd = 0;

            /**
             * RuntimeDetectionResult hasSpan.
             * @member {boolean} hasSpan
             * @memberof privoke.v1.RuntimeDetectionResult
             * @instance
             */
            RuntimeDetectionResult.prototype.hasSpan = false;

            /**
             * RuntimeDetectionResult confidence.
             * @member {number} confidence
             * @memberof privoke.v1.RuntimeDetectionResult
             * @instance
             */
            RuntimeDetectionResult.prototype.confidence = 0;

            /**
             * RuntimeDetectionResult hasConfidence.
             * @member {boolean} hasConfidence
             * @memberof privoke.v1.RuntimeDetectionResult
             * @instance
             */
            RuntimeDetectionResult.prototype.hasConfidence = false;

            /**
             * RuntimeDetectionResult reasoning.
             * @member {string} reasoning
             * @memberof privoke.v1.RuntimeDetectionResult
             * @instance
             */
            RuntimeDetectionResult.prototype.reasoning = "";

            /**
             * RuntimeDetectionResult metadata.
             * @member {Object.<string,string>} metadata
             * @memberof privoke.v1.RuntimeDetectionResult
             * @instance
             */
            RuntimeDetectionResult.prototype.metadata = $util.emptyObject;

            /**
             * Creates a new RuntimeDetectionResult instance using the specified properties.
             * @function create
             * @memberof privoke.v1.RuntimeDetectionResult
             * @static
             * @param {privoke.v1.RuntimeDetectionResult.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.RuntimeDetectionResult} RuntimeDetectionResult instance
             * @type {{
             *   (properties: privoke.v1.RuntimeDetectionResult.$Shape): privoke.v1.RuntimeDetectionResult & privoke.v1.RuntimeDetectionResult.$Shape;
             *   (properties?: privoke.v1.RuntimeDetectionResult.$Properties): privoke.v1.RuntimeDetectionResult;
             * }}
             */
            RuntimeDetectionResult.create = function(properties) {
                return new RuntimeDetectionResult(properties);
            };

            /**
             * Encodes the specified RuntimeDetectionResult message. Does not implicitly {@link privoke.v1.RuntimeDetectionResult.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.RuntimeDetectionResult
             * @static
             * @param {privoke.v1.RuntimeDetectionResult.$Properties} message RuntimeDetectionResult message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeDetectionResult.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.classification != null && $Object.hasOwnProperty.call(message, "classification"))
                    $root.privoke.v1.RuntimeClassification.encode(message.classification, writer.uint32(/* id 1, wireType 2 =*/10).fork(), _depth + 1).ldelim();
                if (message.action != null && $Object.hasOwnProperty.call(message, "action") && message.action !== "")
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.action);
                if (message.sectionOfText != null && $Object.hasOwnProperty.call(message, "sectionOfText") && message.sectionOfText !== "")
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.sectionOfText);
                if (message.spanStart != null && $Object.hasOwnProperty.call(message, "spanStart") && message.spanStart !== 0)
                    writer.uint32(/* id 4, wireType 0 =*/32).int32(message.spanStart);
                if (message.spanEnd != null && $Object.hasOwnProperty.call(message, "spanEnd") && message.spanEnd !== 0)
                    writer.uint32(/* id 5, wireType 0 =*/40).int32(message.spanEnd);
                if (message.hasSpan != null && $Object.hasOwnProperty.call(message, "hasSpan") && message.hasSpan !== false)
                    writer.uint32(/* id 6, wireType 0 =*/48).bool(message.hasSpan);
                if (message.confidence != null && $Object.hasOwnProperty.call(message, "confidence") && !$Object.is(message.confidence, 0))
                    writer.uint32(/* id 7, wireType 1 =*/57).double(message.confidence);
                if (message.hasConfidence != null && $Object.hasOwnProperty.call(message, "hasConfidence") && message.hasConfidence !== false)
                    writer.uint32(/* id 8, wireType 0 =*/64).bool(message.hasConfidence);
                if (message.reasoning != null && $Object.hasOwnProperty.call(message, "reasoning") && message.reasoning !== "")
                    writer.uint32(/* id 9, wireType 2 =*/74).string(message.reasoning);
                if (message.metadata != null && $Object.hasOwnProperty.call(message, "metadata"))
                    for (let keys = $Object.keys(message.metadata), i = 0; i < keys.length; ++i)
                        writer.uint32(/* id 10, wireType 2 =*/82).fork().uint32(/* id 1, wireType 2 =*/10).string(keys[i]).uint32(/* id 2, wireType 2 =*/18).string(message.metadata[keys[i]]).ldelim();
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified RuntimeDetectionResult message, length delimited. Does not implicitly {@link privoke.v1.RuntimeDetectionResult.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.RuntimeDetectionResult
             * @static
             * @param {privoke.v1.RuntimeDetectionResult.$Properties} message RuntimeDetectionResult message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeDetectionResult.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a RuntimeDetectionResult message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.RuntimeDetectionResult
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.RuntimeDetectionResult & privoke.v1.RuntimeDetectionResult.$Shape} RuntimeDetectionResult
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeDetectionResult.decode = function (reader, length, _end, _depth, _target) {
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

            /**
             * Decodes a RuntimeDetectionResult message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.RuntimeDetectionResult
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.RuntimeDetectionResult & privoke.v1.RuntimeDetectionResult.$Shape} RuntimeDetectionResult
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeDetectionResult.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a RuntimeDetectionResult message.
             * @function verify
             * @memberof privoke.v1.RuntimeDetectionResult
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            RuntimeDetectionResult.verify = function (message, _depth) {
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
                if (message.action != null && $Object.hasOwnProperty.call(message, "action"))
                    if (!$util.isString(message.action))
                        return "action: string expected";
                if (message.sectionOfText != null && $Object.hasOwnProperty.call(message, "sectionOfText"))
                    if (!$util.isString(message.sectionOfText))
                        return "sectionOfText: string expected";
                if (message.spanStart != null && $Object.hasOwnProperty.call(message, "spanStart"))
                    if (!$util.isInteger(message.spanStart))
                        return "spanStart: integer expected";
                if (message.spanEnd != null && $Object.hasOwnProperty.call(message, "spanEnd"))
                    if (!$util.isInteger(message.spanEnd))
                        return "spanEnd: integer expected";
                if (message.hasSpan != null && $Object.hasOwnProperty.call(message, "hasSpan"))
                    if (typeof message.hasSpan !== "boolean")
                        return "hasSpan: boolean expected";
                if (message.confidence != null && $Object.hasOwnProperty.call(message, "confidence"))
                    if (typeof message.confidence !== "number")
                        return "confidence: number expected";
                if (message.hasConfidence != null && $Object.hasOwnProperty.call(message, "hasConfidence"))
                    if (typeof message.hasConfidence !== "boolean")
                        return "hasConfidence: boolean expected";
                if (message.reasoning != null && $Object.hasOwnProperty.call(message, "reasoning"))
                    if (!$util.isString(message.reasoning))
                        return "reasoning: string expected";
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

            /**
             * Creates a RuntimeDetectionResult message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.RuntimeDetectionResult
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.RuntimeDetectionResult} RuntimeDetectionResult
             */
            RuntimeDetectionResult.fromObject = function (object, _depth) {
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
                if (object.action != null)
                    if (typeof object.action !== "string" || object.action.length)
                        message.action = $String(object.action);
                if (object.sectionOfText != null)
                    if (typeof object.sectionOfText !== "string" || object.sectionOfText.length)
                        message.sectionOfText = $String(object.sectionOfText);
                if (object.spanStart != null)
                    if ($Number(object.spanStart) !== 0)
                        message.spanStart = object.spanStart | 0;
                if (object.spanEnd != null)
                    if ($Number(object.spanEnd) !== 0)
                        message.spanEnd = object.spanEnd | 0;
                if (object.hasSpan != null)
                    if (object.hasSpan)
                        message.hasSpan = $Boolean(object.hasSpan);
                if (object.confidence != null)
                    if (!$Object.is($Number(object.confidence), 0))
                        message.confidence = $Number(object.confidence);
                if (object.hasConfidence != null)
                    if (object.hasConfidence)
                        message.hasConfidence = $Boolean(object.hasConfidence);
                if (object.reasoning != null)
                    if (typeof object.reasoning !== "string" || object.reasoning.length)
                        message.reasoning = $String(object.reasoning);
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

            /**
             * Creates a plain object from a RuntimeDetectionResult message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.RuntimeDetectionResult
             * @static
             * @param {privoke.v1.RuntimeDetectionResult} message RuntimeDetectionResult
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            RuntimeDetectionResult.toObject = function (message, options, _depth) {
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

            /**
             * Converts this RuntimeDetectionResult to JSON.
             * @function toJSON
             * @memberof privoke.v1.RuntimeDetectionResult
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            RuntimeDetectionResult.prototype.toJSON = function() {
                return RuntimeDetectionResult.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for RuntimeDetectionResult
             * @function getTypeUrl
             * @memberof privoke.v1.RuntimeDetectionResult
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            RuntimeDetectionResult.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.RuntimeDetectionResult";
            };

            return RuntimeDetectionResult;
        })();

        v1.AnalyzePromptResponse = (function() {

            /**
             * Properties of an AnalyzePromptResponse.
             * @typedef {Object} privoke.v1.AnalyzePromptResponse.$Properties
             * @property {string|null} [requestId] AnalyzePromptResponse requestId
             * @property {string|null} [action] AnalyzePromptResponse action
             * @property {boolean|null} [allowed] AnalyzePromptResponse allowed
             * @property {string|null} [maskedText] AnalyzePromptResponse maskedText
             * @property {privoke.v1.RuntimeClassification.$Properties|null} [classification] AnalyzePromptResponse classification
             * @property {string|null} [reason] AnalyzePromptResponse reason
             * @property {privoke.v1.RuntimeDetectionResult.$Properties|null} [evidence] AnalyzePromptResponse evidence
             * @property {Object.<string,string>|null} [metadata] AnalyzePromptResponse metadata
             * @property {Array.<privoke.v1.RuntimeLayerExecution.$Properties>|null} [layers] AnalyzePromptResponse layers
             * @property {number|null} [elapsedMs] AnalyzePromptResponse elapsedMs
             * @property {string|null} [error] AnalyzePromptResponse error
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of an AnalyzePromptResponse.
             * @memberof privoke.v1
             * @interface IAnalyzePromptResponse
             * @augments privoke.v1.AnalyzePromptResponse.$Properties
             * @deprecated Use privoke.v1.AnalyzePromptResponse.$Properties instead.
             */

            /**
             * Shape of an AnalyzePromptResponse.
             * @typedef {privoke.v1.AnalyzePromptResponse.$Properties} privoke.v1.AnalyzePromptResponse.$Shape
             */

            /**
             * Constructs a new AnalyzePromptResponse.
             * @memberof privoke.v1
             * @classdesc Represents an AnalyzePromptResponse.
             * @constructor
             * @param {privoke.v1.AnalyzePromptResponse.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const AnalyzePromptResponse = function (properties) {
                this.metadata = {};
                this.layers = [];
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * AnalyzePromptResponse requestId.
             * @member {string} requestId
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             */
            AnalyzePromptResponse.prototype.requestId = "";

            /**
             * AnalyzePromptResponse action.
             * @member {string} action
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             */
            AnalyzePromptResponse.prototype.action = "";

            /**
             * AnalyzePromptResponse allowed.
             * @member {boolean} allowed
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             */
            AnalyzePromptResponse.prototype.allowed = false;

            /**
             * AnalyzePromptResponse maskedText.
             * @member {string} maskedText
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             */
            AnalyzePromptResponse.prototype.maskedText = "";

            /**
             * AnalyzePromptResponse classification.
             * @member {privoke.v1.RuntimeClassification.$Properties|null|undefined} classification
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             */
            AnalyzePromptResponse.prototype.classification = null;

            /**
             * AnalyzePromptResponse reason.
             * @member {string} reason
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             */
            AnalyzePromptResponse.prototype.reason = "";

            /**
             * AnalyzePromptResponse evidence.
             * @member {privoke.v1.RuntimeDetectionResult.$Properties|null|undefined} evidence
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             */
            AnalyzePromptResponse.prototype.evidence = null;

            /**
             * AnalyzePromptResponse metadata.
             * @member {Object.<string,string>} metadata
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             */
            AnalyzePromptResponse.prototype.metadata = $util.emptyObject;

            /**
             * AnalyzePromptResponse layers.
             * @member {Array.<privoke.v1.RuntimeLayerExecution.$Properties>} layers
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             */
            AnalyzePromptResponse.prototype.layers = $util.emptyArray;

            /**
             * AnalyzePromptResponse elapsedMs.
             * @member {number} elapsedMs
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             */
            AnalyzePromptResponse.prototype.elapsedMs = 0;

            /**
             * AnalyzePromptResponse error.
             * @member {string} error
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             */
            AnalyzePromptResponse.prototype.error = "";

            /**
             * Creates a new AnalyzePromptResponse instance using the specified properties.
             * @function create
             * @memberof privoke.v1.AnalyzePromptResponse
             * @static
             * @param {privoke.v1.AnalyzePromptResponse.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.AnalyzePromptResponse} AnalyzePromptResponse instance
             * @type {{
             *   (properties: privoke.v1.AnalyzePromptResponse.$Shape): privoke.v1.AnalyzePromptResponse & privoke.v1.AnalyzePromptResponse.$Shape;
             *   (properties?: privoke.v1.AnalyzePromptResponse.$Properties): privoke.v1.AnalyzePromptResponse;
             * }}
             */
            AnalyzePromptResponse.create = function(properties) {
                return new AnalyzePromptResponse(properties);
            };

            /**
             * Encodes the specified AnalyzePromptResponse message. Does not implicitly {@link privoke.v1.AnalyzePromptResponse.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.AnalyzePromptResponse
             * @static
             * @param {privoke.v1.AnalyzePromptResponse.$Properties} message AnalyzePromptResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            AnalyzePromptResponse.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId") && message.requestId !== "")
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.requestId);
                if (message.action != null && $Object.hasOwnProperty.call(message, "action") && message.action !== "")
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.action);
                if (message.allowed != null && $Object.hasOwnProperty.call(message, "allowed") && message.allowed !== false)
                    writer.uint32(/* id 3, wireType 0 =*/24).bool(message.allowed);
                if (message.maskedText != null && $Object.hasOwnProperty.call(message, "maskedText") && message.maskedText !== "")
                    writer.uint32(/* id 4, wireType 2 =*/34).string(message.maskedText);
                if (message.classification != null && $Object.hasOwnProperty.call(message, "classification"))
                    $root.privoke.v1.RuntimeClassification.encode(message.classification, writer.uint32(/* id 5, wireType 2 =*/42).fork(), _depth + 1).ldelim();
                if (message.reason != null && $Object.hasOwnProperty.call(message, "reason") && message.reason !== "")
                    writer.uint32(/* id 6, wireType 2 =*/50).string(message.reason);
                if (message.evidence != null && $Object.hasOwnProperty.call(message, "evidence"))
                    $root.privoke.v1.RuntimeDetectionResult.encode(message.evidence, writer.uint32(/* id 7, wireType 2 =*/58).fork(), _depth + 1).ldelim();
                if (message.metadata != null && $Object.hasOwnProperty.call(message, "metadata"))
                    for (let keys = $Object.keys(message.metadata), i = 0; i < keys.length; ++i)
                        writer.uint32(/* id 8, wireType 2 =*/66).fork().uint32(/* id 1, wireType 2 =*/10).string(keys[i]).uint32(/* id 2, wireType 2 =*/18).string(message.metadata[keys[i]]).ldelim();
                if (message.layers != null && message.layers.length)
                    for (let i = 0; i < message.layers.length; ++i)
                        $root.privoke.v1.RuntimeLayerExecution.encode(message.layers[i], writer.uint32(/* id 10, wireType 2 =*/82).fork(), _depth + 1).ldelim();
                if (message.elapsedMs != null && $Object.hasOwnProperty.call(message, "elapsedMs") && !$Object.is(message.elapsedMs, 0))
                    writer.uint32(/* id 11, wireType 1 =*/89).double(message.elapsedMs);
                if (message.error != null && $Object.hasOwnProperty.call(message, "error") && message.error !== "")
                    writer.uint32(/* id 12, wireType 2 =*/98).string(message.error);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified AnalyzePromptResponse message, length delimited. Does not implicitly {@link privoke.v1.AnalyzePromptResponse.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.AnalyzePromptResponse
             * @static
             * @param {privoke.v1.AnalyzePromptResponse.$Properties} message AnalyzePromptResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            AnalyzePromptResponse.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes an AnalyzePromptResponse message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.AnalyzePromptResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.AnalyzePromptResponse & privoke.v1.AnalyzePromptResponse.$Shape} AnalyzePromptResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            AnalyzePromptResponse.decode = function (reader, length, _end, _depth, _target) {
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

            /**
             * Decodes an AnalyzePromptResponse message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.AnalyzePromptResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.AnalyzePromptResponse & privoke.v1.AnalyzePromptResponse.$Shape} AnalyzePromptResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            AnalyzePromptResponse.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies an AnalyzePromptResponse message.
             * @function verify
             * @memberof privoke.v1.AnalyzePromptResponse
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            AnalyzePromptResponse.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId"))
                    if (!$util.isString(message.requestId))
                        return "requestId: string expected";
                if (message.action != null && $Object.hasOwnProperty.call(message, "action"))
                    if (!$util.isString(message.action))
                        return "action: string expected";
                if (message.allowed != null && $Object.hasOwnProperty.call(message, "allowed"))
                    if (typeof message.allowed !== "boolean")
                        return "allowed: boolean expected";
                if (message.maskedText != null && $Object.hasOwnProperty.call(message, "maskedText"))
                    if (!$util.isString(message.maskedText))
                        return "maskedText: string expected";
                if (message.classification != null && $Object.hasOwnProperty.call(message, "classification")) {
                    let error = $root.privoke.v1.RuntimeClassification.verify(message.classification, _depth + 1);
                    if (error)
                        return "classification." + error;
                }
                if (message.reason != null && $Object.hasOwnProperty.call(message, "reason"))
                    if (!$util.isString(message.reason))
                        return "reason: string expected";
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
                if (message.elapsedMs != null && $Object.hasOwnProperty.call(message, "elapsedMs"))
                    if (typeof message.elapsedMs !== "number")
                        return "elapsedMs: number expected";
                if (message.error != null && $Object.hasOwnProperty.call(message, "error"))
                    if (!$util.isString(message.error))
                        return "error: string expected";
                return null;
            };

            /**
             * Creates an AnalyzePromptResponse message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.AnalyzePromptResponse
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.AnalyzePromptResponse} AnalyzePromptResponse
             */
            AnalyzePromptResponse.fromObject = function (object, _depth) {
                if (object instanceof $root.privoke.v1.AnalyzePromptResponse)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".privoke.v1.AnalyzePromptResponse: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.privoke.v1.AnalyzePromptResponse();
                if (object.requestId != null)
                    if (typeof object.requestId !== "string" || object.requestId.length)
                        message.requestId = $String(object.requestId);
                if (object.action != null)
                    if (typeof object.action !== "string" || object.action.length)
                        message.action = $String(object.action);
                if (object.allowed != null)
                    if (object.allowed)
                        message.allowed = $Boolean(object.allowed);
                if (object.maskedText != null)
                    if (typeof object.maskedText !== "string" || object.maskedText.length)
                        message.maskedText = $String(object.maskedText);
                if (object.classification != null) {
                    if (!$util.isObject(object.classification))
                        throw $TypeError(".privoke.v1.AnalyzePromptResponse.classification: object expected");
                    message.classification = $root.privoke.v1.RuntimeClassification.fromObject(object.classification, _depth + 1);
                }
                if (object.reason != null)
                    if (typeof object.reason !== "string" || object.reason.length)
                        message.reason = $String(object.reason);
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
                if (object.elapsedMs != null)
                    if (!$Object.is($Number(object.elapsedMs), 0))
                        message.elapsedMs = $Number(object.elapsedMs);
                if (object.error != null)
                    if (typeof object.error !== "string" || object.error.length)
                        message.error = $String(object.error);
                return message;
            };

            /**
             * Creates a plain object from an AnalyzePromptResponse message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.AnalyzePromptResponse
             * @static
             * @param {privoke.v1.AnalyzePromptResponse} message AnalyzePromptResponse
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            AnalyzePromptResponse.toObject = function (message, options, _depth) {
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

            /**
             * Converts this AnalyzePromptResponse to JSON.
             * @function toJSON
             * @memberof privoke.v1.AnalyzePromptResponse
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            AnalyzePromptResponse.prototype.toJSON = function() {
                return AnalyzePromptResponse.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for AnalyzePromptResponse
             * @function getTypeUrl
             * @memberof privoke.v1.AnalyzePromptResponse
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            AnalyzePromptResponse.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.AnalyzePromptResponse";
            };

            return AnalyzePromptResponse;
        })();

        v1.RuntimeTrainingExample = (function() {

            /**
             * Properties of a RuntimeTrainingExample.
             * @typedef {Object} privoke.v1.RuntimeTrainingExample.$Properties
             * @property {string|null} [text] RuntimeTrainingExample text
             * @property {privoke.v1.RuntimeClassification.$Properties|null} [target] RuntimeTrainingExample target
             * @property {boolean|null} [hasTarget] RuntimeTrainingExample hasTarget
             * @property {number|null} [weight] RuntimeTrainingExample weight
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a RuntimeTrainingExample.
             * @memberof privoke.v1
             * @interface IRuntimeTrainingExample
             * @augments privoke.v1.RuntimeTrainingExample.$Properties
             * @deprecated Use privoke.v1.RuntimeTrainingExample.$Properties instead.
             */

            /**
             * Shape of a RuntimeTrainingExample.
             * @typedef {privoke.v1.RuntimeTrainingExample.$Properties} privoke.v1.RuntimeTrainingExample.$Shape
             */

            /**
             * Constructs a new RuntimeTrainingExample.
             * @memberof privoke.v1
             * @classdesc Represents a RuntimeTrainingExample.
             * @constructor
             * @param {privoke.v1.RuntimeTrainingExample.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const RuntimeTrainingExample = function (properties) {
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * RuntimeTrainingExample text.
             * @member {string} text
             * @memberof privoke.v1.RuntimeTrainingExample
             * @instance
             */
            RuntimeTrainingExample.prototype.text = "";

            /**
             * RuntimeTrainingExample target.
             * @member {privoke.v1.RuntimeClassification.$Properties|null|undefined} target
             * @memberof privoke.v1.RuntimeTrainingExample
             * @instance
             */
            RuntimeTrainingExample.prototype.target = null;

            /**
             * RuntimeTrainingExample hasTarget.
             * @member {boolean} hasTarget
             * @memberof privoke.v1.RuntimeTrainingExample
             * @instance
             */
            RuntimeTrainingExample.prototype.hasTarget = false;

            /**
             * RuntimeTrainingExample weight.
             * @member {number} weight
             * @memberof privoke.v1.RuntimeTrainingExample
             * @instance
             */
            RuntimeTrainingExample.prototype.weight = 0;

            /**
             * Creates a new RuntimeTrainingExample instance using the specified properties.
             * @function create
             * @memberof privoke.v1.RuntimeTrainingExample
             * @static
             * @param {privoke.v1.RuntimeTrainingExample.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.RuntimeTrainingExample} RuntimeTrainingExample instance
             * @type {{
             *   (properties: privoke.v1.RuntimeTrainingExample.$Shape): privoke.v1.RuntimeTrainingExample & privoke.v1.RuntimeTrainingExample.$Shape;
             *   (properties?: privoke.v1.RuntimeTrainingExample.$Properties): privoke.v1.RuntimeTrainingExample;
             * }}
             */
            RuntimeTrainingExample.create = function(properties) {
                return new RuntimeTrainingExample(properties);
            };

            /**
             * Encodes the specified RuntimeTrainingExample message. Does not implicitly {@link privoke.v1.RuntimeTrainingExample.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.RuntimeTrainingExample
             * @static
             * @param {privoke.v1.RuntimeTrainingExample.$Properties} message RuntimeTrainingExample message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeTrainingExample.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.text != null && $Object.hasOwnProperty.call(message, "text") && message.text !== "")
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.text);
                if (message.target != null && $Object.hasOwnProperty.call(message, "target"))
                    $root.privoke.v1.RuntimeClassification.encode(message.target, writer.uint32(/* id 2, wireType 2 =*/18).fork(), _depth + 1).ldelim();
                if (message.hasTarget != null && $Object.hasOwnProperty.call(message, "hasTarget") && message.hasTarget !== false)
                    writer.uint32(/* id 3, wireType 0 =*/24).bool(message.hasTarget);
                if (message.weight != null && $Object.hasOwnProperty.call(message, "weight") && !$Object.is(message.weight, 0))
                    writer.uint32(/* id 4, wireType 1 =*/33).double(message.weight);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified RuntimeTrainingExample message, length delimited. Does not implicitly {@link privoke.v1.RuntimeTrainingExample.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.RuntimeTrainingExample
             * @static
             * @param {privoke.v1.RuntimeTrainingExample.$Properties} message RuntimeTrainingExample message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeTrainingExample.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a RuntimeTrainingExample message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.RuntimeTrainingExample
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.RuntimeTrainingExample & privoke.v1.RuntimeTrainingExample.$Shape} RuntimeTrainingExample
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeTrainingExample.decode = function (reader, length, _end, _depth, _target) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $Reader.recursionLimit)
                    throw $Error("max depth exceeded");
                let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.RuntimeTrainingExample(), value;
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
                            message.target = $root.privoke.v1.RuntimeClassification.decode(reader, reader.uint32(), $undefined, _depth + 1, message.target);
                            continue;
                        }
                    case 3: {
                            if (wireType !== 0)
                                break;
                            if (value = reader.bool())
                                message.hasTarget = value;
                            else
                                delete message.hasTarget;
                            continue;
                        }
                    case 4: {
                            if (wireType !== 1)
                                break;
                            if (!$Object.is(value = reader.double(), 0))
                                message.weight = value;
                            else
                                delete message.weight;
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

            /**
             * Decodes a RuntimeTrainingExample message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.RuntimeTrainingExample
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.RuntimeTrainingExample & privoke.v1.RuntimeTrainingExample.$Shape} RuntimeTrainingExample
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeTrainingExample.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a RuntimeTrainingExample message.
             * @function verify
             * @memberof privoke.v1.RuntimeTrainingExample
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            RuntimeTrainingExample.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                if (message.text != null && $Object.hasOwnProperty.call(message, "text"))
                    if (!$util.isString(message.text))
                        return "text: string expected";
                if (message.target != null && $Object.hasOwnProperty.call(message, "target")) {
                    let error = $root.privoke.v1.RuntimeClassification.verify(message.target, _depth + 1);
                    if (error)
                        return "target." + error;
                }
                if (message.hasTarget != null && $Object.hasOwnProperty.call(message, "hasTarget"))
                    if (typeof message.hasTarget !== "boolean")
                        return "hasTarget: boolean expected";
                if (message.weight != null && $Object.hasOwnProperty.call(message, "weight"))
                    if (typeof message.weight !== "number")
                        return "weight: number expected";
                return null;
            };

            /**
             * Creates a RuntimeTrainingExample message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.RuntimeTrainingExample
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.RuntimeTrainingExample} RuntimeTrainingExample
             */
            RuntimeTrainingExample.fromObject = function (object, _depth) {
                if (object instanceof $root.privoke.v1.RuntimeTrainingExample)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".privoke.v1.RuntimeTrainingExample: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.privoke.v1.RuntimeTrainingExample();
                if (object.text != null)
                    if (typeof object.text !== "string" || object.text.length)
                        message.text = $String(object.text);
                if (object.target != null) {
                    if (!$util.isObject(object.target))
                        throw $TypeError(".privoke.v1.RuntimeTrainingExample.target: object expected");
                    message.target = $root.privoke.v1.RuntimeClassification.fromObject(object.target, _depth + 1);
                }
                if (object.hasTarget != null)
                    if (object.hasTarget)
                        message.hasTarget = $Boolean(object.hasTarget);
                if (object.weight != null)
                    if (!$Object.is($Number(object.weight), 0))
                        message.weight = $Number(object.weight);
                return message;
            };

            /**
             * Creates a plain object from a RuntimeTrainingExample message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.RuntimeTrainingExample
             * @static
             * @param {privoke.v1.RuntimeTrainingExample} message RuntimeTrainingExample
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            RuntimeTrainingExample.toObject = function (message, options, _depth) {
                if (!options)
                    options = {};
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.text = "";
                    object.target = null;
                    object.hasTarget = false;
                    object.weight = 0;
                }
                if (message.text != null && $Object.hasOwnProperty.call(message, "text"))
                    object.text = message.text;
                if (message.target != null && $Object.hasOwnProperty.call(message, "target"))
                    object.target = $root.privoke.v1.RuntimeClassification.toObject(message.target, options, _depth + 1);
                if (message.hasTarget != null && $Object.hasOwnProperty.call(message, "hasTarget"))
                    object.hasTarget = message.hasTarget;
                if (message.weight != null && $Object.hasOwnProperty.call(message, "weight"))
                    object.weight = options.json && !$isFinite(message.weight) ? $String(message.weight) : message.weight;
                return object;
            };

            /**
             * Converts this RuntimeTrainingExample to JSON.
             * @function toJSON
             * @memberof privoke.v1.RuntimeTrainingExample
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            RuntimeTrainingExample.prototype.toJSON = function() {
                return RuntimeTrainingExample.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for RuntimeTrainingExample
             * @function getTypeUrl
             * @memberof privoke.v1.RuntimeTrainingExample
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            RuntimeTrainingExample.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.RuntimeTrainingExample";
            };

            return RuntimeTrainingExample;
        })();

        v1.ComputeSemanticGradientsRequest = (function() {

            /**
             * Properties of a ComputeSemanticGradientsRequest.
             * @typedef {Object} privoke.v1.ComputeSemanticGradientsRequest.$Properties
             * @property {string|null} [requestId] ComputeSemanticGradientsRequest requestId
             * @property {string|null} [modelId] ComputeSemanticGradientsRequest modelId
             * @property {Array.<privoke.v1.RuntimeTrainingExample.$Properties>|null} [examples] ComputeSemanticGradientsRequest examples
             * @property {number|null} [learningRate] ComputeSemanticGradientsRequest learningRate
             * @property {number|null} [maxGradient] ComputeSemanticGradientsRequest maxGradient
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a ComputeSemanticGradientsRequest.
             * @memberof privoke.v1
             * @interface IComputeSemanticGradientsRequest
             * @augments privoke.v1.ComputeSemanticGradientsRequest.$Properties
             * @deprecated Use privoke.v1.ComputeSemanticGradientsRequest.$Properties instead.
             */

            /**
             * Shape of a ComputeSemanticGradientsRequest.
             * @typedef {privoke.v1.ComputeSemanticGradientsRequest.$Properties} privoke.v1.ComputeSemanticGradientsRequest.$Shape
             */

            /**
             * Constructs a new ComputeSemanticGradientsRequest.
             * @memberof privoke.v1
             * @classdesc Represents a ComputeSemanticGradientsRequest.
             * @constructor
             * @param {privoke.v1.ComputeSemanticGradientsRequest.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const ComputeSemanticGradientsRequest = function (properties) {
                this.examples = [];
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * ComputeSemanticGradientsRequest requestId.
             * @member {string} requestId
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @instance
             */
            ComputeSemanticGradientsRequest.prototype.requestId = "";

            /**
             * ComputeSemanticGradientsRequest modelId.
             * @member {string} modelId
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @instance
             */
            ComputeSemanticGradientsRequest.prototype.modelId = "";

            /**
             * ComputeSemanticGradientsRequest examples.
             * @member {Array.<privoke.v1.RuntimeTrainingExample.$Properties>} examples
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @instance
             */
            ComputeSemanticGradientsRequest.prototype.examples = $util.emptyArray;

            /**
             * ComputeSemanticGradientsRequest learningRate.
             * @member {number} learningRate
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @instance
             */
            ComputeSemanticGradientsRequest.prototype.learningRate = 0;

            /**
             * ComputeSemanticGradientsRequest maxGradient.
             * @member {number} maxGradient
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @instance
             */
            ComputeSemanticGradientsRequest.prototype.maxGradient = 0;

            /**
             * Creates a new ComputeSemanticGradientsRequest instance using the specified properties.
             * @function create
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @static
             * @param {privoke.v1.ComputeSemanticGradientsRequest.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.ComputeSemanticGradientsRequest} ComputeSemanticGradientsRequest instance
             * @type {{
             *   (properties: privoke.v1.ComputeSemanticGradientsRequest.$Shape): privoke.v1.ComputeSemanticGradientsRequest & privoke.v1.ComputeSemanticGradientsRequest.$Shape;
             *   (properties?: privoke.v1.ComputeSemanticGradientsRequest.$Properties): privoke.v1.ComputeSemanticGradientsRequest;
             * }}
             */
            ComputeSemanticGradientsRequest.create = function(properties) {
                return new ComputeSemanticGradientsRequest(properties);
            };

            /**
             * Encodes the specified ComputeSemanticGradientsRequest message. Does not implicitly {@link privoke.v1.ComputeSemanticGradientsRequest.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @static
             * @param {privoke.v1.ComputeSemanticGradientsRequest.$Properties} message ComputeSemanticGradientsRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ComputeSemanticGradientsRequest.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId") && message.requestId !== "")
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.requestId);
                if (message.modelId != null && $Object.hasOwnProperty.call(message, "modelId") && message.modelId !== "")
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.modelId);
                if (message.examples != null && message.examples.length)
                    for (let i = 0; i < message.examples.length; ++i)
                        $root.privoke.v1.RuntimeTrainingExample.encode(message.examples[i], writer.uint32(/* id 3, wireType 2 =*/26).fork(), _depth + 1).ldelim();
                if (message.learningRate != null && $Object.hasOwnProperty.call(message, "learningRate") && !$Object.is(message.learningRate, 0))
                    writer.uint32(/* id 4, wireType 1 =*/33).double(message.learningRate);
                if (message.maxGradient != null && $Object.hasOwnProperty.call(message, "maxGradient") && !$Object.is(message.maxGradient, 0))
                    writer.uint32(/* id 5, wireType 1 =*/41).double(message.maxGradient);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified ComputeSemanticGradientsRequest message, length delimited. Does not implicitly {@link privoke.v1.ComputeSemanticGradientsRequest.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @static
             * @param {privoke.v1.ComputeSemanticGradientsRequest.$Properties} message ComputeSemanticGradientsRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ComputeSemanticGradientsRequest.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a ComputeSemanticGradientsRequest message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.ComputeSemanticGradientsRequest & privoke.v1.ComputeSemanticGradientsRequest.$Shape} ComputeSemanticGradientsRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ComputeSemanticGradientsRequest.decode = function (reader, length, _end, _depth, _target) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $Reader.recursionLimit)
                    throw $Error("max depth exceeded");
                let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.ComputeSemanticGradientsRequest(), value;
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
                                message.modelId = value;
                            else
                                delete message.modelId;
                            continue;
                        }
                    case 3: {
                            if (wireType !== 2)
                                break;
                            if (!(message.examples && message.examples.length))
                                message.examples = [];
                            message.examples.push($root.privoke.v1.RuntimeTrainingExample.decode(reader, reader.uint32(), $undefined, _depth + 1));
                            continue;
                        }
                    case 4: {
                            if (wireType !== 1)
                                break;
                            if (!$Object.is(value = reader.double(), 0))
                                message.learningRate = value;
                            else
                                delete message.learningRate;
                            continue;
                        }
                    case 5: {
                            if (wireType !== 1)
                                break;
                            if (!$Object.is(value = reader.double(), 0))
                                message.maxGradient = value;
                            else
                                delete message.maxGradient;
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

            /**
             * Decodes a ComputeSemanticGradientsRequest message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.ComputeSemanticGradientsRequest & privoke.v1.ComputeSemanticGradientsRequest.$Shape} ComputeSemanticGradientsRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ComputeSemanticGradientsRequest.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ComputeSemanticGradientsRequest message.
             * @function verify
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ComputeSemanticGradientsRequest.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId"))
                    if (!$util.isString(message.requestId))
                        return "requestId: string expected";
                if (message.modelId != null && $Object.hasOwnProperty.call(message, "modelId"))
                    if (!$util.isString(message.modelId))
                        return "modelId: string expected";
                if (message.examples != null && $Object.hasOwnProperty.call(message, "examples")) {
                    if (!$Array.isArray(message.examples))
                        return "examples: array expected";
                    for (let i = 0; i < message.examples.length; ++i) {
                        let error = $root.privoke.v1.RuntimeTrainingExample.verify(message.examples[i], _depth + 1);
                        if (error)
                            return "examples." + error;
                    }
                }
                if (message.learningRate != null && $Object.hasOwnProperty.call(message, "learningRate"))
                    if (typeof message.learningRate !== "number")
                        return "learningRate: number expected";
                if (message.maxGradient != null && $Object.hasOwnProperty.call(message, "maxGradient"))
                    if (typeof message.maxGradient !== "number")
                        return "maxGradient: number expected";
                return null;
            };

            /**
             * Creates a ComputeSemanticGradientsRequest message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.ComputeSemanticGradientsRequest} ComputeSemanticGradientsRequest
             */
            ComputeSemanticGradientsRequest.fromObject = function (object, _depth) {
                if (object instanceof $root.privoke.v1.ComputeSemanticGradientsRequest)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".privoke.v1.ComputeSemanticGradientsRequest: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.privoke.v1.ComputeSemanticGradientsRequest();
                if (object.requestId != null)
                    if (typeof object.requestId !== "string" || object.requestId.length)
                        message.requestId = $String(object.requestId);
                if (object.modelId != null)
                    if (typeof object.modelId !== "string" || object.modelId.length)
                        message.modelId = $String(object.modelId);
                if (object.examples) {
                    if (!$Array.isArray(object.examples))
                        throw $TypeError(".privoke.v1.ComputeSemanticGradientsRequest.examples: array expected");
                    message.examples = $Array(object.examples.length);
                    for (let i = 0; i < object.examples.length; ++i) {
                        if (!$util.isObject(object.examples[i]))
                            throw $TypeError(".privoke.v1.ComputeSemanticGradientsRequest.examples: object expected");
                        message.examples[i] = $root.privoke.v1.RuntimeTrainingExample.fromObject(object.examples[i], _depth + 1);
                    }
                }
                if (object.learningRate != null)
                    if (!$Object.is($Number(object.learningRate), 0))
                        message.learningRate = $Number(object.learningRate);
                if (object.maxGradient != null)
                    if (!$Object.is($Number(object.maxGradient), 0))
                        message.maxGradient = $Number(object.maxGradient);
                return message;
            };

            /**
             * Creates a plain object from a ComputeSemanticGradientsRequest message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @static
             * @param {privoke.v1.ComputeSemanticGradientsRequest} message ComputeSemanticGradientsRequest
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ComputeSemanticGradientsRequest.toObject = function (message, options, _depth) {
                if (!options)
                    options = {};
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let object = {};
                if (options.arrays || options.defaults)
                    object.examples = [];
                if (options.defaults) {
                    object.requestId = "";
                    object.modelId = "";
                    object.learningRate = 0;
                    object.maxGradient = 0;
                }
                if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId"))
                    object.requestId = message.requestId;
                if (message.modelId != null && $Object.hasOwnProperty.call(message, "modelId"))
                    object.modelId = message.modelId;
                if (message.examples && message.examples.length) {
                    object.examples = $Array(message.examples.length);
                    for (let j = 0; j < message.examples.length; ++j)
                        object.examples[j] = $root.privoke.v1.RuntimeTrainingExample.toObject(message.examples[j], options, _depth + 1);
                }
                if (message.learningRate != null && $Object.hasOwnProperty.call(message, "learningRate"))
                    object.learningRate = options.json && !$isFinite(message.learningRate) ? $String(message.learningRate) : message.learningRate;
                if (message.maxGradient != null && $Object.hasOwnProperty.call(message, "maxGradient"))
                    object.maxGradient = options.json && !$isFinite(message.maxGradient) ? $String(message.maxGradient) : message.maxGradient;
                return object;
            };

            /**
             * Converts this ComputeSemanticGradientsRequest to JSON.
             * @function toJSON
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ComputeSemanticGradientsRequest.prototype.toJSON = function() {
                return ComputeSemanticGradientsRequest.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for ComputeSemanticGradientsRequest
             * @function getTypeUrl
             * @memberof privoke.v1.ComputeSemanticGradientsRequest
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            ComputeSemanticGradientsRequest.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.ComputeSemanticGradientsRequest";
            };

            return ComputeSemanticGradientsRequest;
        })();

        v1.RuntimeParameterDelta = (function() {

            /**
             * Properties of a RuntimeParameterDelta.
             * @typedef {Object} privoke.v1.RuntimeParameterDelta.$Properties
             * @property {string|null} [name] RuntimeParameterDelta name
             * @property {Array.<number>|null} [values] RuntimeParameterDelta values
             * @property {Array.<number>|null} [shape] RuntimeParameterDelta shape
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a RuntimeParameterDelta.
             * @memberof privoke.v1
             * @interface IRuntimeParameterDelta
             * @augments privoke.v1.RuntimeParameterDelta.$Properties
             * @deprecated Use privoke.v1.RuntimeParameterDelta.$Properties instead.
             */

            /**
             * Shape of a RuntimeParameterDelta.
             * @typedef {privoke.v1.RuntimeParameterDelta.$Properties} privoke.v1.RuntimeParameterDelta.$Shape
             */

            /**
             * Constructs a new RuntimeParameterDelta.
             * @memberof privoke.v1
             * @classdesc Represents a RuntimeParameterDelta.
             * @constructor
             * @param {privoke.v1.RuntimeParameterDelta.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const RuntimeParameterDelta = function (properties) {
                this.values = [];
                this.shape = [];
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * RuntimeParameterDelta name.
             * @member {string} name
             * @memberof privoke.v1.RuntimeParameterDelta
             * @instance
             */
            RuntimeParameterDelta.prototype.name = "";

            /**
             * RuntimeParameterDelta values.
             * @member {Array.<number>} values
             * @memberof privoke.v1.RuntimeParameterDelta
             * @instance
             */
            RuntimeParameterDelta.prototype.values = $util.emptyArray;

            /**
             * RuntimeParameterDelta shape.
             * @member {Array.<number>} shape
             * @memberof privoke.v1.RuntimeParameterDelta
             * @instance
             */
            RuntimeParameterDelta.prototype.shape = $util.emptyArray;

            /**
             * Creates a new RuntimeParameterDelta instance using the specified properties.
             * @function create
             * @memberof privoke.v1.RuntimeParameterDelta
             * @static
             * @param {privoke.v1.RuntimeParameterDelta.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.RuntimeParameterDelta} RuntimeParameterDelta instance
             * @type {{
             *   (properties: privoke.v1.RuntimeParameterDelta.$Shape): privoke.v1.RuntimeParameterDelta & privoke.v1.RuntimeParameterDelta.$Shape;
             *   (properties?: privoke.v1.RuntimeParameterDelta.$Properties): privoke.v1.RuntimeParameterDelta;
             * }}
             */
            RuntimeParameterDelta.create = function(properties) {
                return new RuntimeParameterDelta(properties);
            };

            /**
             * Encodes the specified RuntimeParameterDelta message. Does not implicitly {@link privoke.v1.RuntimeParameterDelta.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.RuntimeParameterDelta
             * @static
             * @param {privoke.v1.RuntimeParameterDelta.$Properties} message RuntimeParameterDelta message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeParameterDelta.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.name != null && $Object.hasOwnProperty.call(message, "name") && message.name !== "")
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.name);
                if (message.values != null && message.values.length)
                    writer.uint32(/* id 2, wireType 2 =*/18).floats(message.values);
                if (message.shape != null && message.shape.length)
                    writer.uint32(/* id 3, wireType 2 =*/26).uint32s(message.shape);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified RuntimeParameterDelta message, length delimited. Does not implicitly {@link privoke.v1.RuntimeParameterDelta.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.RuntimeParameterDelta
             * @static
             * @param {privoke.v1.RuntimeParameterDelta.$Properties} message RuntimeParameterDelta message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            RuntimeParameterDelta.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a RuntimeParameterDelta message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.RuntimeParameterDelta
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.RuntimeParameterDelta & privoke.v1.RuntimeParameterDelta.$Shape} RuntimeParameterDelta
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeParameterDelta.decode = function (reader, length, _end, _depth, _target) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $Reader.recursionLimit)
                    throw $Error("max depth exceeded");
                let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.RuntimeParameterDelta(), value;
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
                                message.name = value;
                            else
                                delete message.name;
                            continue;
                        }
                    case 2: {
                            if (wireType === 2) {
                                if (!(message.values && message.values.length))
                                    message.values = [];
                                reader.floats(message.values);
                                continue;
                            }
                            if (wireType !== 5)
                                break;
                            if (!(message.values && message.values.length))
                                message.values = [];
                            message.values.push(reader.float());
                            continue;
                        }
                    case 3: {
                            if (wireType === 2) {
                                if (!(message.shape && message.shape.length))
                                    message.shape = [];
                                reader.uint32s(message.shape);
                                continue;
                            }
                            if (wireType !== 0)
                                break;
                            if (!(message.shape && message.shape.length))
                                message.shape = [];
                            message.shape.push(reader.uint32());
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

            /**
             * Decodes a RuntimeParameterDelta message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.RuntimeParameterDelta
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.RuntimeParameterDelta & privoke.v1.RuntimeParameterDelta.$Shape} RuntimeParameterDelta
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            RuntimeParameterDelta.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a RuntimeParameterDelta message.
             * @function verify
             * @memberof privoke.v1.RuntimeParameterDelta
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            RuntimeParameterDelta.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                if (message.name != null && $Object.hasOwnProperty.call(message, "name"))
                    if (!$util.isString(message.name))
                        return "name: string expected";
                if (message.values != null && $Object.hasOwnProperty.call(message, "values")) {
                    if (!$Array.isArray(message.values))
                        return "values: array expected";
                    for (let i = 0; i < message.values.length; ++i)
                        if (typeof message.values[i] !== "number")
                            return "values: number[] expected";
                }
                if (message.shape != null && $Object.hasOwnProperty.call(message, "shape")) {
                    if (!$Array.isArray(message.shape))
                        return "shape: array expected";
                    for (let i = 0; i < message.shape.length; ++i)
                        if (!$util.isInteger(message.shape[i]))
                            return "shape: integer[] expected";
                }
                return null;
            };

            /**
             * Creates a RuntimeParameterDelta message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.RuntimeParameterDelta
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.RuntimeParameterDelta} RuntimeParameterDelta
             */
            RuntimeParameterDelta.fromObject = function (object, _depth) {
                if (object instanceof $root.privoke.v1.RuntimeParameterDelta)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".privoke.v1.RuntimeParameterDelta: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.privoke.v1.RuntimeParameterDelta();
                if (object.name != null)
                    if (typeof object.name !== "string" || object.name.length)
                        message.name = $String(object.name);
                if (object.values) {
                    if (!$Array.isArray(object.values))
                        throw $TypeError(".privoke.v1.RuntimeParameterDelta.values: array expected");
                    message.values = $Array(object.values.length);
                    for (let i = 0; i < object.values.length; ++i)
                        message.values[i] = $Number(object.values[i]);
                }
                if (object.shape) {
                    if (!$Array.isArray(object.shape))
                        throw $TypeError(".privoke.v1.RuntimeParameterDelta.shape: array expected");
                    message.shape = $Array(object.shape.length);
                    for (let i = 0; i < object.shape.length; ++i)
                        message.shape[i] = object.shape[i] >>> 0;
                }
                return message;
            };

            /**
             * Creates a plain object from a RuntimeParameterDelta message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.RuntimeParameterDelta
             * @static
             * @param {privoke.v1.RuntimeParameterDelta} message RuntimeParameterDelta
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            RuntimeParameterDelta.toObject = function (message, options, _depth) {
                if (!options)
                    options = {};
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let object = {};
                if (options.arrays || options.defaults) {
                    object.values = [];
                    object.shape = [];
                }
                if (options.defaults)
                    object.name = "";
                if (message.name != null && $Object.hasOwnProperty.call(message, "name"))
                    object.name = message.name;
                if (message.values && message.values.length) {
                    object.values = $Array(message.values.length);
                    for (let j = 0; j < message.values.length; ++j)
                        object.values[j] = options.json && !$isFinite(message.values[j]) ? $String(message.values[j]) : message.values[j];
                }
                if (message.shape && message.shape.length) {
                    object.shape = $Array(message.shape.length);
                    for (let j = 0; j < message.shape.length; ++j)
                        object.shape[j] = message.shape[j];
                }
                return object;
            };

            /**
             * Converts this RuntimeParameterDelta to JSON.
             * @function toJSON
             * @memberof privoke.v1.RuntimeParameterDelta
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            RuntimeParameterDelta.prototype.toJSON = function() {
                return RuntimeParameterDelta.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for RuntimeParameterDelta
             * @function getTypeUrl
             * @memberof privoke.v1.RuntimeParameterDelta
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            RuntimeParameterDelta.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.RuntimeParameterDelta";
            };

            return RuntimeParameterDelta;
        })();

        v1.ComputeSemanticGradientsResponse = (function() {

            /**
             * Properties of a ComputeSemanticGradientsResponse.
             * @typedef {Object} privoke.v1.ComputeSemanticGradientsResponse.$Properties
             * @property {string|null} [requestId] ComputeSemanticGradientsResponse requestId
             * @property {string|null} [modelId] ComputeSemanticGradientsResponse modelId
             * @property {string|null} [baseVersion] ComputeSemanticGradientsResponse baseVersion
             * @property {Array.<privoke.v1.RuntimeParameterDelta.$Properties>|null} [gradients] ComputeSemanticGradientsResponse gradients
             * @property {Object.<string,number>|null} [metrics] ComputeSemanticGradientsResponse metrics
             * @property {Object.<string,string>|null} [metadata] ComputeSemanticGradientsResponse metadata
             * @property {string|null} [error] ComputeSemanticGradientsResponse error
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a ComputeSemanticGradientsResponse.
             * @memberof privoke.v1
             * @interface IComputeSemanticGradientsResponse
             * @augments privoke.v1.ComputeSemanticGradientsResponse.$Properties
             * @deprecated Use privoke.v1.ComputeSemanticGradientsResponse.$Properties instead.
             */

            /**
             * Shape of a ComputeSemanticGradientsResponse.
             * @typedef {privoke.v1.ComputeSemanticGradientsResponse.$Properties} privoke.v1.ComputeSemanticGradientsResponse.$Shape
             */

            /**
             * Constructs a new ComputeSemanticGradientsResponse.
             * @memberof privoke.v1
             * @classdesc Represents a ComputeSemanticGradientsResponse.
             * @constructor
             * @param {privoke.v1.ComputeSemanticGradientsResponse.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const ComputeSemanticGradientsResponse = function (properties) {
                this.gradients = [];
                this.metrics = {};
                this.metadata = {};
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * ComputeSemanticGradientsResponse requestId.
             * @member {string} requestId
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @instance
             */
            ComputeSemanticGradientsResponse.prototype.requestId = "";

            /**
             * ComputeSemanticGradientsResponse modelId.
             * @member {string} modelId
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @instance
             */
            ComputeSemanticGradientsResponse.prototype.modelId = "";

            /**
             * ComputeSemanticGradientsResponse baseVersion.
             * @member {string} baseVersion
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @instance
             */
            ComputeSemanticGradientsResponse.prototype.baseVersion = "";

            /**
             * ComputeSemanticGradientsResponse gradients.
             * @member {Array.<privoke.v1.RuntimeParameterDelta.$Properties>} gradients
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @instance
             */
            ComputeSemanticGradientsResponse.prototype.gradients = $util.emptyArray;

            /**
             * ComputeSemanticGradientsResponse metrics.
             * @member {Object.<string,number>} metrics
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @instance
             */
            ComputeSemanticGradientsResponse.prototype.metrics = $util.emptyObject;

            /**
             * ComputeSemanticGradientsResponse metadata.
             * @member {Object.<string,string>} metadata
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @instance
             */
            ComputeSemanticGradientsResponse.prototype.metadata = $util.emptyObject;

            /**
             * ComputeSemanticGradientsResponse error.
             * @member {string} error
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @instance
             */
            ComputeSemanticGradientsResponse.prototype.error = "";

            /**
             * Creates a new ComputeSemanticGradientsResponse instance using the specified properties.
             * @function create
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @static
             * @param {privoke.v1.ComputeSemanticGradientsResponse.$Properties=} [properties] Properties to set
             * @returns {privoke.v1.ComputeSemanticGradientsResponse} ComputeSemanticGradientsResponse instance
             * @type {{
             *   (properties: privoke.v1.ComputeSemanticGradientsResponse.$Shape): privoke.v1.ComputeSemanticGradientsResponse & privoke.v1.ComputeSemanticGradientsResponse.$Shape;
             *   (properties?: privoke.v1.ComputeSemanticGradientsResponse.$Properties): privoke.v1.ComputeSemanticGradientsResponse;
             * }}
             */
            ComputeSemanticGradientsResponse.create = function(properties) {
                return new ComputeSemanticGradientsResponse(properties);
            };

            /**
             * Encodes the specified ComputeSemanticGradientsResponse message. Does not implicitly {@link privoke.v1.ComputeSemanticGradientsResponse.verify|verify} messages.
             * @function encode
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @static
             * @param {privoke.v1.ComputeSemanticGradientsResponse.$Properties} message ComputeSemanticGradientsResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ComputeSemanticGradientsResponse.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId") && message.requestId !== "")
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.requestId);
                if (message.modelId != null && $Object.hasOwnProperty.call(message, "modelId") && message.modelId !== "")
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.modelId);
                if (message.baseVersion != null && $Object.hasOwnProperty.call(message, "baseVersion") && message.baseVersion !== "")
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.baseVersion);
                if (message.gradients != null && message.gradients.length)
                    for (let i = 0; i < message.gradients.length; ++i)
                        $root.privoke.v1.RuntimeParameterDelta.encode(message.gradients[i], writer.uint32(/* id 4, wireType 2 =*/34).fork(), _depth + 1).ldelim();
                if (message.metrics != null && $Object.hasOwnProperty.call(message, "metrics"))
                    for (let keys = $Object.keys(message.metrics), i = 0; i < keys.length; ++i)
                        writer.uint32(/* id 5, wireType 2 =*/42).fork().uint32(/* id 1, wireType 2 =*/10).string(keys[i]).uint32(/* id 2, wireType 1 =*/17).double(message.metrics[keys[i]]).ldelim();
                if (message.metadata != null && $Object.hasOwnProperty.call(message, "metadata"))
                    for (let keys = $Object.keys(message.metadata), i = 0; i < keys.length; ++i)
                        writer.uint32(/* id 6, wireType 2 =*/50).fork().uint32(/* id 1, wireType 2 =*/10).string(keys[i]).uint32(/* id 2, wireType 2 =*/18).string(message.metadata[keys[i]]).ldelim();
                if (message.error != null && $Object.hasOwnProperty.call(message, "error") && message.error !== "")
                    writer.uint32(/* id 7, wireType 2 =*/58).string(message.error);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Encodes the specified ComputeSemanticGradientsResponse message, length delimited. Does not implicitly {@link privoke.v1.ComputeSemanticGradientsResponse.verify|verify} messages.
             * @function encodeDelimited
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @static
             * @param {privoke.v1.ComputeSemanticGradientsResponse.$Properties} message ComputeSemanticGradientsResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ComputeSemanticGradientsResponse.encodeDelimited = function(message, writer) {
                return this.encode(message, (writer || $Writer.create()).fork()).ldelim();
            };

            /**
             * Decodes a ComputeSemanticGradientsResponse message from the specified reader or buffer.
             * @function decode
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {privoke.v1.ComputeSemanticGradientsResponse & privoke.v1.ComputeSemanticGradientsResponse.$Shape} ComputeSemanticGradientsResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ComputeSemanticGradientsResponse.decode = function (reader, length, _end, _depth, _target) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $Reader.recursionLimit)
                    throw $Error("max depth exceeded");
                let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.privoke.v1.ComputeSemanticGradientsResponse(), key, value;
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
                                message.modelId = value;
                            else
                                delete message.modelId;
                            continue;
                        }
                    case 3: {
                            if (wireType !== 2)
                                break;
                            if ((value = reader.stringVerify()).length)
                                message.baseVersion = value;
                            else
                                delete message.baseVersion;
                            continue;
                        }
                    case 4: {
                            if (wireType !== 2)
                                break;
                            if (!(message.gradients && message.gradients.length))
                                message.gradients = [];
                            message.gradients.push($root.privoke.v1.RuntimeParameterDelta.decode(reader, reader.uint32(), $undefined, _depth + 1));
                            continue;
                        }
                    case 5: {
                            if (wireType !== 2)
                                break;
                            if (message.metrics === $util.emptyObject)
                                message.metrics = {};
                            let end2 = reader.uint32() + reader.pos;
                            key = "";
                            value = 0;
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
                                    if (wireType !== 1)
                                        break;
                                    value = reader.double();
                                    continue;
                                }
                                reader.skipType(wireType, _depth, tag2);
                            }
                            if (key === "__proto__")
                                $util.makeProp(message.metrics, key);
                            message.metrics[key] = value;
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

            /**
             * Decodes a ComputeSemanticGradientsResponse message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {privoke.v1.ComputeSemanticGradientsResponse & privoke.v1.ComputeSemanticGradientsResponse.$Shape} ComputeSemanticGradientsResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ComputeSemanticGradientsResponse.decodeDelimited = function(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ComputeSemanticGradientsResponse message.
             * @function verify
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ComputeSemanticGradientsResponse.verify = function (message, _depth) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    return "max depth exceeded";
                if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId"))
                    if (!$util.isString(message.requestId))
                        return "requestId: string expected";
                if (message.modelId != null && $Object.hasOwnProperty.call(message, "modelId"))
                    if (!$util.isString(message.modelId))
                        return "modelId: string expected";
                if (message.baseVersion != null && $Object.hasOwnProperty.call(message, "baseVersion"))
                    if (!$util.isString(message.baseVersion))
                        return "baseVersion: string expected";
                if (message.gradients != null && $Object.hasOwnProperty.call(message, "gradients")) {
                    if (!$Array.isArray(message.gradients))
                        return "gradients: array expected";
                    for (let i = 0; i < message.gradients.length; ++i) {
                        let error = $root.privoke.v1.RuntimeParameterDelta.verify(message.gradients[i], _depth + 1);
                        if (error)
                            return "gradients." + error;
                    }
                }
                if (message.metrics != null && $Object.hasOwnProperty.call(message, "metrics")) {
                    if (!$util.isObject(message.metrics))
                        return "metrics: object expected";
                    let key = $Object.keys(message.metrics);
                    for (let i = 0; i < key.length; ++i)
                        if (typeof message.metrics[key[i]] !== "number")
                            return "metrics: number{k:string} expected";
                }
                if (message.metadata != null && $Object.hasOwnProperty.call(message, "metadata")) {
                    if (!$util.isObject(message.metadata))
                        return "metadata: object expected";
                    let key = $Object.keys(message.metadata);
                    for (let i = 0; i < key.length; ++i)
                        if (!$util.isString(message.metadata[key[i]]))
                            return "metadata: string{k:string} expected";
                }
                if (message.error != null && $Object.hasOwnProperty.call(message, "error"))
                    if (!$util.isString(message.error))
                        return "error: string expected";
                return null;
            };

            /**
             * Creates a ComputeSemanticGradientsResponse message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {privoke.v1.ComputeSemanticGradientsResponse} ComputeSemanticGradientsResponse
             */
            ComputeSemanticGradientsResponse.fromObject = function (object, _depth) {
                if (object instanceof $root.privoke.v1.ComputeSemanticGradientsResponse)
                    return object;
                if (!$util.isObject(object))
                    throw $TypeError(".privoke.v1.ComputeSemanticGradientsResponse: object expected");
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let message = new $root.privoke.v1.ComputeSemanticGradientsResponse();
                if (object.requestId != null)
                    if (typeof object.requestId !== "string" || object.requestId.length)
                        message.requestId = $String(object.requestId);
                if (object.modelId != null)
                    if (typeof object.modelId !== "string" || object.modelId.length)
                        message.modelId = $String(object.modelId);
                if (object.baseVersion != null)
                    if (typeof object.baseVersion !== "string" || object.baseVersion.length)
                        message.baseVersion = $String(object.baseVersion);
                if (object.gradients) {
                    if (!$Array.isArray(object.gradients))
                        throw $TypeError(".privoke.v1.ComputeSemanticGradientsResponse.gradients: array expected");
                    message.gradients = $Array(object.gradients.length);
                    for (let i = 0; i < object.gradients.length; ++i) {
                        if (!$util.isObject(object.gradients[i]))
                            throw $TypeError(".privoke.v1.ComputeSemanticGradientsResponse.gradients: object expected");
                        message.gradients[i] = $root.privoke.v1.RuntimeParameterDelta.fromObject(object.gradients[i], _depth + 1);
                    }
                }
                if (object.metrics) {
                    if (!$util.isObject(object.metrics))
                        throw $TypeError(".privoke.v1.ComputeSemanticGradientsResponse.metrics: object expected");
                    message.metrics = {};
                    for (let keys = $Object.keys(object.metrics), i = 0; i < keys.length; ++i) {
                        if (keys[i] === "__proto__")
                            $util.makeProp(message.metrics, keys[i]);
                        message.metrics[keys[i]] = $Number(object.metrics[keys[i]]);
                    }
                }
                if (object.metadata) {
                    if (!$util.isObject(object.metadata))
                        throw $TypeError(".privoke.v1.ComputeSemanticGradientsResponse.metadata: object expected");
                    message.metadata = {};
                    for (let keys = $Object.keys(object.metadata), i = 0; i < keys.length; ++i) {
                        if (keys[i] === "__proto__")
                            $util.makeProp(message.metadata, keys[i]);
                        message.metadata[keys[i]] = $String(object.metadata[keys[i]]);
                    }
                }
                if (object.error != null)
                    if (typeof object.error !== "string" || object.error.length)
                        message.error = $String(object.error);
                return message;
            };

            /**
             * Creates a plain object from a ComputeSemanticGradientsResponse message. Also converts values to other types if specified.
             * @function toObject
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @static
             * @param {privoke.v1.ComputeSemanticGradientsResponse} message ComputeSemanticGradientsResponse
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ComputeSemanticGradientsResponse.toObject = function (message, options, _depth) {
                if (!options)
                    options = {};
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                let object = {};
                if (options.arrays || options.defaults)
                    object.gradients = [];
                if (options.objects || options.defaults) {
                    object.metrics = {};
                    object.metadata = {};
                }
                if (options.defaults) {
                    object.requestId = "";
                    object.modelId = "";
                    object.baseVersion = "";
                    object.error = "";
                }
                if (message.requestId != null && $Object.hasOwnProperty.call(message, "requestId"))
                    object.requestId = message.requestId;
                if (message.modelId != null && $Object.hasOwnProperty.call(message, "modelId"))
                    object.modelId = message.modelId;
                if (message.baseVersion != null && $Object.hasOwnProperty.call(message, "baseVersion"))
                    object.baseVersion = message.baseVersion;
                if (message.gradients && message.gradients.length) {
                    object.gradients = $Array(message.gradients.length);
                    for (let j = 0; j < message.gradients.length; ++j)
                        object.gradients[j] = $root.privoke.v1.RuntimeParameterDelta.toObject(message.gradients[j], options, _depth + 1);
                }
                let keys2;
                if (message.metrics && (keys2 = $Object.keys(message.metrics)).length) {
                    object.metrics = {};
                    for (let j = 0; j < keys2.length; ++j) {
                        if (keys2[j] === "__proto__")
                            $util.makeProp(object.metrics, keys2[j]);
                        object.metrics[keys2[j]] = options.json && !$isFinite(message.metrics[keys2[j]]) ? $String(message.metrics[keys2[j]]) : message.metrics[keys2[j]];
                    }
                }
                if (message.metadata && (keys2 = $Object.keys(message.metadata)).length) {
                    object.metadata = {};
                    for (let j = 0; j < keys2.length; ++j) {
                        if (keys2[j] === "__proto__")
                            $util.makeProp(object.metadata, keys2[j]);
                        object.metadata[keys2[j]] = message.metadata[keys2[j]];
                    }
                }
                if (message.error != null && $Object.hasOwnProperty.call(message, "error"))
                    object.error = message.error;
                return object;
            };

            /**
             * Converts this ComputeSemanticGradientsResponse to JSON.
             * @function toJSON
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ComputeSemanticGradientsResponse.prototype.toJSON = function() {
                return ComputeSemanticGradientsResponse.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the type url for ComputeSemanticGradientsResponse
             * @function getTypeUrl
             * @memberof privoke.v1.ComputeSemanticGradientsResponse
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            ComputeSemanticGradientsResponse.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/privoke.v1.ComputeSemanticGradientsResponse";
            };

            return ComputeSemanticGradientsResponse;
        })();

        v1.PrivokeRuntimeService = (function() {

            /**
             * Constructs a new PrivokeRuntimeService service.
             * @memberof privoke.v1
             * @classdesc Represents a PrivokeRuntimeService
             * @extends $protobuf.rpc.Service
             * @constructor
             * @param {$protobuf.RPCImpl} rpcImpl RPC implementation
             * @param {boolean} [requestDelimited=false] Whether requests are length-delimited
             * @param {boolean} [responseDelimited=false] Whether responses are length-delimited
             */
            const PrivokeRuntimeService = function(rpcImpl, requestDelimited, responseDelimited) {
                $protobuf.rpc.Service.call(this, rpcImpl, requestDelimited, responseDelimited);
            };

            $Object.defineProperty(PrivokeRuntimeService.prototype = $Object.create($protobuf.rpc.Service.prototype), "constructor", { value: PrivokeRuntimeService, writable: true, enumerable: false, configurable: true });

            /**
             * Creates new PrivokeRuntimeService service using the specified rpc implementation.
             * @function create
             * @memberof privoke.v1.PrivokeRuntimeService
             * @static
             * @param {$protobuf.RPCImpl} rpcImpl RPC implementation
             * @param {boolean} [requestDelimited=false] Whether requests are length-delimited
             * @param {boolean} [responseDelimited=false] Whether responses are length-delimited
             * @returns {PrivokeRuntimeService} RPC service. Useful where requests and/or responses are streamed.
             */
            PrivokeRuntimeService.create = function(rpcImpl, requestDelimited, responseDelimited) {
                return new this(rpcImpl, requestDelimited, responseDelimited);
            };

            /**
             * Callback as used by {@link privoke.v1.PrivokeRuntimeService#analyzePrompt}.
             * @memberof privoke.v1.PrivokeRuntimeService
             * @typedef AnalyzePromptCallback
             * @type {function}
             * @param {Error|null} error Error, if any
             * @param {privoke.v1.AnalyzePromptResponse} [response] AnalyzePromptResponse
             */

            /**
             * Calls AnalyzePrompt.
             * @memberof privoke.v1.PrivokeRuntimeService
             * @typedef AnalyzePrompt
             * @type {{
             *   (request: privoke.v1.IAnalyzePromptRequest, callback: privoke.v1.PrivokeRuntimeService.AnalyzePromptCallback): void;
             *   (request: privoke.v1.IAnalyzePromptRequest): Promise<privoke.v1.AnalyzePromptResponse>;
             *   readonly name: "AnalyzePrompt";
             *   readonly path: "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt";
             *   readonly requestType: "AnalyzePromptRequest";
             *   readonly responseType: "AnalyzePromptResponse";
             *   readonly requestStream: undefined;
             *   readonly responseStream: undefined;
             * }}
             */

            /**
             * Calls AnalyzePrompt.
             * @name privoke.v1.PrivokeRuntimeService#analyzePrompt
             * @type {privoke.v1.PrivokeRuntimeService.AnalyzePrompt}
             */
            $Object.defineProperties(PrivokeRuntimeService.prototype.analyzePrompt = function(request, callback) {
                return $protobuf.rpc.Service.prototype.rpcCall.call(this, PrivokeRuntimeService.prototype.analyzePrompt, $root.privoke.v1.AnalyzePromptRequest, $root.privoke.v1.AnalyzePromptResponse, request, callback);
            }, {
                name: { value: "AnalyzePrompt" },
                path: { value: "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt" },
                requestType: { value: "AnalyzePromptRequest" },
                responseType: { value: "AnalyzePromptResponse" },
                requestStream: { value: $undefined },
                responseStream: { value: $undefined }
            });

            /**
             * Callback as used by {@link privoke.v1.PrivokeRuntimeService#computeSemanticGradients}.
             * @memberof privoke.v1.PrivokeRuntimeService
             * @typedef ComputeSemanticGradientsCallback
             * @type {function}
             * @param {Error|null} error Error, if any
             * @param {privoke.v1.ComputeSemanticGradientsResponse} [response] ComputeSemanticGradientsResponse
             */

            /**
             * Calls ComputeSemanticGradients.
             * @memberof privoke.v1.PrivokeRuntimeService
             * @typedef ComputeSemanticGradients
             * @type {{
             *   (request: privoke.v1.IComputeSemanticGradientsRequest, callback: privoke.v1.PrivokeRuntimeService.ComputeSemanticGradientsCallback): void;
             *   (request: privoke.v1.IComputeSemanticGradientsRequest): Promise<privoke.v1.ComputeSemanticGradientsResponse>;
             *   readonly name: "ComputeSemanticGradients";
             *   readonly path: "/privoke.v1.PrivokeRuntimeService/ComputeSemanticGradients";
             *   readonly requestType: "ComputeSemanticGradientsRequest";
             *   readonly responseType: "ComputeSemanticGradientsResponse";
             *   readonly requestStream: undefined;
             *   readonly responseStream: undefined;
             * }}
             */

            /**
             * Calls ComputeSemanticGradients.
             * @name privoke.v1.PrivokeRuntimeService#computeSemanticGradients
             * @type {privoke.v1.PrivokeRuntimeService.ComputeSemanticGradients}
             */
            $Object.defineProperties(PrivokeRuntimeService.prototype.computeSemanticGradients = function(request, callback) {
                return $protobuf.rpc.Service.prototype.rpcCall.call(this, PrivokeRuntimeService.prototype.computeSemanticGradients, $root.privoke.v1.ComputeSemanticGradientsRequest, $root.privoke.v1.ComputeSemanticGradientsResponse, request, callback);
            }, {
                name: { value: "ComputeSemanticGradients" },
                path: { value: "/privoke.v1.PrivokeRuntimeService/ComputeSemanticGradients" },
                requestType: { value: "ComputeSemanticGradientsRequest" },
                responseType: { value: "ComputeSemanticGradientsResponse" },
                requestStream: { value: $undefined },
                responseStream: { value: $undefined }
            });

            /**
             * Callback as used by {@link privoke.v1.PrivokeRuntimeService#health}.
             * @memberof privoke.v1.PrivokeRuntimeService
             * @typedef HealthCallback
             * @type {function}
             * @param {Error|null} error Error, if any
             * @param {privoke.v1.RuntimeHealthResponse} [response] RuntimeHealthResponse
             */

            /**
             * Calls Health.
             * @memberof privoke.v1.PrivokeRuntimeService
             * @typedef Health
             * @type {{
             *   (request: privoke.v1.IRuntimeHealthRequest, callback: privoke.v1.PrivokeRuntimeService.HealthCallback): void;
             *   (request: privoke.v1.IRuntimeHealthRequest): Promise<privoke.v1.RuntimeHealthResponse>;
             *   readonly name: "Health";
             *   readonly path: "/privoke.v1.PrivokeRuntimeService/Health";
             *   readonly requestType: "RuntimeHealthRequest";
             *   readonly responseType: "RuntimeHealthResponse";
             *   readonly requestStream: undefined;
             *   readonly responseStream: undefined;
             * }}
             */

            /**
             * Calls Health.
             * @name privoke.v1.PrivokeRuntimeService#health
             * @type {privoke.v1.PrivokeRuntimeService.Health}
             */
            $Object.defineProperties(PrivokeRuntimeService.prototype.health = function(request, callback) {
                return $protobuf.rpc.Service.prototype.rpcCall.call(this, PrivokeRuntimeService.prototype.health, $root.privoke.v1.RuntimeHealthRequest, $root.privoke.v1.RuntimeHealthResponse, request, callback);
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

            /**
             * Constructs a new PrivokeRuntimeControlService service.
             * @memberof privoke.v1
             * @classdesc Represents a PrivokeRuntimeControlService
             * @extends $protobuf.rpc.Service
             * @constructor
             * @param {$protobuf.RPCImpl} rpcImpl RPC implementation
             * @param {boolean} [requestDelimited=false] Whether requests are length-delimited
             * @param {boolean} [responseDelimited=false] Whether responses are length-delimited
             */
            const PrivokeRuntimeControlService = function(rpcImpl, requestDelimited, responseDelimited) {
                $protobuf.rpc.Service.call(this, rpcImpl, requestDelimited, responseDelimited);
            };

            $Object.defineProperty(PrivokeRuntimeControlService.prototype = $Object.create($protobuf.rpc.Service.prototype), "constructor", { value: PrivokeRuntimeControlService, writable: true, enumerable: false, configurable: true });

            /**
             * Creates new PrivokeRuntimeControlService service using the specified rpc implementation.
             * @function create
             * @memberof privoke.v1.PrivokeRuntimeControlService
             * @static
             * @param {$protobuf.RPCImpl} rpcImpl RPC implementation
             * @param {boolean} [requestDelimited=false] Whether requests are length-delimited
             * @param {boolean} [responseDelimited=false] Whether responses are length-delimited
             * @returns {PrivokeRuntimeControlService} RPC service. Useful where requests and/or responses are streamed.
             */
            PrivokeRuntimeControlService.create = function(rpcImpl, requestDelimited, responseDelimited) {
                return new this(rpcImpl, requestDelimited, responseDelimited);
            };

            /**
             * Callback as used by {@link privoke.v1.PrivokeRuntimeControlService#setRuntimeEnabled}.
             * @memberof privoke.v1.PrivokeRuntimeControlService
             * @typedef SetRuntimeEnabledCallback
             * @type {function}
             * @param {Error|null} error Error, if any
             * @param {privoke.v1.RuntimeControlStatus} [response] RuntimeControlStatus
             */

            /**
             * Calls SetRuntimeEnabled.
             * @memberof privoke.v1.PrivokeRuntimeControlService
             * @typedef SetRuntimeEnabled
             * @type {{
             *   (request: privoke.v1.ISetRuntimeEnabledRequest, callback: privoke.v1.PrivokeRuntimeControlService.SetRuntimeEnabledCallback): void;
             *   (request: privoke.v1.ISetRuntimeEnabledRequest): Promise<privoke.v1.RuntimeControlStatus>;
             *   readonly name: "SetRuntimeEnabled";
             *   readonly path: "/privoke.v1.PrivokeRuntimeControlService/SetRuntimeEnabled";
             *   readonly requestType: "SetRuntimeEnabledRequest";
             *   readonly responseType: "RuntimeControlStatus";
             *   readonly requestStream: undefined;
             *   readonly responseStream: undefined;
             * }}
             */

            /**
             * Calls SetRuntimeEnabled.
             * @name privoke.v1.PrivokeRuntimeControlService#setRuntimeEnabled
             * @type {privoke.v1.PrivokeRuntimeControlService.SetRuntimeEnabled}
             */
            $Object.defineProperties(PrivokeRuntimeControlService.prototype.setRuntimeEnabled = function(request, callback) {
                return $protobuf.rpc.Service.prototype.rpcCall.call(this, PrivokeRuntimeControlService.prototype.setRuntimeEnabled, $root.privoke.v1.SetRuntimeEnabledRequest, $root.privoke.v1.RuntimeControlStatus, request, callback);
            }, {
                name: { value: "SetRuntimeEnabled" },
                path: { value: "/privoke.v1.PrivokeRuntimeControlService/SetRuntimeEnabled" },
                requestType: { value: "SetRuntimeEnabledRequest" },
                responseType: { value: "RuntimeControlStatus" },
                requestStream: { value: $undefined },
                responseStream: { value: $undefined }
            });

            /**
             * Callback as used by {@link privoke.v1.PrivokeRuntimeControlService#status}.
             * @memberof privoke.v1.PrivokeRuntimeControlService
             * @typedef StatusCallback
             * @type {function}
             * @param {Error|null} error Error, if any
             * @param {privoke.v1.RuntimeControlStatus} [response] RuntimeControlStatus
             */

            /**
             * Calls Status.
             * @memberof privoke.v1.PrivokeRuntimeControlService
             * @typedef Status
             * @type {{
             *   (request: privoke.v1.IRuntimeHealthRequest, callback: privoke.v1.PrivokeRuntimeControlService.StatusCallback): void;
             *   (request: privoke.v1.IRuntimeHealthRequest): Promise<privoke.v1.RuntimeControlStatus>;
             *   readonly name: "Status";
             *   readonly path: "/privoke.v1.PrivokeRuntimeControlService/Status";
             *   readonly requestType: "RuntimeHealthRequest";
             *   readonly responseType: "RuntimeControlStatus";
             *   readonly requestStream: undefined;
             *   readonly responseStream: undefined;
             * }}
             */

            /**
             * Calls Status.
             * @name privoke.v1.PrivokeRuntimeControlService#status
             * @type {privoke.v1.PrivokeRuntimeControlService.Status}
             */
            $Object.defineProperties(PrivokeRuntimeControlService.prototype.status = function(request, callback) {
                return $protobuf.rpc.Service.prototype.rpcCall.call(this, PrivokeRuntimeControlService.prototype.status, $root.privoke.v1.RuntimeHealthRequest, $root.privoke.v1.RuntimeControlStatus, request, callback);
            }, {
                name: { value: "Status" },
                path: { value: "/privoke.v1.PrivokeRuntimeControlService/Status" },
                requestType: { value: "RuntimeHealthRequest" },
                responseType: { value: "RuntimeControlStatus" },
                requestStream: { value: $undefined },
                responseStream: { value: $undefined }
            });

            /**
             * Callback as used by {@link privoke.v1.PrivokeRuntimeControlService#modelStreamingHealth}.
             * @memberof privoke.v1.PrivokeRuntimeControlService
             * @typedef ModelStreamingHealthCallback
             * @type {function}
             * @param {Error|null} error Error, if any
             * @param {privoke.v1.RuntimeHealthResponse} [response] RuntimeHealthResponse
             */

            /**
             * Calls ModelStreamingHealth.
             * @memberof privoke.v1.PrivokeRuntimeControlService
             * @typedef ModelStreamingHealth
             * @type {{
             *   (request: privoke.v1.IRuntimeHealthRequest, callback: privoke.v1.PrivokeRuntimeControlService.ModelStreamingHealthCallback): void;
             *   (request: privoke.v1.IRuntimeHealthRequest): Promise<privoke.v1.RuntimeHealthResponse>;
             *   readonly name: "ModelStreamingHealth";
             *   readonly path: "/privoke.v1.PrivokeRuntimeControlService/ModelStreamingHealth";
             *   readonly requestType: "RuntimeHealthRequest";
             *   readonly responseType: "RuntimeHealthResponse";
             *   readonly requestStream: undefined;
             *   readonly responseStream: undefined;
             * }}
             */

            /**
             * Calls ModelStreamingHealth.
             * @name privoke.v1.PrivokeRuntimeControlService#modelStreamingHealth
             * @type {privoke.v1.PrivokeRuntimeControlService.ModelStreamingHealth}
             */
            $Object.defineProperties(PrivokeRuntimeControlService.prototype.modelStreamingHealth = function(request, callback) {
                return $protobuf.rpc.Service.prototype.rpcCall.call(this, PrivokeRuntimeControlService.prototype.modelStreamingHealth, $root.privoke.v1.RuntimeHealthRequest, $root.privoke.v1.RuntimeHealthResponse, request, callback);
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

    return privoke;
})();

export {
  $root as default
};
