"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProxyFinalResponseFilter = void 0;
const events_1 = __importDefault(require("events"));
class ProxyFinalResponseFilter extends events_1.default.EventEmitter {
    constructor(proxy, ctx) {
        super();
        this.writable = true;
        this.write = function (chunk) {
            proxy._onResponseData(ctx, chunk, function (err, chunk) {
                if (err) {
                    return proxy._onError("ON_RESPONSE_DATA_ERROR", ctx, err);
                }
                if (chunk) {
                    return ctx.proxyToClientResponse.write(chunk);
                }
            });
            return true;
        };
        this.end = function (chunk) {
            if (chunk) {
                return proxy._onResponseData(ctx, chunk, function (err, chunk) {
                    if (err) {
                        return proxy._onError("ON_RESPONSE_DATA_ERROR", ctx, err);
                    }
                    return proxy._onResponseEnd(ctx, function (err) {
                        if (err) {
                            return proxy._onError("ON_RESPONSE_END_ERROR", ctx, err);
                        }
                        return ctx.proxyToClientResponse.end(chunk || undefined);
                    });
                });
            }
            else {
                return proxy._onResponseEnd(ctx, function (err) {
                    if (err) {
                        return proxy._onError("ON_RESPONSE_END_ERROR", ctx, err);
                    }
                    return ctx.proxyToClientResponse.end(chunk || undefined);
                });
            }
        };
        return this;
    }
}
exports.ProxyFinalResponseFilter = ProxyFinalResponseFilter;
//# sourceMappingURL=ProxyFinalResponseFilter.js.map