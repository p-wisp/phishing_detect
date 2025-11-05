"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProxyFinalRequestFilter = void 0;
const events_1 = __importDefault(require("events"));
class ProxyFinalRequestFilter extends events_1.default.EventEmitter {
    constructor(proxy, ctx) {
        super();
        this.writable = true;
        this.write = (chunk) => {
            proxy._onRequestData(ctx, chunk, (err, chunk) => {
                if (err) {
                    return proxy._onError("ON_REQUEST_DATA_ERROR", ctx, err);
                }
                if (chunk) {
                    return ctx.proxyToServerRequest.write(chunk);
                }
            });
            return true;
        };
        this.end = (chunk) => {
            if (chunk) {
                return proxy._onRequestData(ctx, chunk, (err, chunk) => {
                    if (err) {
                        return proxy._onError("ON_REQUEST_DATA_ERROR", ctx, err);
                    }
                    return proxy._onRequestEnd(ctx, (err) => {
                        if (err) {
                            return proxy._onError("ON_REQUEST_END_ERROR", ctx, err);
                        }
                        return ctx.proxyToServerRequest.end(chunk);
                    });
                });
            }
            else {
                return proxy._onRequestEnd(ctx, (err) => {
                    if (err) {
                        return proxy._onError("ON_REQUEST_END_ERROR", ctx, err);
                    }
                    return ctx.proxyToServerRequest.end(chunk || undefined);
                });
            }
        };
    }
}
exports.ProxyFinalRequestFilter = ProxyFinalRequestFilter;
//# sourceMappingURL=ProxyFinalRequestFilter.js.map