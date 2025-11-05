"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const zlib_1 = __importDefault(require("zlib"));
exports.default = {
    onResponse(ctx, callback) {
        const serverToProxyResponse = ctx.serverToProxyResponse;
        if (serverToProxyResponse.headers["content-encoding"]?.toLowerCase() == "gzip") {
            delete serverToProxyResponse.headers["content-encoding"];
            ctx.addResponseFilter(zlib_1.default.createGunzip());
        }
        return callback();
    },
    onRequest(ctx, callback) {
        ctx.proxyToServerRequestOptions.headers["accept-encoding"] = "gzip";
        return callback();
    },
};
//# sourceMappingURL=gunzip.js.map