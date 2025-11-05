/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
import type { Server as HTTPServer, IncomingHttpHeaders, IncomingMessage, ServerResponse } from "http";
import http from "http";
import type { Server, ServerOptions } from "https";
import https from "https";
import type { WebSocket as WebSocketType } from "ws";
import WebSocket, { WebSocketServer } from "ws";
import semaphore from "semaphore";
import ca from "./ca";
import gunzip from "./middleware/gunzip";
import wildcard from "./middleware/wildcard";
import type { ICertDetails, IContext, IProxy, IProxyOptions, ErrorCallback, ICertficateContext, ICreateServerCallback, IProxySSLServer, IWebSocketContext, OnCertificateRequiredCallback, OnConnectParams, OnErrorParams, OnRequestDataParams, OnRequestParams, OnWebSocketCloseParams, OnWebSocketErrorParams, OnWebSocketFrameParams, OnWebSocketMessageParams, OnWebsocketRequestParams, OnWebSocketSendParams } from "./types";
import type stream from "node:stream";
export { wildcard, gunzip };
type HandlerType<T extends (...args: any[]) => any> = Array<Parameters<T>[0]>;
interface WebSocketFlags {
    mask?: boolean | undefined;
    binary?: boolean | undefined;
    compress?: boolean | undefined;
    fin?: boolean | undefined;
}
export declare class Proxy implements IProxy {
    ca: ca;
    connectRequests: Record<string, http.IncomingMessage>;
    forceSNI: boolean;
    httpAgent: http.Agent;
    httpHost?: string;
    httpPort: number;
    httpServer: HTTPServer | undefined;
    httpsAgent: https.Agent;
    httpsPort?: number;
    httpsServer: Server | undefined;
    keepAlive: boolean;
    onConnectHandlers: HandlerType<IProxy["onConnect"]>;
    onErrorHandlers: HandlerType<IProxy["onError"]>;
    onRequestDataHandlers: HandlerType<IProxy["onRequestData"]>;
    onRequestEndHandlers: HandlerType<IProxy["onRequestEnd"]>;
    onRequestHandlers: HandlerType<IProxy["onRequest"]>;
    onRequestHeadersHandlers: HandlerType<IProxy["onRequestHeaders"]>;
    onResponseDataHandlers: HandlerType<IProxy["onResponseData"]>;
    onResponseEndHandlers: HandlerType<IProxy["onResponseEnd"]>;
    onResponseHandlers: HandlerType<IProxy["onResponse"]>;
    onResponseHeadersHandlers: HandlerType<IProxy["onResponseHeaders"]>;
    onWebSocketCloseHandlers: HandlerType<IProxy["onWebSocketClose"]>;
    onWebSocketConnectionHandlers: HandlerType<IProxy["onWebSocketConnection"]>;
    onWebSocketErrorHandlers: HandlerType<IProxy["onWebSocketError"]>;
    onWebSocketFrameHandlers: HandlerType<IProxy["onWebSocketFrame"]>;
    options: IProxyOptions;
    responseContentPotentiallyModified: boolean;
    sslCaDir: string;
    sslSemaphores: Record<string, semaphore.Semaphore>;
    sslServers: Record<string, IProxySSLServer>;
    timeout: number;
    wsServer: WebSocketServer | undefined;
    wssServer: WebSocketServer | undefined;
    static wildcard: {
        onCertificateRequired(hostname: string, callback: ErrorCallback): void;
    };
    static gunzip: {
        onResponse(ctx: IContext, callback: Function): any;
        onRequest(ctx: IContext, callback: Function): any;
    };
    constructor();
    listen(options: IProxyOptions, callback?: ErrorCallback): this;
    _createHttpsServer(options: ServerOptions & {
        hosts?: string[];
    }, callback: ICreateServerCallback): void;
    close(): this;
    onError(fn: OnErrorParams): this;
    onConnect(fn: OnConnectParams): this;
    onRequestHeaders(fn: OnRequestParams): this;
    onRequest(fn: OnRequestParams): this;
    onWebSocketConnection(fn: OnWebsocketRequestParams): this;
    onWebSocketSend(fn: OnWebSocketSendParams): this;
    onWebSocketMessage(fn: OnWebSocketMessageParams): this;
    onWebSocketFrame(fn: OnWebSocketFrameParams): this;
    onWebSocketClose(fn: OnWebSocketCloseParams): this;
    onWebSocketError(fn: OnWebSocketErrorParams): this;
    onRequestData(fn: OnRequestDataParams): this;
    onRequestEnd(fn: OnRequestParams): this;
    onResponse(fn: OnRequestParams): this;
    onResponseHeaders(fn: OnRequestParams): this;
    onResponseData(fn: OnRequestDataParams): this;
    onResponseEnd(fn: OnRequestParams): this;
    use(mod: any): this;
    _onSocketError(socketDescription: string, err: NodeJS.ErrnoException): void;
    _onHttpServerConnect(req: http.IncomingMessage, socket: stream.Duplex, head: Buffer): any;
    _onHttpServerConnectData(req: http.IncomingMessage, socket: stream.Duplex, head: Buffer): void;
    onCertificateRequired(hostname: string, callback: OnCertificateRequiredCallback): void;
    onCertificateMissing(ctx: ICertficateContext, files: ICertDetails, callback: ErrorCallback): void;
    _onError(kind: string, ctx: IContext | null, err: Error): void;
    _onWebSocketServerConnect(isSSL: boolean, ws: WebSocketType, upgradeReq: IncomingMessage): void;
    _onHttpServerRequest(isSSL: boolean, clientToProxyRequest: IncomingMessage, proxyToClientResponse: ServerResponse): void;
    _onRequestHeaders(ctx: IContext, callback: ErrorCallback): void;
    _onRequest(ctx: IContext, callback: ErrorCallback): void;
    _onWebSocketConnection(ctx: IWebSocketContext, callback: ErrorCallback): void;
    _onWebSocketFrame(ctx: IWebSocketContext, type: string, fromServer: boolean, data: WebSocket.RawData, flags?: WebSocketFlags | boolean): void;
    _onWebSocketClose(ctx: IWebSocketContext, closedByServer: boolean, code: number, message: Buffer): void;
    _onWebSocketError(ctx: IWebSocketContext, err: Error): void;
    _onRequestData(ctx: IContext, chunk: any, callback: any): void;
    _onRequestEnd(ctx: IContext, callback: ErrorCallback): void;
    _onResponse(ctx: IContext, callback: ErrorCallback): void;
    _onResponseHeaders(ctx: IContext, callback: ErrorCallback): void;
    _onResponseData(ctx: IContext, chunk: any, callback: ErrorCallback): void;
    _onResponseEnd(ctx: IContext, callback: ErrorCallback): void;
    static parseHostAndPort(req: http.IncomingMessage, defaultPort?: number): {
        host: string;
        port: number | undefined;
    } | null;
    static parseHost(hostString: string, defaultPort?: number): {
        host: string;
        port: number | undefined;
    };
    static filterAndCanonizeHeaders(originalHeaders: IncomingHttpHeaders): {};
}
