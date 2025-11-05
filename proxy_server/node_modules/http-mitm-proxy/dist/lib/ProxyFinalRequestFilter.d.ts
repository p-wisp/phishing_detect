/// <reference types="node" />
import events from "events";
export declare class ProxyFinalRequestFilter extends events.EventEmitter {
    writable: boolean;
    write: any;
    end: any;
    constructor(proxy: any, ctx: any);
}
