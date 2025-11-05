#! /usr/bin/env node --experimental-specifier-resolution=node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const yargs_1 = __importDefault(require("yargs"));
const helpers_1 = require("yargs/helpers");
const debug_1 = __importDefault(require("debug"));
const debug = (0, debug_1.default)("http-mitm-proxy:bin");
const proxy_1 = require("../lib/proxy");
const proxy = new proxy_1.Proxy();
const args = (0, yargs_1.default)((0, helpers_1.hideBin)(process.argv))
    .alias("h", "help")
    .alias("h", "?")
    .options("port", {
    default: 80,
    describe: "HTTP Port.",
})
    .alias("p", "port")
    .options("host", {
    describe: "HTTP Listen Interface.",
}).argv;
if (args.help) {
    yargs_1.default.showHelp();
    process.exit(-1);
}
proxy.onError((ctx, err, errorKind) => {
    debug(errorKind, err);
});
proxy.listen(args, (err) => {
    if (err) {
        debug(`Failed to start listening on port ${args.port}`, err);
        process.exit(1);
    }
    debug(`proxy listening on ${args.port}`);
});
//# sourceMappingURL=mitm-proxy.js.map