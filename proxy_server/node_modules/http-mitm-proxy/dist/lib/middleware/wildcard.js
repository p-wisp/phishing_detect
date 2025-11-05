"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const HOSTNAME_REGEX = /^(.+)(\.[^.]{4,}(\.[^.]{1,3})*\.[^.]+)$/;
exports.default = {
    onCertificateRequired(hostname, callback) {
        let rootHost = hostname;
        if (HOSTNAME_REGEX.test(hostname)) {
            rootHost = hostname.replace(/^[^.]+\./, "");
        }
        return callback(null, {
            keyFile: this.sslCaDir + "/keys/_." + rootHost + ".key",
            certFile: this.sslCaDir + "/certs/_." + rootHost + ".pem",
            hosts: ["*." + rootHost, rootHost],
        });
    },
};
//# sourceMappingURL=wildcard.js.map