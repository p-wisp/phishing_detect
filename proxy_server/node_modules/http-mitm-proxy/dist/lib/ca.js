"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CA = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const node_forge_1 = __importDefault(require("node-forge"));
const { pki, md } = node_forge_1.default;
const mkdirp_1 = __importDefault(require("mkdirp"));
const async_1 = __importDefault(require("async"));
const CAattrs = [
    {
        name: "commonName",
        value: "NodeMITMProxyCA",
    },
    {
        name: "countryName",
        value: "Internet",
    },
    {
        shortName: "ST",
        value: "Internet",
    },
    {
        name: "localityName",
        value: "Internet",
    },
    {
        name: "organizationName",
        value: "Node MITM Proxy CA",
    },
    {
        shortName: "OU",
        value: "CA",
    },
];
const CAextensions = [
    {
        name: "basicConstraints",
        cA: true,
    },
    {
        name: "keyUsage",
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true,
    },
    {
        name: "extKeyUsage",
        serverAuth: true,
        clientAuth: true,
        codeSigning: true,
        emailProtection: true,
        timeStamping: true,
    },
    {
        name: "nsCertType",
        client: true,
        server: true,
        email: true,
        objsign: true,
        sslCA: true,
        emailCA: true,
        objCA: true,
    },
    {
        name: "subjectKeyIdentifier",
    },
];
const ServerAttrs = [
    {
        name: "countryName",
        value: "Internet",
    },
    {
        shortName: "ST",
        value: "Internet",
    },
    {
        name: "localityName",
        value: "Internet",
    },
    {
        name: "organizationName",
        value: "Node MITM Proxy CA",
    },
    {
        shortName: "OU",
        value: "Node MITM Proxy Server Certificate",
    },
];
const ServerExtensions = [
    {
        name: "basicConstraints",
        cA: false,
    },
    {
        name: "keyUsage",
        keyCertSign: false,
        digitalSignature: true,
        nonRepudiation: false,
        keyEncipherment: true,
        dataEncipherment: true,
    },
    {
        name: "extKeyUsage",
        serverAuth: true,
        clientAuth: true,
        codeSigning: false,
        emailProtection: false,
        timeStamping: false,
    },
    {
        name: "nsCertType",
        client: true,
        server: true,
        email: false,
        objsign: false,
        sslCA: false,
        emailCA: false,
        objCA: false,
    },
    {
        name: "subjectKeyIdentifier",
    },
];
class CA {
    static create(caFolder, callback) {
        const ca = new CA();
        ca.baseCAFolder = caFolder;
        ca.certsFolder = path_1.default.join(ca.baseCAFolder, "certs");
        ca.keysFolder = path_1.default.join(ca.baseCAFolder, "keys");
        mkdirp_1.default.sync(ca.baseCAFolder);
        mkdirp_1.default.sync(ca.certsFolder);
        mkdirp_1.default.sync(ca.keysFolder);
        async_1.default.series([
            (callback) => {
                const exists = fs_1.default.existsSync(path_1.default.join(ca.certsFolder, "ca.pem"));
                if (exists) {
                    ca.loadCA(callback);
                }
                else {
                    ca.generateCA(callback);
                }
            },
        ], (err) => {
            if (err) {
                return callback(err);
            }
            return callback(null, ca);
        });
    }
    randomSerialNumber() {
        let sn = "";
        for (let i = 0; i < 4; i++) {
            sn += `00000000${Math.floor(Math.random() * 256 ** 4).toString(16)}`.slice(-8);
        }
        return sn;
    }
    getPem() {
        return pki.certificateToPem(this.CAcert);
    }
    generateCA(callback) {
        const self = this;
        pki.rsa.generateKeyPair({ bits: 2048 }, (err, keys) => {
            if (err) {
                return callback(err);
            }
            const cert = pki.createCertificate();
            cert.publicKey = keys.publicKey;
            cert.serialNumber = self.randomSerialNumber();
            cert.validity.notBefore = new Date();
            cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1);
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
            cert.setSubject(CAattrs);
            cert.setIssuer(CAattrs);
            cert.setExtensions(CAextensions);
            cert.sign(keys.privateKey, md.sha256.create());
            self.CAcert = cert;
            self.CAkeys = keys;
            const tasks = [
                fs_1.default.writeFile.bind(null, path_1.default.join(self.certsFolder, "ca.pem"), pki.certificateToPem(cert)),
                fs_1.default.writeFile.bind(null, path_1.default.join(self.keysFolder, "ca.private.key"), pki.privateKeyToPem(keys.privateKey)),
                fs_1.default.writeFile.bind(null, path_1.default.join(self.keysFolder, "ca.public.key"), pki.publicKeyToPem(keys.publicKey)),
            ];
            async_1.default.parallel(tasks, callback);
        });
    }
    loadCA(callback) {
        const self = this;
        async_1.default.auto({
            certPEM(callback) {
                fs_1.default.readFile(path_1.default.join(self.certsFolder, "ca.pem"), "utf-8", callback);
            },
            keyPrivatePEM(callback) {
                fs_1.default.readFile(path_1.default.join(self.keysFolder, "ca.private.key"), "utf-8", callback);
            },
            keyPublicPEM(callback) {
                fs_1.default.readFile(path_1.default.join(self.keysFolder, "ca.public.key"), "utf-8", callback);
            },
        }, (err, results) => {
            if (err) {
                return callback(err);
            }
            self.CAcert = pki.certificateFromPem(results.certPEM);
            self.CAkeys = {
                privateKey: pki.privateKeyFromPem(results.keyPrivatePEM),
                publicKey: pki.publicKeyFromPem(results.keyPublicPEM),
            };
            return callback();
        });
    }
    generateServerCertificateKeys(hosts, cb) {
        const self = this;
        if (typeof hosts === "string") {
            hosts = [hosts];
        }
        const mainHost = hosts[0];
        const keysServer = pki.rsa.generateKeyPair(2048);
        const certServer = pki.createCertificate();
        certServer.publicKey = keysServer.publicKey;
        certServer.serialNumber = this.randomSerialNumber();
        certServer.validity.notBefore = new Date();
        certServer.validity.notBefore.setDate(certServer.validity.notBefore.getDate() - 1);
        certServer.validity.notAfter = new Date();
        certServer.validity.notAfter.setFullYear(certServer.validity.notBefore.getFullYear() + 1);
        const attrsServer = ServerAttrs.slice(0);
        attrsServer.unshift({
            name: "commonName",
            value: mainHost,
        });
        certServer.setSubject(attrsServer);
        certServer.setIssuer(this.CAcert.issuer.attributes);
        certServer.setExtensions(ServerExtensions.concat([
            {
                name: "subjectAltName",
                altNames: hosts.map((host) => {
                    if (host.match(/^[\d.]+$/)) {
                        return { type: 7, ip: host };
                    }
                    return { type: 2, value: host };
                }),
            },
        ]));
        certServer.sign(this.CAkeys.privateKey, md.sha256.create());
        const certPem = pki.certificateToPem(certServer);
        const keyPrivatePem = pki.privateKeyToPem(keysServer.privateKey);
        const keyPublicPem = pki.publicKeyToPem(keysServer.publicKey);
        fs_1.default.writeFile(`${this.certsFolder}/${mainHost.replace(/\*/g, "_")}.pem`, certPem, (error) => {
            if (error) {
                console.error(`Failed to save certificate to disk in ${self.certsFolder}`, error);
            }
        });
        fs_1.default.writeFile(`${this.keysFolder}/${mainHost.replace(/\*/g, "_")}.key`, keyPrivatePem, (error) => {
            if (error) {
                console.error(`Failed to save private key to disk in ${self.keysFolder}`, error);
            }
        });
        fs_1.default.writeFile(`${this.keysFolder}/${mainHost.replace(/\*/g, "_")}.public.key`, keyPublicPem, (error) => {
            if (error) {
                console.error(`Failed to save public key to disk in ${self.keysFolder}`, error);
            }
        });
        cb(certPem, keyPrivatePem);
    }
    getCACertPath() {
        return `${this.certsFolder}/ca.pem`;
    }
}
exports.CA = CA;
exports.default = CA;
//# sourceMappingURL=ca.js.map