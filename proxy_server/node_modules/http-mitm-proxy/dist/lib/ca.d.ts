/// <reference types="node" />
import Forge from "node-forge";
import ErrnoException = NodeJS.ErrnoException;
export declare class CA {
    baseCAFolder: string;
    certsFolder: string;
    keysFolder: string;
    CAcert: ReturnType<typeof Forge.pki.createCertificate>;
    CAkeys: ReturnType<typeof Forge.pki.rsa.generateKeyPair>;
    static create(caFolder: any, callback: any): void;
    randomSerialNumber(): string;
    getPem(): any;
    generateCA(callback: (err?: ErrnoException | null | undefined, results?: unknown[] | undefined) => void): void;
    loadCA(callback: Function): void;
    generateServerCertificateKeys(hosts: string | string[], cb: any): void;
    getCACertPath(): string;
}
export default CA;
