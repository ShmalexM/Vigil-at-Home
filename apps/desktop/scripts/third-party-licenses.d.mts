import type { Plugin } from 'vite';

export declare const LICENSES_DIR: string;
export declare function writeLicenses(name: string, files: Iterable<string>): number;
export declare function thirdPartyLicenses(name: string): Plugin;
