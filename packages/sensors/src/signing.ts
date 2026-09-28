// Works out a program's SigningStatus from what each sensor reports about its
// code signature. Rules key on this (unsigned or ad hoc programs are treated
// as untrusted), so a sensor that leaves it out makes those rules blind.

import type { SigningStatus } from '@vigil/core';

/** Leaf certificate common names Apple uses. */
const APPLE_PLATFORM_CN = 'Software Signing';
const APP_STORE_CN = 'Apple Mac OS Application Signing';
const DEVELOPER_ID_PREFIX = 'Developer ID Application';

function fromCertificate(cn: string): SigningStatus {
  if (cn === APPLE_PLATFORM_CN) return 'apple';
  if (cn === APP_STORE_CN) return 'app_store';
  if (cn.startsWith(DEVELOPER_ID_PREFIX)) return 'developer_id';
  // Apple Development and other certificates Gatekeeper does not trust on its own.
  return 'unknown';
}

/**
 * Santa's EXEC log line: cert_cn is the leaf certificate's common name and is
 * absent when there is no certificate. Santa does not log whether such a
 * program was ad hoc signed or not signed at all, so both come out as
 * unsigned (rules treat the two the same). A signing ID in Santa's
 * "platform:com.apple.ls" form, as the sync protocol reports it, also marks
 * an Apple binary.
 */
export function santaSigning(f: {
  cert_sha256?: string | undefined;
  cert_cn?: string | undefined;
  teamid?: string | undefined;
  signingid?: string | undefined;
}): SigningStatus {
  if (f.signingid?.startsWith('platform:')) return 'apple';
  if (f.cert_cn) return fromCertificate(f.cert_cn);
  if (f.teamid) return 'developer_id';
  if (f.cert_sha256) return 'unknown';
  return 'unsigned';
}

/**
 * osquery's signature table. `signed` is empty when the join found no row
 * (the program was gone before osquery looked), which says nothing.
 */
export function osquerySigning(c: {
  signed?: string | undefined;
  authority?: string | undefined;
  identifier?: string | undefined;
}): SigningStatus | undefined {
  if (c.signed === '1') return c.authority ? fromCertificate(c.authority) : 'adhoc';
  if (c.signed === '0') return c.identifier ? 'invalid' : 'unsigned';
  return undefined;
}
