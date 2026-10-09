/**
 * Where the known-bad lists come from. Each source feeds one list; several
 * sources may feed the same list and their entries are combined.
 *
 * The defaults are abuse.ch feeds, free for not-for-profit use under
 * https://abuse.ch/terms-of-use/ (Feodo Tracker's list is also CC0), chosen for a low
 * false-positive rate: confirmed botnet command servers, hosts currently
 * serving malware, and hashes of confirmed malware samples. URLhaus and
 * MalwareBazaar downloads take the user's own free abuse.ch Auth-Key when
 * they have one; Vigil never ships one.
 */

export type FeedList = 'known_bad_sha256' | 'known_bad_domains' | 'known_bad_ips';

/** Keys the user can add for feeds that take one. */
export type FeedKeyName = 'abusech';

/** abuse.ch's per-user key, free at https://auth.abuse.ch/ for non-commercial use. */
const ABUSE_CH_AUTH = { key: 'abusech', header: 'Auth-Key' } as const;

export interface FeedSource {
  /** Stable id, stored with the entries. Lowercase letters, digits and dashes. */
  id: string;
  name: string;
  url: string;
  list: FeedList;
  /**
   * `lines`: one value per line; `#` and `;` start comments; anything after the
   * first space, tab or comma on a line is ignored.
   * `hosts`: a hosts file (`127.0.0.1 evil.example`); the host names are kept.
   */
  format: 'lines' | 'hosts';
  /** How often to fetch. */
  intervalHours: number;
  /**
   * Keep entries this many days after the feed stops listing them. Use this
   * for feeds that only publish recent additions. 0 means the feed is the
   * whole list and anything it drops is removed.
   */
  retainDays: number;
  /** Extra request headers, e.g. an API key the provider requires. */
  headers?: Record<string, string>;
  /**
   * The user's own key this feed takes, sent in `header` when the importer's
   * `keys` option returns one for `key`. Without it the feed is fetched as
   * usual; if that is refused (401/403) the feed reports `needs_key`, is not
   * counted as failing, and its stored entries are kept.
   */
  auth?: { key: FeedKeyName; header: string };
  license: string;
  homepage: string;
}

export const DEFAULT_FEEDS: readonly FeedSource[] = [
  {
    id: 'feodo-c2-ips',
    name: 'Feodo Tracker botnet command servers',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
    list: 'known_bad_ips',
    format: 'lines',
    intervalHours: 6,
    retainDays: 0,
    license: 'CC0-1.0',
    homepage: 'https://feodotracker.abuse.ch/',
  },
  {
    id: 'urlhaus-hosts',
    name: 'URLhaus hosts serving malware',
    url: 'https://urlhaus.abuse.ch/downloads/hostfile/',
    list: 'known_bad_domains',
    format: 'hosts',
    intervalHours: 6,
    retainDays: 0,
    license: 'abuse.ch terms of use (not-for-profit)',
    homepage: 'https://urlhaus.abuse.ch/',
    auth: ABUSE_CH_AUTH,
  },
  {
    id: 'malwarebazaar-recent',
    name: 'MalwareBazaar recent malware hashes',
    url: 'https://bazaar.abuse.ch/export/txt/sha256/recent/',
    list: 'known_bad_sha256',
    format: 'lines',
    intervalHours: 1,
    // The export only covers the last 48 hours, so keep what it has shown.
    retainDays: 180,
    license: 'abuse.ch terms of use (not-for-profit)',
    homepage: 'https://bazaar.abuse.ch/',
    auth: ABUSE_CH_AUTH,
  },
];
