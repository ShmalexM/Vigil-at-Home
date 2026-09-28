/**
 * Where the known-bad lists come from. Each source feeds one list; several
 * sources may feed the same list and their entries are combined.
 *
 * The defaults are abuse.ch feeds, published under CC0 and chosen for a low
 * false-positive rate: confirmed botnet command servers, hosts currently
 * serving malware, and hashes of confirmed malware samples.
 */

export type FeedList = 'known_bad_sha256' | 'known_bad_domains' | 'known_bad_ips';

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
    license: 'CC0-1.0',
    homepage: 'https://urlhaus.abuse.ch/',
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
    license: 'CC0-1.0',
    homepage: 'https://bazaar.abuse.ch/',
  },
];
