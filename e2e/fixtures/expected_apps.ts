/* Single source of truth for what the catalog should ship. Loaded by the
 * static-store + all-apps suites and asserted against what the page renders.
 *
 * To regenerate: `node fixtures/refresh.mjs`
 */
export const EXPECTED_APPS = [
  { name: 'AiLagoon',          version: '0.7.0', categories: ['Productivity'] },
  { name: 'BotMother',         version: '1.0.9', categories: ['Productivity', 'Social'] },
  { name: 'Cal Bureau',        version: '0.1.0', categories: ['Productivity', 'Office'] },
  { name: 'cca.sh',            version: '0.2.0', categories: ['Productivity', 'Office'] },
  { name: 'CanBoard',          version: '0.1.0', categories: ['Productivity'] },
  { name: 'ClientSpace',       version: '0.1.0', categories: ['Productivity'] },
  { name: 'Consilium',         version: '0.1.0', categories: ['Productivity', 'Social'] },
  { name: 'Contacts Bureau',   version: '0.1.0', categories: ['Productivity', 'Office'] },
  { name: 'CrateLink',         version: '0.1.0', categories: ['Productivity', 'Office'] },
  { name: 'CyberTeller',       version: '0.1.0', categories: ['Productivity'] },
  { name: 'Diagrams Bureau',   version: '1.0.4', categories: ['Productivity', 'Office'] },
  { name: 'Docs Bureau',       version: '1.0.4', categories: ['Productivity', 'Office'] },
  { name: 'DueProcess',        version: '0.1.0', categories: ['Productivity'] },
  { name: 'InstaCo.app',       version: '0.1.0', categories: ['Productivity'] },
  { name: 'Melusina OpenClaw', version: '0.1.0', categories: ['Productivity'] },
  { name: 'MerMail',           version: '0.4.6', categories: ['Productivity'] },
  { name: 'MiniGit',           version: '0.2.0', categories: ['Developer Tools'] },
  { name: 'NamedCoin',         version: '0.1.0', categories: ['Productivity'] },
  { name: 'Notes Bureau',      version: '0.1.0', categories: ['Productivity', 'Office'] },
  { name: 'Paint Bureau',      version: '1.0.4', categories: ['Productivity', 'Office'] },
  { name: 'Sheets Bureau',     version: '1.0.7', categories: ['Productivity', 'Office'] },
] as const;

export const TOTAL_APPS = EXPECTED_APPS.length;
