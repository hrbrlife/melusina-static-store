/* Single source of truth for what the catalog should ship. Loaded by the
 * static-store + all-apps suites and asserted against what the page renders.
 *
 * To regenerate: `node fixtures/refresh.mjs`
 */
export const EXPECTED_APPS = [
  { name: 'AiLagoon',          version: '0.7.0', categories: ['Productivity'] },
  { name: 'BotMother',         version: '1.0.9', categories: ['Productivity', 'Social'] },
  { name: 'BureauCal',         version: '0.1.0', categories: ['Productivity', 'Office'] },
  { name: 'BureauContacts',    version: '0.1.0', categories: ['Productivity', 'Office'] },
  { name: 'BureauNotes',       version: '0.1.0', categories: ['Productivity', 'Office'] },
  { name: 'CanBoard',          version: '0.1.0', categories: ['Productivity'] },
  { name: 'ccash',             version: '0.2.0', categories: ['Productivity', 'Office'] },
  { name: 'ClientSpace',       version: '0.1.0', categories: ['Productivity'] },
  { name: 'Consilium',         version: '0.1.0', categories: ['Productivity', 'Social'] },
  { name: 'CrateLink',         version: '0.1.0', categories: ['Productivity', 'Office'] },
  { name: 'CyberTeller',       version: '0.1.0', categories: ['Productivity'] },
  { name: 'Diagram Bureau',    version: '1.0.4', categories: ['Productivity', 'Office'] },
  { name: 'Doc Bureau',        version: '1.0.4', categories: ['Productivity', 'Office'] },
  { name: 'DueProcess',        version: '0.1.0', categories: ['Productivity'] },
  { name: 'InstaCo.app',       version: '0.1.0', categories: ['Productivity'] },
  { name: 'Melusina OpenClaw', version: '0.1.0', categories: ['Productivity'] },
  { name: 'MerMail',           version: '0.4.6', categories: ['Productivity'] },
  { name: 'MiniGit',           version: '0.2.0', categories: ['Developer Tools'] },
  { name: 'NamedCoin',         version: '0.1.0', categories: ['Productivity'] },
  { name: 'Paint Bureau',      version: '1.0.4', categories: ['Productivity', 'Office'] },
  { name: 'Sheets Bureau',     version: '1.0.7', categories: ['Productivity', 'Office'] },
] as const;

export const TOTAL_APPS = EXPECTED_APPS.length;
