/* Single source of truth for what the catalog should ship. Loaded by the
 * static_store + all-apps suites and asserted against what the page renders.
 *
 * Update only from the reconciled 32-app default-Bazaar catalog ledger.
 */
export const EXPECTED_APPS = [
  { name: 'AiLagoon',                 version: '0.7.26',  categories: ['Productivity'] },
  { name: 'BotMother',                version: '1.3.10',  categories: ['Productivity', 'Social'] },
  { name: 'Bureau Calendar',          version: '0.22.1',  categories: ['Productivity', 'Office'] },
  { name: 'Bureau Contacts',          version: '0.16.0',  categories: ['Productivity', 'Office'] },
  { name: 'Bureau Doc',               version: '2.0.35',  categories: ['Productivity', 'Office'] },
  { name: 'Bureau Paint',             version: '2.0.30',  categories: ['Productivity', 'Office'] },
  { name: 'Bureau Sheets',            version: '2.1.6',   categories: ['Productivity', 'Office'] },
  { name: 'CanBoard',                 version: '0.2.5',   categories: ['Productivity'] },
  { name: 'CCA.SH Configurator',      version: '0.0.81',  categories: ['Productivity'] },
  { name: 'ClientSpace',              version: '0.1.7',   categories: ['Productivity'] },
  { name: 'CrateLink',                version: '0.3.4',   categories: ['Productivity', 'Office'] },
  { name: 'Creeper',                  version: '0.1.24',  categories: ['Productivity', 'Developer Tools'] },
  { name: 'CyberTeller',              version: '0.1.97',  categories: ['Productivity'] },
  { name: 'DomainTemplate',           version: '0.5.88',  categories: ['Productivity', 'Office'] },
  { name: 'DueProcess',               version: '0.1.76',  categories: ['Productivity'] },
  { name: 'Fineract Configurator',    version: '0.2.20',  categories: ['Productivity', 'Office'] },
  { name: 'GoldKey',                  version: '0.3.5',   categories: ['Productivity'] },
  { name: 'InstaCo',                  version: '0.1.10',  categories: ['Productivity', 'Office'] },
  { name: 'InstaDAO',                 version: '1.0.12',  categories: ['Productivity', 'Office'] },
  { name: 'Jinn',                     version: '0.0.10',  categories: ['Productivity'] },
  { name: 'Lobby',                    version: '0.1.30',  categories: ['Productivity'] },
  { name: 'Melusina Dashboard',       version: '0.2.10',  categories: ['Productivity'] },
  { name: 'MerMail',                  version: '0.5.5',   categories: ['Productivity', 'Communications'] },
  { name: 'MiniGit',                  version: '0.2.14',  categories: ['Developer Tools'] },
  { name: 'NamedCoin',                version: '0.1.36',  categories: ['Productivity'] },
  { name: 'NamedCoin Configurator',   version: '0.1.44',  categories: ['Productivity'] },
  { name: 'OpenSanctions',            version: '0.1.25',  categories: ['Productivity'] },
  { name: 'paype.cc',                 version: '0.3.191', categories: ['Productivity', 'Office'] },
  { name: 'Shell Tester',             version: '0.1.11',  categories: ['Developer Tools'] },
  { name: 'Teleport',                 version: '1.3.5',   categories: ['Communications', 'Productivity'] },
  { name: 'TeleScreen',               version: '0.0.16',  categories: ['Productivity', 'Developer Tools'] },
  { name: 'Vintage',                  version: '1.3.4',   categories: ['Productivity'] },
] as const;

export const TOTAL_APPS = EXPECTED_APPS.length;
