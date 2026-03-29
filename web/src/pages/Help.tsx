import { useState } from 'react';

/**
 * Help page — organized into Getting Started, Concepts, MCP Integration,
 * Supported Services, FAQ, and Troubleshooting with searchable content.
 */

interface HelpSection {
  id: string;
  title: string;
  icon: string;
}

const SECTIONS: HelpSection[] = [
  { id: 'getting-started', title: 'Getting Started', icon: '1' },
  { id: 'concepts', title: 'Key Concepts', icon: '2' },
  { id: 'mcp', title: 'MCP Integration', icon: '3' },
  { id: 'services', title: 'Supported Services', icon: '4' },
  { id: 'faq', title: 'FAQ', icon: '5' },
  { id: 'troubleshooting', title: 'Troubleshooting', icon: '6' },
];

interface ServiceLink {
  name: string;
  href: string;
  note: string;
}

const SERVICE_LINKS: ServiceLink[] = [
  { name: 'GitHub', href: 'https://github.com/settings/tokens', note: 'Personal Access Tokens (classic or fine-grained)' },
  { name: 'OpenAI', href: 'https://platform.openai.com/api-keys', note: 'API Keys' },
  { name: 'Anthropic', href: 'https://console.anthropic.com/settings/keys', note: 'API Keys' },
  { name: 'Stripe', href: 'https://dashboard.stripe.com/apikeys', note: 'API Keys (secret key)' },
  { name: 'Slack', href: 'https://api.slack.com/apps', note: 'Bot Token (xoxb-) from your Slack App' },
  { name: 'GitLab', href: 'https://gitlab.com/-/user_settings/personal_access_tokens', note: 'Personal Access Tokens' },
  { name: 'Google Cloud', href: 'https://console.cloud.google.com/apis/credentials', note: 'API Keys or Service Account JSON' },
  { name: 'AWS', href: 'https://console.aws.amazon.com/iam/home#/security_credentials', note: 'Access Key ID + Secret Access Key' },
  { name: 'Azure', href: 'https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps', note: 'Tenant ID + Client ID + Client Secret' },
  { name: 'PostgreSQL', href: 'https://www.postgresql.org/docs/current/libpq-connect.html', note: 'Connection URI' },
  { name: 'MySQL', href: 'https://dev.mysql.com/doc/', note: 'Connection URI' },
  { name: 'Redis', href: 'https://redis.io/docs/latest/develop/connect/', note: 'Connection URI' },
];

const FAQ_ITEMS = [
  { q: 'Where are my credentials stored?', a: 'Credentials are encrypted at rest in OpenBao (an open-source vault) running locally inside the container. They are never sent anywhere outside your machine.' },
  { q: 'Can I add multiple instances of the same service?', a: 'Yes — use a custom name when adding the service (e.g., "github-work" and "github-personal"). Each gets its own credential.' },
  { q: 'What is the MCP proxy?', a: 'The Straylight MCP proxy sits between your AI coding assistant and your services. It injects credentials at the HTTP transport layer so the AI never sees your keys in its context window.' },
  { q: 'How do I update a credential?', a: 'Go to Services, click the service tile, then click "Update Credential". Enter your new key and save. The old credential is overwritten in the vault.' },
  { q: 'Does this work offline?', a: 'Yes — Straylight runs entirely on your machine. You only need a network connection to reach the target APIs themselves.' },
  { q: 'What happens if the vault is sealed?', a: 'Straylight automatically initializes and unseals the vault on startup. If it shows "sealed" after a restart, the container may need to be recreated.' },
  { q: 'Can I use this with other AI tools besides Claude?', a: 'Straylight supports any MCP-compatible AI coding assistant. The HTTP proxy and MCP tools follow the open standard.' },
  { q: 'Is there a cloud/hosted version?', a: 'No — Straylight is local-only by design. Your credentials never leave your machine.' },
];

const TROUBLESHOOTING_ITEMS = [
  {
    title: 'Health status shows "degraded"',
    steps: [
      'Check that the container is running: docker ps | grep straylight',
      'View container logs: docker logs straylight-ai',
      'If the vault is sealed, recreate the container: docker rm -f straylight-ai && npx straylight-ai setup',
    ],
  },
  {
    title: 'Claude Code cannot find the MCP server',
    steps: [
      'Verify Straylight is running: curl http://localhost:9470/api/v1/health',
      'Re-register: claude mcp add straylight-ai --transport stdio -- npx straylight-ai mcp',
      'Restart Claude Code after adding the server.',
    ],
  },
  {
    title: 'Service shows "not configured" after adding it',
    steps: [
      'Click the service tile and use "Check Credential" to verify.',
      'Ensure you copied the full token including any prefix (e.g., ghp_, sk-ant-, sk_live_).',
      'Some tokens expire — check if you need to regenerate one.',
    ],
  },
  {
    title: 'API calls return 403 or authentication errors',
    steps: [
      'Verify your credential is valid by testing it directly (e.g., curl with the token).',
      'Check that the service target URL is correct in the service configuration.',
      'For OAuth tokens, they may have expired — re-authorize via the service detail page.',
    ],
  },
];

const CONCEPT_ITEMS = [
  {
    title: 'Zero-Knowledge Proxy',
    description: 'Straylight injects credentials at the HTTP transport layer. The AI coding assistant makes API calls through Straylight, which adds authentication headers or query parameters. The AI never sees, stores, or can leak your actual credentials.',
  },
  {
    title: 'MCP (Model Context Protocol)',
    description: 'MCP is an open standard for connecting AI assistants to external tools and data sources. Straylight provides MCP tools like straylight_api_call, straylight_exec, and straylight_services that Claude Code can use.',
  },
  {
    title: 'OpenBao Vault',
    description: 'OpenBao is an open-source secrets manager (fork of HashiCorp Vault). Straylight runs it inside the container to encrypt credentials at rest with automatic initialization and unsealing.',
  },
  {
    title: 'Service Templates',
    description: 'Pre-configured integrations for popular services (GitHub, OpenAI, Stripe, etc.) that know the correct API endpoints, authentication methods, and header formats.',
  },
  {
    title: 'Audit Trail',
    description: 'Every credential access, API call, and tool invocation is logged in an append-only audit log. View the audit feed on the Dashboard to monitor what the AI is doing with your credentials.',
  },
  {
    title: 'Dynamic Credentials',
    description: 'For database and cloud services, Straylight can generate short-lived temporary credentials via the OpenBao database and cloud secrets engines, reducing the blast radius of any compromise.',
  },
];

export function Help() {
  const [search, setSearch] = useState('');

  const lc = search.toLowerCase();
  const matchesSearch = (text: string) => !lc || text.toLowerCase().includes(lc);

  return (
    <div className="mx-auto max-w-4xl space-y-8">
      {/* Header + search */}
      <div>
        <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Help &amp; User Guide</h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Everything you need to set up and use Straylight-AI.
        </p>
        <div className="relative mt-4">
          <svg
            aria-hidden="true" className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500"
            width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
          >
            <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            type="text"
            placeholder="Search help topics..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-white py-2.5 pl-10 pr-4 text-sm text-slate-900 placeholder-slate-400 focus:border-indigo-300 focus:outline-none focus:ring-2 focus:ring-indigo-200 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-indigo-600 dark:focus:ring-indigo-900/40"
          />
        </div>
      </div>

      {/* Quick nav */}
      <nav className="flex flex-wrap gap-2">
        {SECTIONS.map((s) => (
          <a
            key={s.id}
            href={`#${s.id}`}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600 transition-colors hover:border-indigo-300 hover:text-indigo-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400 dark:hover:border-indigo-600 dark:hover:text-indigo-300"
          >
            <span className="flex h-4 w-4 items-center justify-center rounded bg-indigo-100 text-[10px] font-bold text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300">
              {s.icon}
            </span>
            {s.title}
          </a>
        ))}
      </nav>

      {/* Getting Started */}
      <section id="getting-started">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">Getting Started</h2>
        <ol className="space-y-4">
          {[
            {
              step: '1',
              title: 'Install Straylight',
              desc: (
                <>
                  Run <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs dark:bg-slate-700">npx straylight-ai setup</code> to pull the Docker image and start the container. The dashboard opens at{' '}
                  <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs dark:bg-slate-700">http://localhost:9470</code>.
                </>
              ),
            },
            {
              step: '2',
              title: 'Add a Service',
              desc: 'Go to the Services page and click Add Service. Choose a provider (e.g., GitHub), pick an auth method, and paste your API key. Straylight stores it encrypted in the local vault.',
            },
            {
              step: '3',
              title: 'Connect to Claude Code',
              desc: 'Register Straylight as an MCP server so Claude Code can use your services without seeing your credentials.',
            },
          ]
            .filter((item) => matchesSearch(item.title) || matchesSearch(String(item.desc)))
            .map((item) => (
              <li key={item.step} className="flex gap-4">
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-100 text-sm font-bold text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300">
                  {item.step}
                </span>
                <div>
                  <p className="font-medium text-slate-800 dark:text-slate-200">{item.title}</p>
                  <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">{item.desc}</p>
                  {item.step === '3' && (
                    <pre className="mt-2 overflow-x-auto rounded-md bg-slate-900 px-4 py-3 text-xs text-emerald-300">
                      <code>claude mcp add straylight-ai --transport stdio -- npx straylight-ai mcp</code>
                    </pre>
                  )}
                </div>
              </li>
            ))}
        </ol>
      </section>

      {/* Key Concepts */}
      <section id="concepts">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">Key Concepts</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {CONCEPT_ITEMS.filter((c) => matchesSearch(c.title) || matchesSearch(c.description)).map((item) => (
            <div
              key={item.title}
              className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800"
            >
              <p className="font-medium text-slate-800 dark:text-slate-200">{item.title}</p>
              <p className="mt-1.5 text-sm leading-relaxed text-slate-500 dark:text-slate-400">{item.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* MCP Integration */}
      <section id="mcp">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">MCP Integration</h2>
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-5 dark:border-slate-700 dark:bg-slate-800/50">
            <p className="mb-2 text-xs font-medium uppercase tracking-wider text-slate-400 dark:text-slate-500">
              Register with Claude Code
            </p>
            <pre className="overflow-x-auto text-sm text-slate-800 dark:text-slate-200">
              <code>claude mcp add straylight-ai --transport stdio -- npx straylight-ai mcp</code>
            </pre>
          </div>

          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">Available MCP Tools</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              { name: 'straylight_api_call', desc: 'Make authenticated HTTP requests to any configured service.' },
              { name: 'straylight_exec', desc: 'Run commands with credentials injected as environment variables.' },
              { name: 'straylight_services', desc: 'List all configured services and their status.' },
              { name: 'straylight_check', desc: 'Check if a credential is valid and available.' },
              { name: 'straylight_db_query', desc: 'Execute database queries with dynamic temporary credentials.' },
              { name: 'straylight_scan', desc: 'Scan project files for exposed secrets across 14 pattern categories.' },
              { name: 'straylight_read_file', desc: 'Read files with sensitive content automatically redacted.' },
            ]
              .filter((t) => matchesSearch(t.name) || matchesSearch(t.desc))
              .map((tool) => (
                <div key={tool.name} className="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-700 dark:bg-slate-800">
                  <code className="text-xs font-semibold text-indigo-600 dark:text-indigo-400">{tool.name}</code>
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{tool.desc}</p>
                </div>
              ))}
          </div>
        </div>
      </section>

      {/* Supported Services */}
      <section id="services">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">Supported Services</h2>
        <p className="mb-4 text-sm text-slate-500 dark:text-slate-400">
          Click a service name to go to its credential management page.
        </p>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {SERVICE_LINKS.filter((s) => matchesSearch(s.name) || matchesSearch(s.note)).map((svc) => (
            <a
              key={svc.name}
              href={svc.href}
              target="_blank"
              rel="noopener noreferrer"
              className="flex flex-col rounded-lg border border-slate-200 bg-white p-3 transition-colors hover:border-indigo-300 hover:shadow-sm dark:border-slate-700 dark:bg-slate-800 dark:hover:border-indigo-500"
            >
              <span className="font-medium text-indigo-700 dark:text-indigo-300">{svc.name}</span>
              <span className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{svc.note}</span>
            </a>
          ))}
        </div>
      </section>

      {/* FAQ */}
      <section id="faq">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">FAQ</h2>
        <div className="space-y-3">
          {FAQ_ITEMS.filter((item) => matchesSearch(item.q) || matchesSearch(item.a)).map((item) => (
            <details
              key={item.q}
              className="group rounded-xl border border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-800"
            >
              <summary className="cursor-pointer select-none px-4 py-3 text-sm font-medium text-slate-800 dark:text-slate-200">
                {item.q}
              </summary>
              <p className="px-4 pb-3 text-sm leading-relaxed text-slate-500 dark:text-slate-400">{item.a}</p>
            </details>
          ))}
        </div>
      </section>

      {/* Troubleshooting */}
      <section id="troubleshooting">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">Troubleshooting</h2>
        <div className="space-y-3">
          {TROUBLESHOOTING_ITEMS.filter(
            (item) => matchesSearch(item.title) || item.steps.some((s) => matchesSearch(s))
          ).map((item) => (
            <div
              key={item.title}
              className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800"
            >
              <p className="font-medium text-slate-800 dark:text-slate-200">{item.title}</p>
              <ol className="mt-2 list-decimal list-inside space-y-1">
                {item.steps.map((step, i) => (
                  <li key={i} className="text-sm text-slate-500 dark:text-slate-400">{step}</li>
                ))}
              </ol>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
