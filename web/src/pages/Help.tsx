/**
 * Help page — Getting Started, MCP Integration, Supported Services, FAQ, Troubleshooting.
 */

interface ServiceLink {
  name: string;
  href: string;
  note: string;
}

const SERVICE_LINKS: ServiceLink[] = [
  {
    name: 'GitHub',
    href: 'https://github.com/settings/tokens',
    note: 'Personal Access Tokens (classic or fine-grained)',
  },
  {
    name: 'OpenAI',
    href: 'https://platform.openai.com/api-keys',
    note: 'API Keys',
  },
  {
    name: 'Anthropic',
    href: 'https://console.anthropic.com/settings/keys',
    note: 'API Keys',
  },
  {
    name: 'Stripe',
    href: 'https://dashboard.stripe.com/apikeys',
    note: 'API Keys (secret key)',
  },
  {
    name: 'Slack',
    href: 'https://api.slack.com/apps',
    note: 'Bot Token (xoxb-) from your Slack App',
  },
  {
    name: 'GitLab',
    href: 'https://gitlab.com/-/user_settings/personal_access_tokens',
    note: 'Personal Access Tokens',
  },
  {
    name: 'Google',
    href: 'https://console.cloud.google.com/apis/credentials',
    note: 'API Keys or Service Account JSON',
  },
];

const FAQ_ITEMS = [
  {
    q: 'Where are my credentials stored?',
    a: 'Credentials are stored in OpenBao (an open-source vault) running locally on your machine. They are never sent to Straylight servers.',
  },
  {
    q: 'Can I add multiple instances of the same service?',
    a: 'Yes — use a custom name when adding the service (e.g., "github-work" and "github-personal").',
  },
  {
    q: 'What is the MCP proxy?',
    a: 'The Straylight MCP proxy sits between Claude Code and your services. It injects your credentials transparently so Claude can call APIs without ever seeing your keys.',
  },
  {
    q: 'How do I update a credential?',
    a: 'Navigate to the service detail page and click "Rotate Credential". Enter your new key and save.',
  },
  {
    q: 'Does this work offline?',
    a: 'Yes — Straylight runs entirely on your machine. You only need a network connection to reach the target APIs.',
  },
];

const TROUBLESHOOTING_ITEMS = [
  {
    title: 'Health status shows "degraded"',
    steps: [
      'Check that the OpenBao vault is running: open a terminal and run straylight status.',
      'If the vault is sealed, run straylight vault unseal and enter your master key.',
      'Restart Straylight if the problem persists.',
    ],
  },
  {
    title: 'Claude Code cannot find the MCP server',
    steps: [
      'Verify the server is running: curl http://localhost:9470/api/v1/health',
      'Re-run: claude mcp add straylight http://localhost:9470',
      'Restart Claude Code after adding the server.',
    ],
  },
  {
    title: 'Service shows "not configured" after adding it',
    steps: [
      'Check your credential is correct by clicking the service tile and using "Check Credential".',
      'For token format errors, ensure you copied the full token including any prefix (e.g., ghp_, sk_).',
    ],
  },
];

export function Help() {
  return (
    <div className="mx-auto max-w-3xl space-y-10">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">Help &amp; User Guide</h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Everything you need to set up and use Straylight-AI.
        </p>
      </div>

      {/* Getting Started */}
      <section id="getting-started">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">
          Getting Started
        </h2>
        <ol className="space-y-4">
          <li className="flex gap-4">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-100 text-sm font-bold text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300">
              1
            </span>
            <div>
              <p className="font-medium text-slate-800 dark:text-slate-200">Step 1. Install Straylight</p>
              <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
                Download and run the Straylight binary for your platform. The dashboard opens at{' '}
                <code className="rounded bg-slate-100 px-1 py-0.5 text-xs dark:bg-slate-700">
                  http://localhost:9470
                </code>.
              </p>
            </div>
          </li>
          <li className="flex gap-4">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-100 text-sm font-bold text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300">
              2
            </span>
            <div>
              <p className="font-medium text-slate-800 dark:text-slate-200">Step 2. Add a Service</p>
              <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
                Click <strong>Add Service</strong> on the dashboard. Choose a provider (e.g., GitHub),
                pick an auth method, and paste your API key or token. Straylight stores it securely in
                the local vault.
              </p>
            </div>
          </li>
          <li className="flex gap-4">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-100 text-sm font-bold text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300">
              3
            </span>
            <div>
              <p className="font-medium text-slate-800 dark:text-slate-200">Step 3. Connect to Claude Code</p>
              <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
                Register Straylight as an MCP server so Claude Code can use your services:
              </p>
              <pre className="mt-2 rounded-md bg-slate-900 px-4 py-3 text-xs text-green-300 overflow-x-auto">
                <code>claude mcp add straylight http://localhost:9470</code>
              </pre>
            </div>
          </li>
        </ol>
      </section>

      {/* MCP Integration */}
      <section id="mcp-integration">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">
          MCP Integration
        </h2>
        <p className="mb-3 text-sm text-slate-600 dark:text-slate-400">
          Straylight implements the Model Context Protocol (MCP), letting Claude Code call your APIs
          directly. After connecting, Claude can use tools like{' '}
          <code className="rounded bg-slate-100 px-1 py-0.5 text-xs dark:bg-slate-700">straylight_api_call</code>{' '}
          to make authenticated requests to any service you have configured.
        </p>
        <div className="rounded-md border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-800/50">
          <p className="mb-2 text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wide">
            Register with Claude Code
          </p>
          <pre className="text-sm text-slate-800 dark:text-slate-200 overflow-x-auto">
            <code>claude mcp add straylight http://localhost:9470</code>
          </pre>
        </div>
        <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">
          Once connected, Claude can call{' '}
          <code className="rounded bg-slate-100 px-1 py-0.5 text-xs dark:bg-slate-700">straylight_services</code>{' '}
          to list available services, and{' '}
          <code className="rounded bg-slate-100 px-1 py-0.5 text-xs dark:bg-slate-700">straylight_api_call</code>{' '}
          to make authenticated requests.
        </p>
      </section>

      {/* Supported Services */}
      <section id="supported-services">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">
          Supported Services
        </h2>
        <p className="mb-4 text-sm text-slate-500 dark:text-slate-400">
          Click a service name to go directly to its key management page.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          {SERVICE_LINKS.map((svc) => (
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
        <div className="space-y-4">
          {FAQ_ITEMS.map((item) => (
            <div
              key={item.q}
              className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800"
            >
              <p className="font-medium text-slate-800 dark:text-slate-200">{item.q}</p>
              <p className="mt-1.5 text-sm text-slate-500 dark:text-slate-400">{item.a}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Troubleshooting */}
      <section id="troubleshooting">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-slate-100">
          Troubleshooting
        </h2>
        <div className="space-y-4">
          {TROUBLESHOOTING_ITEMS.map((item) => (
            <div
              key={item.title}
              className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800"
            >
              <p className="font-medium text-slate-800 dark:text-slate-200">{item.title}</p>
              <ol className="mt-2 list-decimal list-inside space-y-1">
                {item.steps.map((step, i) => (
                  <li key={i} className="text-sm text-slate-500 dark:text-slate-400">
                    {step}
                  </li>
                ))}
              </ol>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
