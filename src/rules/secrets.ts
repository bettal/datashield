import type { ConfigFile, Finding, Rule } from "../types.js";
import { looksLikeHighEntropySecret, shannonEntropy } from "../detection/index.js";
import {
  findLineNumber,
  findAllMatches,
  maskSecretValue,
  isTextLikeFile,
  isMarkdownLikeFile,
  isExampleLikePath,
  hasNearbyCodeFence,
  hasExampleOrTestContext,
  isLikelyExampleValue,
} from "./helpers.js";

/**
 * Secret detection patterns.
 */
const SECRET_PATTERNS: ReadonlyArray<{
  readonly name: string;
  readonly pattern: RegExp;
  readonly description: string;
}> = [
  {
    name: "anthropic-api-key",
    pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g,
    description: "Anthropic API key",
  },
  {
    name: "openai-api-key",
    pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/g,
    description: "OpenAI API key",
  },
  {
    name: "openai-legacy-api-key",
    pattern: /sk-(?!ant-|proj-|or-v1-)[a-zA-Z0-9_-]{20,}/g,
    description: "OpenAI API key",
  },
  {
    name: "xai-api-key",
    pattern: /xai-[a-zA-Z0-9_-]{20,}/g,
    description: "xAI API key",
  },
  {
    name: "github-pat",
    pattern: /ghp_[a-zA-Z0-9]{36,}/g,
    description: "GitHub personal access token",
  },
  {
    name: "github-fine-grained",
    pattern: /github_pat_[a-zA-Z0-9_]{20,}/g,
    description: "GitHub fine-grained token",
  },
  {
    name: "linear-api-key",
    pattern: /lin_api_[a-zA-Z0-9]{20,}/g,
    description: "Linear API key",
  },
  {
    name: "cloudflare-api-token",
    pattern: /(?:CLOUDFLARE_API_TOKEN|CLOUDFLARE_TOKEN|CF_API_TOKEN|CF_TOKEN)\s*[=:]\s*["']?[a-zA-Z0-9_-]{20,}["']?/gi,
    description: "Cloudflare API token",
  },
  {
    name: "aws-access-key",
    pattern: /AKIA[0-9A-Z]{16}/g,
    description: "AWS access key ID",
  },
  {
    name: "aws-secret-key",
    pattern: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi,
    description: "AWS secret access key",
  },
  {
    name: "hardcoded-password",
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi,
    description: "Hardcoded password",
  },
  {
    name: "bearer-token",
    pattern: /["']Bearer\s+[a-zA-Z0-9._-]{20,}["']/g,
    description: "Hardcoded bearer token",
  },
  {
    name: "connection-string",
    pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps):\/\/[^\s"']+:[^\s"']+@/gi,
    description: "Database connection string with credentials",
  },
  {
    name: "slack-token",
    pattern: /xox[bprs]-[a-zA-Z0-9-]{10,}/g,
    description: "Slack API token",
  },
  {
    name: "jwt-token",
    pattern: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    description: "JWT token",
  },
  {
    name: "google-api-key",
    pattern: /AIza[a-zA-Z0-9_-]{35}/g,
    description: "Google API key",
  },
  {
    name: "stripe-key",
    pattern: /(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{24,}/g,
    description: "Stripe API key",
  },
  {
    name: "discord-token",
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g,
    description: "Discord bot token",
  },
  {
    name: "npm-token",
    pattern: /npm_[a-zA-Z0-9]{36,}/g,
    description: "npm access token",
  },
  {
    name: "sendgrid-key",
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    description: "SendGrid API key",
  },
  {
    name: "twilio-key",
    pattern: /SK[a-f0-9]{32}/g,
    description: "Twilio API key",
  },
  {
    name: "azure-key",
    pattern: /(?:AccountKey|azure[_-]?(?:storage[_-]?)?(?:account[_-]?)?key)\s*[=:]\s*["']?[a-zA-Z0-9/+]{86}==/gi,
    description: "Azure storage account key",
  },
  {
    name: "mailchimp-key",
    pattern: /[a-f0-9]{32}-us\d{1,2}/g,
    description: "Mailchimp API key",
  },
  {
    name: "huggingface-token",
    pattern: /hf_[a-zA-Z0-9]{20,}/g,
    description: "Hugging Face access token",
  },
  {
    name: "databricks-token",
    pattern: /dapi[a-f0-9]{32}/g,
    description: "Databricks personal access token",
  },
  {
    name: "digitalocean-token",
    pattern: /dop_v1_[a-f0-9]{64}/g,
    description: "DigitalOcean personal access token",
  },
  {
    name: "digitalocean-oauth",
    pattern: /doo_v1_[a-f0-9]{64}/g,
    description: "DigitalOcean OAuth token",
  },
  {
    name: "gitlab-pat",
    pattern: /glpat-[a-zA-Z0-9_-]{20}/g,
    description: "GitLab personal access token",
  },
  {
    name: "gitlab-runner-token",
    pattern: /glrt-[a-zA-Z0-9_-]{20}/g,
    description: "GitLab runner token",
  },
  {
    name: "gitlab-pipeline-token",
    pattern: /glptt-[a-zA-Z0-9_-]{20}/g,
    description: "GitLab pipeline trigger token",
  },
  {
    name: "github-oauth",
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    description: "GitHub OAuth token",
  },
  {
    name: "github-app-token",
    pattern: /(?:ghu|ghs)_[a-zA-Z0-9]{36}/g,
    description: "GitHub App token",
  },
  {
    name: "github-refresh-token",
    pattern: /ghr_[a-zA-Z0-9]{36}/g,
    description: "GitHub refresh token",
  },
  {
    name: "bitbucket-token",
    pattern: /ATBB[a-zA-Z0-9]{28,}/g,
    description: "Bitbucket access token",
  },
  {
    name: "shopify-access-token",
    pattern: /shpat_[a-f0-9]{32}/g,
    description: "Shopify access token",
  },
  {
    name: "shopify-shared-secret",
    pattern: /shpss_[a-f0-9]{32}/g,
    description: "Shopify shared secret",
  },
  {
    name: "square-access-token",
    pattern: /sq0atp-[a-zA-Z0-9_-]{22}/g,
    description: "Square access token",
  },
  {
    name: "square-oauth-secret",
    pattern: /sq0csp-[a-zA-Z0-9_-]{43}/g,
    description: "Square OAuth secret",
  },
  {
    name: "paypal-braintree-token",
    pattern: /access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}/g,
    description: "PayPal/Braintree access token",
  },
  {
    name: "telegram-bot-token",
    pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g,
    description: "Telegram bot token",
  },
  {
    name: "firebase-cloud-messaging-key",
    pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
    description: "Firebase Cloud Messaging key",
  },
  {
    name: "supabase-service-role",
    pattern: /sbp_[a-f0-9]{40}/g,
    description: "Supabase service role token",
  },
  {
    name: "vercel-token",
    pattern: /vercel_[a-zA-Z0-9]{24}/g,
    description: "Vercel token",
  },
  {
    name: "netlify-token",
    pattern: /nfp_[a-zA-Z0-9]{40}/g,
    description: "Netlify personal access token",
  },
  {
    name: "railway-token",
    pattern: /railway_[a-zA-Z0-9]{36}/g,
    description: "Railway token",
  },
  {
    name: "planetscale-token",
    pattern: /pscale_tkn_[a-zA-Z0-9_]{43}/g,
    description: "PlanetScale token",
  },
  {
    name: "gcp-oauth-token",
    pattern: /ya29\.[a-zA-Z0-9_-]{20,}/g,
    description: "Google OAuth access token",
  },
  {
    name: "gcp-oauth-client-secret",
    pattern: /GOCSPX-[a-zA-Z0-9_-]{28}/g,
    description: "Google OAuth client secret",
  },
  {
    name: "azure-storage-account-key",
    pattern: /AccountKey=[A-Za-z0-9+/=]{86,}/g,
    description: "Azure Storage account key",
  },
  {
    name: "azure-sas-token",
    pattern: /[?&]sig=[A-Za-z0-9%+/=]{40,}/g,
    description: "Azure SAS token",
  },
  {
    name: "newrelic-api-key",
    pattern: /NRAK-[A-Z0-9]{27}/g,
    description: "New Relic API key",
  },
  {
    name: "sentry-dsn",
    pattern: /https:\/\/[a-f0-9]{32}@[a-z0-9.-]+\/\d+/g,
    description: "Sentry DSN",
  },
  {
    name: "pypi-token",
    pattern: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g,
    description: "PyPI upload token",
  },
  {
    name: "doppler-token",
    pattern: /dp\.pt\.[a-zA-Z0-9]{43}/g,
    description: "Doppler token",
  },
  {
    name: "onepassword-token",
    pattern: /ops_[a-zA-Z0-9]{20,}/g,
    description: "1Password service token",
  },
  {
    name: "groq-api-key",
    pattern: /gsk_[a-zA-Z0-9]{52}/g,
    description: "Groq API key",
  },
  {
    name: "perplexity-api-key",
    pattern: /pplx-[a-zA-Z0-9]{48}/g,
    description: "Perplexity API key",
  },
  {
    name: "replicate-token",
    pattern: /r8_[a-zA-Z0-9]{37}/g,
    description: "Replicate API token",
  },
  {
    name: "dropbox-token",
    pattern: /sl\.[a-zA-Z0-9_-]{130,}/g,
    description: "Dropbox access token",
  },
  {
    name: "mailgun-key",
    pattern: /key-[a-f0-9]{32}/g,
    description: "Mailgun API key",
  },
  {
    name: "facebook-access-token",
    pattern: /EAACEdEose0cBA[A-Za-z0-9]+/g,
    description: "Facebook access token",
  },
  {
    name: "notion-token",
    pattern: /(?:ntn_[a-zA-Z0-9]{40,}|secret_[a-zA-Z0-9]{40,})/g,
    description: "Notion integration token",
  },
  {
    name: "openrouter-api-key",
    pattern: /sk-or-v1-[a-f0-9]{64}/g,
    description: "OpenRouter API key",
  },
  {
    name: "anthropic-admin-key",
    pattern: /sk-ant-admin[a-zA-Z0-9_-]{20,}/g,
    description: "Anthropic admin API key",
  },
  {
    name: "stripe-restricted-key",
    pattern: /rk_(?:live|test)_[a-zA-Z0-9]{24,}/g,
    description: "Stripe restricted API key",
  },
  {
    name: "twilio-account-sid",
    pattern: /AC[a-f0-9]{32}/g,
    description: "Twilio account SID",
  },
  {
    name: "sendinblue-key",
    pattern: /xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}/g,
    description: "Brevo (Sendinblue) API key",
  },
  {
    name: "age-secret-key",
    pattern: /AGE-SECRET-KEY-1[A-Z0-9]{58}/g,
    description: "age encryption secret key",
  },
  {
    name: "encrypted-private-key",
    pattern: /-----BEGIN ENCRYPTED PRIVATE KEY-----/g,
    description: "Encrypted private key material",
  },
  {
    name: "aws-session-token",
    pattern: /\bASIA[0-9A-Z]{16}\b/g,
    description: "AWS temporary session access key",
  },
  {
    name: "cloudinary-credentials",
    pattern: /cloudinary:\/\/\d+:[A-Za-z0-9_-]+@[a-z0-9-]+/g,
    description: "Cloudinary credentials URL",
  },
];

function extractDelimitedToken(content: string, startIndex: number): string {
  let endIndex = startIndex;
  while (endIndex < content.length) {
    const char = content[endIndex];
    if (/\s/.test(char) || /["'`)\]}>]/.test(char)) {
      break;
    }
    endIndex += 1;
  }

  return content.slice(startIndex, endIndex).replace(/[.,;:]+$/, "");
}

function isLikelyMarkdownExamplePassword(
  file: ConfigFile,
  secretPatternName: string,
  matchIndex: number
): boolean {
  if (secretPatternName !== "hardcoded-password") return false;
  if (!isMarkdownLikeFile(file)) return false;
  if (!isExampleLikePath(file)) return false;

  return hasNearbyCodeFence(file.content, matchIndex) || hasExampleOrTestContext(file.content, matchIndex);
}

function isLikelyPlaceholderConnectionString(file: ConfigFile, rawValue: string): boolean {
  if (!isMarkdownLikeFile(file)) return false;

  try {
    const url = new URL(rawValue);
    const username = decodeURIComponent(url.username).toLowerCase();
    const password = decodeURIComponent(url.password).toLowerCase();
    const hostname = url.hostname.toLowerCase();
    const databaseName = url.pathname.replace(/^\/+/, "").toLowerCase();

    const genericUsernames = new Set(["user", "username", "dbuser", "demo"]);
    const genericPasswords = new Set(["pass", "password", "passwd", "demo", "example"]);
    const genericDatabases = new Set(["db", "database", "dbname", "mydb"]);

    const hasGenericHost =
      hostname === "host" ||
      hostname === "hostname" ||
      hostname === "db" ||
      hostname === "database" ||
      hostname === "example" ||
      hostname === "example.com" ||
      hostname.endsWith(".example.com");

    return (
      genericUsernames.has(username) &&
      genericPasswords.has(password) &&
      (hasGenericHost || genericDatabases.has(databaseName))
    );
  } catch {
    return false;
  }
}

function isExplicitBearerTokenPlaceholder(rawValue: string): boolean {
  const match = rawValue.match(/^["']Bearer\s+([A-Z0-9_]+)["']$/);
  if (!match) return false;

  return /^YOUR_[A-Z0-9]+(?:_[A-Z0-9]+)*_HERE$/.test(match[1]);
}

export const secretRules: ReadonlyArray<Rule> = [
  {
    id: "secrets-hardcoded",
    name: "Hardcoded Secrets Detection",
    description: "Scans for hardcoded API keys, tokens, passwords, and credentials",
    severity: "critical",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const findings: Finding[] = [];

      for (const secretPattern of SECRET_PATTERNS) {
        const matches = findAllMatches(file.content, secretPattern.pattern);

        for (const match of matches) {
          // Skip if it's inside an env var reference like ${VAR_NAME}
          const idx = match.index ?? 0;
          const context = file.content.substring(
            Math.max(0, idx - 20),
            idx + match[0].length + 10
          );
          if (context.includes("${") || context.includes("process.env")) {
            continue;
          }

          if (isLikelyMarkdownExamplePassword(file, secretPattern.name, idx)) {
            continue;
          }

          const rawValue =
            secretPattern.name === "connection-string"
              ? extractDelimitedToken(file.content, idx)
              : match[0];

          if (
            secretPattern.name === "bearer-token" &&
            isExplicitBearerTokenPlaceholder(rawValue)
          ) {
            continue;
          }

          if (
            secretPattern.name === "connection-string" &&
            isLikelyPlaceholderConnectionString(file, rawValue)
          ) {
            continue;
          }

          const maskedValue = maskSecretValue(rawValue);

          findings.push({
            id: `secrets-${secretPattern.name}-${idx}`,
            severity: "critical",
            category: "secrets",
            title: `Hardcoded ${secretPattern.description}`,
            description: `Found ${secretPattern.description} in ${file.path}. Secrets must never be hardcoded in configuration files.`,
            file: file.path,
            line: findLineNumber(file, idx),
            evidence: maskedValue,
            fix: {
              description: `Replace with environment variable reference`,
              before: maskSecretValue(rawValue),
              after: `\${${secretPattern.name.toUpperCase().replace(/-/g, "_")}}`,
              auto: false,
            },
          });
        }
      }

      return findings;
    },
  },
  {
    id: "secrets-env-in-config",
    name: "Environment Variable Exposure",
    description: "Checks for env var values being logged or exposed in config",
    severity: "high",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const findings: Finding[] = [];

      const echoEnvPattern = /echo\s+.*\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|PASS|CRED)\w*\}?/gi;
      const matches = findAllMatches(file.content, echoEnvPattern);

      for (const match of matches) {
        findings.push({
          id: `secrets-echo-env-${match.index}`,
          severity: "high",
          category: "secrets",
          title: "Environment variable echoed to terminal",
          description: `Hook or script echoes sensitive environment variable. This exposes secrets in terminal output and session logs.`,
          file: file.path,
          line: findLineNumber(file, match.index ?? 0),
          evidence: match[0],
          fix: {
            description: "Remove echo of sensitive environment variables",
            before: match[0],
            after: "# [REMOVED: secret was being echoed]",
            auto: true,
          },
        });
      }

      return findings;
    },
  },
  {
    id: "secrets-env-in-claude-md",
    name: "Secrets in CLAUDE.md",
    description: "Checks for sensitive env var assignments in CLAUDE.md files which are often committed to repos",
    severity: "high",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];

      const findings: Finding[] = [];

      // Detect patterns like KEY=value, export KEY=value, KEY: value
      const envAssignmentPattern =
        /(?:export\s+)?\b(\w*(?:API_KEY|SECRET_KEY|AUTH_TOKEN|ACCESS_TOKEN|PRIVATE_KEY|PASSWORD|CREDENTIAL|API_SECRET)\w*)\s*[=:]\s*["']?([^\s"']{4,})["']?/gi;
      const matches = findAllMatches(file.content, envAssignmentPattern);

      for (const match of matches) {
        const varName = match[1];
        const idx = match.index ?? 0;

        // Skip env var references like ${VAR} or $VAR
        const value = match[2];
        if (value.startsWith("${") || value.startsWith("$")) continue;

        findings.push({
          id: `secrets-claude-md-env-${idx}`,
          severity: "high",
          category: "secrets",
          title: `Sensitive env var in CLAUDE.md: ${varName}`,
          description: `CLAUDE.md contains an assignment for "${varName}". CLAUDE.md files are typically committed to version control, exposing secrets to anyone who clones the repository.`,
          file: file.path,
          line: findLineNumber(file, idx),
          evidence: `${varName}=<redacted>`,
          fix: {
            description: "Move to .env file and reference via environment variable",
            before: match[0].replace(match[2], maskSecretValue(match[2])),
            after: `# Set ${varName} in your .env file`,
            auto: false,
          },
        });
      }

      return findings;
    },
  },
  {
    id: "secrets-sensitive-env-passthrough",
    name: "Sensitive Env Var Passthrough",
    description: "Checks for MCP servers passing through excessive sensitive environment variables",
    severity: "medium",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (file.type !== "mcp-json") return [];

      const findings: Finding[] = [];

      try {
        const config = JSON.parse(file.content);
        const servers = config.mcpServers ?? {};

        const sensitivePatterns =
          /KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH/i;

        for (const [name, server] of Object.entries(servers)) {
          const serverConfig = server as Record<string, unknown>;
          const env = (serverConfig.env ?? {}) as Record<string, string>;

          const sensitiveVars = Object.keys(env).filter((key) =>
            sensitivePatterns.test(key)
          );

          if (sensitiveVars.length > 5) {
            findings.push({
              id: `secrets-env-passthrough-${name}`,
              severity: "medium",
              category: "secrets",
              title: `MCP server "${name}" receives ${sensitiveVars.length} sensitive env vars`,
              description: `The MCP server "${name}" has ${sensitiveVars.length} sensitive environment variables passed through (${sensitiveVars.slice(0, 3).join(", ")}...). Over-sharing secrets increases the blast radius if the server is compromised. Only pass env vars that the server actually needs.`,
              file: file.path,
              evidence: `Sensitive vars: ${sensitiveVars.join(", ")}`,
              fix: {
                description:
                  "Remove env vars that the server does not need",
                before: `${sensitiveVars.length} sensitive env vars`,
                after: "Only the required env vars for this server",
                auto: false,
              },
            });
          }
        }
      } catch {
        // Not valid JSON
      }

      return findings;
    },
  },
  {
    id: "secrets-url-credentials",
    name: "URL-Embedded Credentials",
    description: "Checks for URLs containing embedded usernames and passwords",
    severity: "high",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];

      const findings: Finding[] = [];

      // Match https://user:password@host patterns (not just database connection strings)
      const urlCredPattern = /https?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/g;
      const matches = findAllMatches(file.content, urlCredPattern);

      for (const match of matches) {
        const idx = match.index ?? 0;

        // Skip if it's inside an env var reference
        const context = file.content.substring(Math.max(0, idx - 20), idx);
        if (context.includes("${") || context.includes("process.env")) continue;

        // Mask the password portion
        const masked = match[0].replace(/(:\/\/[^:]+:)[^@]+(@)/, "$1****$2");

        findings.push({
          id: `secrets-url-credentials-${idx}`,
          severity: "high",
          category: "secrets",
          title: `URL contains embedded credentials`,
          description: `Found a URL with embedded username:password in ${file.path}. Credentials in URLs are exposed in logs, browser history, and referer headers. Use environment variables or a credentials manager instead.`,
          file: file.path,
          line: findLineNumber(file, idx),
          evidence: masked,
          fix: {
            description: "Use environment variables for credentials",
            before: masked,
            after: "https://${USERNAME}:${PASSWORD}@...",
            auto: false,
          },
        });
      }

      return findings;
    },
  },
  {
    id: "secrets-credential-file-reference",
    name: "Credential File Reference",
    description: "Checks for references to credential files that should never be accessed by agents",
    severity: "high",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];

      const findings: Finding[] = [];

      const credentialFiles: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /~\/\.aws\/credentials|\/\.aws\/credentials/g,
          description: "AWS credentials file",
        },
        {
          pattern: /~\/\.ssh\/id_(?:rsa|ed25519|ecdsa)|\/\.ssh\/id_(?:rsa|ed25519|ecdsa)/g,
          description: "SSH private key file",
        },
        {
          pattern: /~\/\.netrc|\/\.netrc/g,
          description: ".netrc file (contains plain-text login credentials)",
        },
        {
          pattern: /~\/\.pgpass|\/\.pgpass/g,
          description: "PostgreSQL password file",
        },
        {
          pattern: /~\/\.docker\/config\.json|\/\.docker\/config\.json/g,
          description: "Docker config (may contain registry credentials)",
        },
        {
          pattern: /~\/\.npmrc|\/\.npmrc/g,
          description: "npm config (may contain auth tokens)",
        },
        {
          pattern: /~\/\.kube\/config|\/\.kube\/config/g,
          description: "Kubernetes config (contains cluster credentials)",
        },
      ];

      for (const { pattern, description } of credentialFiles) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;

          findings.push({
            id: `secrets-cred-file-ref-${idx}`,
            severity: "high",
            category: "secrets",
            title: `Reference to ${description}: ${match[0]}`,
            description: `Found reference to "${match[0]}" — ${description}. Agent definitions and CLAUDE.md files should not reference credential files. If an agent is instructed to read these files, it could expose secrets.`,
            file: file.path,
            line: findLineNumber(file, idx),
            evidence: match[0],
          });
        }
      }

      return findings;
    },
  },
  {
    id: "secrets-private-key-material",
    name: "Private Key Material in Config",
    description: "Checks for PEM-encoded private keys embedded in configuration files",
    severity: "critical",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const findings: Finding[] = [];

      const keyPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
          description: "PEM-encoded private key",
        },
        {
          pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
          description: "PGP private key block",
        },
      ];

      for (const { pattern, description } of keyPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;

          findings.push({
            id: `secrets-private-key-${idx}`,
            severity: "critical",
            category: "secrets",
            title: `${description} found in config`,
            description: `Found "${match[0]}" in ${file.path}. Private keys should never be stored in configuration files — they grant authentication access and should be stored in secure key stores or referenced via file paths with restrictive permissions.`,
            file: file.path,
            line: findLineNumber(file, idx),
            evidence: match[0],
            fix: {
              description: "Remove private key and reference a key file path instead",
              before: match[0],
              after: "Reference key file: ~/.ssh/id_ed25519",
              auto: false,
            },
          });
        }
      }

      return findings;
    },
  },
  {
    id: "secrets-webhook-url",
    name: "Webhook URL with Secret Token",
    description: "Checks for webhook URLs that contain embedded secret tokens or API keys",
    severity: "high",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const findings: Finding[] = [];

      const webhookPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
          description: "Slack webhook URL — allows posting messages to a Slack channel",
        },
        {
          pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+/g,
          description: "Discord webhook URL — allows posting messages to a Discord channel",
        },
        {
          pattern: /https:\/\/outlook\.office\.com\/webhook\/[a-f0-9-]+/g,
          description: "Microsoft Teams webhook URL",
        },
      ];

      for (const { pattern, description } of webhookPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;

          findings.push({
            id: `secrets-webhook-url-${idx}`,
            severity: "high",
            category: "secrets",
            title: `Webhook URL found: ${description.split(" — ")[0]}`,
            description: `Found a ${description}. Webhook URLs contain embedded secrets and should be stored in environment variables. Anyone with this URL can post messages to the channel.`,
            file: file.path,
            line: findLineNumber(file, idx),
            evidence: maskSecretValue(match[0]),
            fix: {
              description: "Store webhook URL in an environment variable",
              before: maskSecretValue(match[0]),
              after: "${WEBHOOK_URL}",
              auto: false,
            },
          });
        }
      }

      return findings;
    },
  },
  {
    id: "secrets-base64-obfuscation",
    name: "Potential Base64 Obfuscated Secret",
    description: "Checks for long base64-encoded strings that may be obfuscated secrets or payloads",
    severity: "medium",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      // Check any text-like surface where base64 payloads could be embedded.
      if (!isTextLikeFile(file)) return [];

      const findings: Finding[] = [];

      // Match base64 strings that are at least 60 chars (likely encoded secrets/payloads)
      // Must not be inside a URL or common non-secret context
      const base64Pattern = /(?<![a-zA-Z0-9/])([A-Za-z0-9+/]{60,}={0,2})(?![a-zA-Z0-9])/g;
      const matches = findAllMatches(file.content, base64Pattern);

      for (const match of matches) {
        const idx = match.index ?? 0;

        // Skip if it's inside a URL
        const context = file.content.substring(Math.max(0, idx - 30), idx);
        if (/https?:\/\/|data:/.test(context)) continue;

        // Skip if it looks like a hash (hex chars only)
        if (/^[a-fA-F0-9]+$/.test(match[1])) continue;

        findings.push({
          id: `secrets-base64-obfuscation-${idx}`,
          severity: "medium",
          category: "secrets",
          title: `Potential base64-obfuscated payload (${match[1].length} chars)`,
          description: `Found a long base64-encoded string (${match[1].length} characters) in ${file.path}. Attackers may encode secrets or malicious instructions in base64 to bypass pattern-matching detection. Decode and inspect this value.`,
          file: file.path,
          line: findLineNumber(file, idx),
          evidence: match[1].substring(0, 20) + "..." + match[1].substring(match[1].length - 10),
        });
      }

      return findings;
    },
  },
  {
    id: "secrets-hardcoded-ip-port",
    name: "Hardcoded Internal IP Address with Port",
    description: "Checks for hardcoded internal/private IP addresses with ports, which may expose internal services",
    severity: "medium",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      const findings: Finding[] = [];

      // Match private IP ranges with ports: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
      const ipPatterns: ReadonlyArray<{
        readonly pattern: RegExp;
        readonly description: string;
      }> = [
        {
          pattern: /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b/g,
          description: "Class A private IP (10.x.x.x) with port",
        },
        {
          pattern: /\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}:\d{2,5}\b/g,
          description: "Class B private IP (172.16-31.x.x) with port",
        },
        {
          pattern: /\b192\.168\.\d{1,3}\.\d{1,3}:\d{2,5}\b/g,
          description: "Class C private IP (192.168.x.x) with port",
        },
      ];

      for (const { pattern, description } of ipPatterns) {
        const matches = findAllMatches(file.content, pattern);
        for (const match of matches) {
          const idx = match.index ?? 0;

          findings.push({
            id: `secrets-hardcoded-ip-${idx}`,
            severity: "medium",
            category: "secrets",
            title: `Hardcoded internal IP with port: ${match[0]}`,
            description: `Found "${match[0]}" — ${description}. Hardcoded internal IPs expose network topology and service locations. Use environment variables or DNS names instead.`,
            file: file.path,
            line: findLineNumber(file, idx),
            evidence: match[0],
            fix: {
              description: "Replace with environment variable or DNS name",
              before: match[0],
              after: "${INTERNAL_SERVICE_URL}",
              auto: false,
            },
          });
        }
      }

      return findings;
    },
  },
  {
    id: "secrets-generic-assignment",
    name: "Generic Secret Assignment",
    description: "Detects credential-like values assigned to secret-named keys without a known vendor prefix",
    severity: "high",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];

      const findings: Finding[] = [];

      const assignmentPattern =
        /(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?key|auth[_-]?token|encryption[_-]?key|signing[_-]?key|private[_-]?key|secret|token)\s*[=:]\s*["']?([A-Za-z0-9_\-./+=]{16,})["']?/gi;

      for (const match of findAllMatches(file.content, assignmentPattern)) {
        const idx = match.index ?? 0;
        const value = match[1];

        if (value.startsWith("${") || value.startsWith("$")) continue;
        if (isLikelyExampleValue(file, idx)) continue;

        // Require a genuinely random-looking value; ordinary words/paths are out.
        if (!looksLikeHighEntropySecret(value, 16, 3.0)) continue;

        findings.push({
          id: `secrets-generic-assignment-${idx}`,
          severity: "high",
          category: "secrets",
          title: "Credential-like value assigned to a secret key",
          description: `Found a high-entropy value assigned to a secret-named key in ${file.path}. Values like this are usually API keys, tokens, or client secrets that should come from environment variables or a secret manager.`,
          file: file.path,
          line: findLineNumber(file, idx),
          evidence: maskSecretValue(value),
          fix: {
            description: "Replace with an environment variable reference",
            before: match[0].replace(value, maskSecretValue(value)),
            after: "# reference the value from an environment variable",
            auto: false,
          },
        });
      }

      return findings;
    },
  },
  {
    id: "secrets-high-entropy",
    name: "High-Entropy String",
    description: "Detects long random-looking strings that may be unlabelled secrets",
    severity: "medium",
    category: "secrets",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];

      const findings: Finding[] = [];

      const quotedPattern = /["'`]([A-Za-z0-9+/=_-]{24,})["'`]/g;

      for (const match of findAllMatches(file.content, quotedPattern)) {
        const idx = match.index ?? 0;
        const value = match[1];

        if (!looksLikeHighEntropySecret(value, 24, 3.5)) continue;
        if (isLikelyExampleValue(file, idx)) continue;

        // Skip well-known hash shapes that are not secrets.
        if (/^[a-f0-9]{40}$/i.test(value) || /^[a-f0-9]{64}$/i.test(value)) continue;

        // Skip values already caught by a vendor-specific pattern.
        const matchedByVendor = SECRET_PATTERNS.some(
          (secretPattern) => findAllMatches(value, secretPattern.pattern).length > 0
        );
        if (matchedByVendor) continue;

        findings.push({
          id: `secrets-high-entropy-${idx}`,
          severity: "medium",
          category: "secrets",
          title: `High-entropy string (${value.length} chars, ${shannonEntropy(value).toFixed(1)} bits/char)`,
          description: `Found a long high-entropy string in ${file.path}. It does not match a known key format but has the statistical profile of a secret. Verify whether it is a credential and move it to an environment variable if so.`,
          file: file.path,
          line: findLineNumber(file, idx),
          evidence: maskSecretValue(value),
        });
      }

      return findings;
    },
  },
];
