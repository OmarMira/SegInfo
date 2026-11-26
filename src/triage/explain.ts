import type { Finding } from '../report/sarif.js';

/**
 * Per-finding explanation for the UI tooltip: why this specific line was
 * reported (rule-specific, in Spanish) plus the concrete evidence the module
 * captured in `properties` (secret type, entropy, CVE, container, header...).
 *
 * The triage bucket answer ("why is it in this bucket") stays in triage.ts;
 * this module only explains the detection itself, so two rows that share a
 * bucket still get different, verifiable reasons.
 */

export interface FindingExplanation {
  /** Rule-specific reason the scanner reported this finding. */
  why: string;
  /** Labeled facts captured by the module, ready to display. */
  evidence: string[];
}

/** What each secret shape means for the reader (leakscan). */
const SECRET_PATTERN_NOTES: Record<string, string> = {
  'aws-access-key':
    'Clave de acceso de AWS (AKIA…): mientras siga activa puede operar sobre la cuenta.',
  'aws-sts-access-key': 'Credencial temporal de AWS STS (ASIA…): sesión de corta duración.',
  'github-token': 'Token de GitHub (ghp_/gho_/ghu_/ghs_/ghr_): acceso a repositorios o a la cuenta.',
  'github-fine-grained-pat': 'Token fine-grained de GitHub (github_pat_…).',
  'slack-token': 'Token de Slack (xox…): acceso al workspace.',
  'stripe-key': 'Clave de Stripe (sk_live_/sk_test_): la variante live mueve dinero real.',
  'google-api-key': 'Clave de API de Google (AIza…): consumo de servicios de Google Cloud.',
  'npm-token': 'Token de npm (npm_…): puede publicar paquetes en el registro.',
  'jwt-token': 'JWT firmado: puede permitir suplantación mientras no expire.',
  'private-key': 'Bloque de clave privada PEM: identidad criptográfica completa.',
  'db-url-credentials': 'URL de conexión con usuario y contraseña embebidos.',
  'hardcoded-credential':
    'Una variable con nombre de credencial (password, secret, token, api key) recibe un literal de 16+ caracteres.',
};

/** SAST rules: the sink/pattern that matched. */
const RULE_NOTES: Record<string, string> = {
  'sast/sql-injection':
    'Un valor dinámico se concatena o interpola dentro de una consulta SQL (query/execute/raw).',
  'sast/xss-innerhtml':
    'Un valor dinámico se escribe en un sink HTML (innerHTML, insertAdjacentHTML o document.write).',
  'sast/command-injection':
    'Un valor dinámico llega a un sink de shell o ejecución (exec, spawn, System, subprocess).',
  'sast/eval-usage':
    'Se evalúa código dinámico (eval o new Function): ejecuta exactamente lo que reciba.',
  'sast/weak-hash':
    'Se usa MD5 o SHA-1 en un contexto criptográfico; no resiste ataques de colisión.',
  'sast/insecure-random':
    'Se genera un valor sensible (token, contraseña) con Math.random/random, que no es criptográfico.',

  'iac/s3-public-acl':
    'El bucket S3 se crea con una ACL pública (public-read o public-read-write).',
  'iac/sg-sensitive-port-open':
    'Un security group expone a Internet un puerto sensible (SSH, RDP o base de datos).',
  'iac/sg-open-to-world':
    'Un security group acepta ingress desde 0.0.0.0/0 (todo Internet).',
  'iac/tf-hardcoded-secret':
    'Hay una credencial literal en Terraform en lugar de una variable o un gestor de secretos.',
  'iac/k8s-privileged-container':
    'El contenedor corre con securityContext.privileged: true, con acceso casi total al host.',
  'iac/k8s-host-network':
    'El pod usa hostNetwork: true y comparte la pila de red del nodo.',
  'iac/k8s-plaintext-env-secret':
    'Una variable de entorno con nombre de secreto lleva el valor en texto plano.',

  'web/http-not-redirected': 'El sitio responde por HTTP y no redirige a HTTPS.',
  'web/missing-hsts':
    'No se envía Strict-Transport-Security (HSTS): el navegador puede volver a HTTP.',
  'web/missing-csp':
    'No se envía Content-Security-Policy: hay menos defensa frente a XSS.',
  'web/missing-x-content-type-options':
    'No se envía X-Content-Type-Options: nosniff; el navegador puede adivinar el tipo.',
  'web/missing-x-frame-options':
    'No se envía X-Frame-Options ni frame-ancestors: riesgo de clickjacking.',
  'web/missing-referrer-policy': 'No se envía Referrer-Policy: se filtran URLs de origen.',
  'web/insecure-cookie': 'Una cookie no tiene las marcas Secure y/o HttpOnly.',
  'web/missing-samesite': 'Una cookie no declara SameSite.',
  'web/server-version-disclosure':
    'Una cabecera de respuesta revela la versión del servidor o de la tecnología.',
  'web/redirect-loop-or-exceeded':
    'La cadena de redirecciones supera el límite permitido (posible bucle).',
  'web/fetch-failed': 'No se pudo obtener la URL para analizarla.',
};

const PROPERTY_LABELS: Record<string, string> = {
  type: 'Patrón',
  entropy: 'Entropía',
  source: 'Origen',
  commit: 'Commit',
  package: 'Paquete',
  version: 'Versión',
  ecosystem: 'Ecosistema',
  vulnerabilityId: 'ID de vulnerabilidad',
  aliases: 'Alias',
  severity: 'Severidad OSV',
  fixedIn: 'Corregido en',
  kev: 'Explotada conocida (CISA KEV)',
  kevDate: 'Añadida a KEV',
  ransomwareUse: 'Uso en ransomware (KEV)',
  epss: 'Probabilidad de explotación (EPSS)',
  epssPercentile: 'Percentil EPSS',
  enrichment: 'Datos de amenaza',
  resource: 'Recurso',
  acl: 'ACL',
  fromPort: 'Puerto desde',
  toPort: 'Puerto hasta',
  container: 'Contenedor',
  kind: 'Tipo de recurso',
  envVar: 'Variable de entorno',
  sink: 'Sink',
  language: 'Lenguaje',
  header: 'Cabecera',
  versionSnippet: 'Versión expuesta',
  missingSecure: 'Falta Secure',
  missingHttpOnly: 'Falta HttpOnly',
};

/** Property display order: the most meaningful facts first. */
const PROPERTY_ORDER = [
  'type',
  'package',
  'version',
  'vulnerabilityId',
  'aliases',
  'severity',
  'fixedIn',
  'kev',
  'kevDate',
  'ransomwareUse',
  'epss',
  'epssPercentile',
  'enrichment',
  'entropy',
  'source',
  'commit',
  'resource',
  'kind',
  'acl',
  'fromPort',
  'toPort',
  'container',
  'envVar',
  'sink',
  'language',
  'header',
  'versionSnippet',
  'missingSecure',
  'missingHttpOnly',
];

/** Keys that are internal or already shown elsewhere in the tooltip. */
const SKIPPED_PROPERTIES = new Set(['triage', 'check']);

const MAX_EVIDENCE_ITEMS = 9;
const MAX_VALUE_LENGTH = 120;

const SEVERITY_LABELS: Record<string, string> = {
  low: 'Baja',
  moderate: 'Moderada',
  medium: 'Media',
  high: 'Alta',
  critical: 'Crítica',
  unknown: 'Desconocida',
};

const LANGUAGE_LABELS: Record<string, string> = {
  js: 'JavaScript',
  ts: 'TypeScript',
  py: 'Python',
  javascript: 'JavaScript',
  typescript: 'TypeScript',
  python: 'Python',
};

const SOURCE_LABELS: Record<string, string> = {
  'working-tree': 'árbol de trabajo (archivo actual)',
  'git-history': 'historial de git (commit anterior)',
};

const ENRICHMENT_LABELS: Record<string, string> = {
  unavailable: 'no disponible (falló la consulta de amenazas)',
};

function truncate(value: string): string {
  const clean = value.replace(/\s+/g, ' ').trim();
  return clean.length > MAX_VALUE_LENGTH ? `${clean.slice(0, MAX_VALUE_LENGTH - 1)}…` : clean;
}

function formatValue(key: string, value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) {
    const items = value.filter((item) => item !== null && item !== undefined).map(String);
    return items.length > 0 ? truncate(items.join(', ')) : null;
  }
  if (typeof value === 'boolean') {
    if (key === 'kev') return value ? 'Sí (explotada en el mundo real)' : 'No';
    return value ? 'Sí' : 'No';
  }
  if (typeof value === 'number') {
    if (key === 'entropy') return value.toFixed(2);
    if (key === 'epss' || key === 'epssPercentile') return `${(value * 100).toFixed(1)} %`;
    return String(value);
  }
  const text = String(value);
  if (text.trim() === '') return null;
  if (key === 'severity') return SEVERITY_LABELS[text.toLowerCase()] ?? text;
  if (key === 'language') return LANGUAGE_LABELS[text.toLowerCase()] ?? text;
  if (key === 'source') return SOURCE_LABELS[text] ?? text;
  if (key === 'enrichment') return ENRICHMENT_LABELS[text] ?? text;
  if (key === 'fixedIn') return text;
  if (key === 'commit') return text.slice(0, 12);
  return truncate(text);
}

function evidenceFor(properties: Record<string, unknown> | undefined): string[] {
  if (!properties) return [];
  const keys = [
    ...PROPERTY_ORDER.filter((key) => key in properties),
    ...Object.keys(properties).filter(
      (key) => !PROPERTY_ORDER.includes(key) && !SKIPPED_PROPERTIES.has(key),
    ),
  ];

  const evidence: string[] = [];
  const seen = new Set<string>();
  for (const key of keys) {
    if (SKIPPED_PROPERTIES.has(key)) continue;
    const label = PROPERTY_LABELS[key];
    if (!label) continue; // unknown/internal property: do not leak raw keys
    const formatted = formatValue(key, properties[key]);
    if (!formatted) continue;
    const line = `${label}: ${formatted}`;
    if (seen.has(line)) continue;
    seen.add(line);
    evidence.push(line);
    if (evidence.length >= MAX_EVIDENCE_ITEMS) break;
  }
  return evidence;
}

function secretWhy(properties: Record<string, unknown> | undefined, ruleId: string): string {
  const type = typeof properties?.type === 'string' ? properties.type : ruleId.replace(/^leakscan\//, '');
  const note =
    SECRET_PATTERN_NOTES[type] ??
    'El contenido coincide con un patrón de credencial conocido del escáner.';
  const fromHistory = properties?.source === 'git-history';
  return fromHistory
    ? `${note} Aparece en un commit del historial, aunque ya no esté en el archivo actual.`
    : note;
}

function dependencyWhy(properties: Record<string, unknown> | undefined): string {
  const pkg = typeof properties?.package === 'string' ? properties.package : null;
  const version = typeof properties?.version === 'string' ? properties.version : null;
  const id =
    typeof properties?.vulnerabilityId === 'string' ? properties.vulnerabilityId : null;
  if (!pkg) {
    return 'Una dependencia declarada aparece como vulnerable en la base de datos OSV.';
  }
  const target = version ? `${pkg}@${version}` : pkg;
  return id
    ? `La dependencia ${target} figura como afectada por ${id} en la base de datos OSV.`
    : `La dependencia ${target} figura como afectada en la base de datos OSV.`;
}

function fallbackWhy(ruleId: string): string {
  if (ruleId.startsWith('leakscan/')) {
    return 'El contenido coincide con un patrón de secreto conocido del escáner.';
  }
  if (ruleId.startsWith('sca/')) {
    return 'Una dependencia declarada aparece como vulnerable en la base de datos OSV.';
  }
  if (ruleId.startsWith('iac/')) {
    return 'La configuración evaluada cumple el patrón de riesgo de esta comprobación.';
  }
  if (ruleId.startsWith('sast/')) {
    return 'El código coincide con el patrón de esta comprobación de análisis estático.';
  }
  if (ruleId.startsWith('web/')) {
    return 'La respuesta HTTP cumple el patrón de esta comprobación de cabeceras.';
  }
  return 'El hallazgo coincide con la comprobación indicada por la regla.';
}

/** Builds the Spanish "why was this reported" explanation and its evidence. */
export function explainFinding(finding: Finding): FindingExplanation {
  const properties = finding.properties;
  const evidence = evidenceFor(properties);

  let why: string;
  if (finding.ruleId.startsWith('leakscan/')) {
    why = secretWhy(properties, finding.ruleId);
  } else if (finding.ruleId.startsWith('sca/')) {
    why = dependencyWhy(properties);
  } else {
    why = RULE_NOTES[finding.ruleId] ?? fallbackWhy(finding.ruleId);
  }

  return { why, evidence };
}
