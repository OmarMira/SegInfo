import type { Finding } from '../report/sarif.js';

/**
 * Per-finding explanation for the UI tooltip: why this specific line was
 * reported (rule-specific, in Spanish) plus the concrete evidence the module
 * captured in `properties` (secret type, entropy, CVE, container, header...)
 * and how to fix it.
 *
 * The triage bucket answer ("why is it in this bucket") stays in triage.ts;
 * this module only explains the detection itself, so two rows that share a
 * bucket still get different, verifiable reasons.
 *
 * `fix` is the technical remediation for the rule, not the bucket advice: it
 * tells the reader what to change, and uses the finding's own data when that
 * makes the instruction actionable (the fixed version for a vulnerable
 * dependency, the exact header value for a web finding).
 */

export interface FindingExplanation {
  /** Rule-specific reason the scanner reported this finding. */
  why: string;
  /** Labeled facts captured by the module, ready to display. */
  evidence: string[];
  /** Concrete remediation for this rule (Spanish, imperative). */
  fix: string;
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

/** How to fix each secret shape: rotate, relocate, purge history (leakscan). */
const SECRET_FIXES: Record<string, string> = {
  'aws-access-key':
    'Desactivá la clave en IAM (Usuario → Credenciales de seguridad → Desactivar o Eliminar), generá una nueva solo si la necesitás y guardala en un gestor de secretos. El valor ya estuvo expuesto: purgalo del historial de git con git filter-repo o BFG.',
  'aws-sts-access-key':
    'Revocá la sesión temporal y sacá el token del repo. Las credenciales STS se piden en tiempo de ejecución (rol / assume-role), nunca se escriben en archivos.',
  'github-token':
    'Revocá el token en GitHub → Settings → Developer settings → Personal access tokens, generá uno nuevo con permisos mínimos y cargalo desde un secret store o una variable de entorno.',
  'github-fine-grained-pat':
    'Revocá el token fine-grained en GitHub → Settings → Developer settings → Fine-grained tokens, generá uno nuevo acotado a los repositorios necesarios y guardalo fuera del código.',
  'slack-token':
    'Revocá el token en la app de Slack (OAuth & Permissions → Revoke) y reinstalá la app; el token nuevo va en una variable de entorno, no en el repo.',
  'stripe-key':
    'Rollé la clave en el dashboard de Stripe (Developers → API keys → Roll key) y cargá la nueva por variable de entorno. Si era una clave live, revisá los movimientos por uso no autorizado.',
  'google-api-key':
    'Borrá o restringí la clave en Google Cloud Console (APIs & Services → Credentials): limitá las APIs habilitadas y los orígenes o IPs permitidos, y sacala del código.',
  'npm-token':
    'Revocá el token con npm token revoke <id> y publicá desde CI con tokens de corta duración u OIDC (--provenance), en lugar de un token fijo en el repo.',
  'jwt-token':
    'Rotá la clave de firma para invalidar los JWT ya emitidos y generá los tokens en el servidor; un JWT en el repo permite suplantar sesiones mientras no expire.',
  'private-key':
    'Tratá la clave como comprometida: generá un par nuevo, reemplazá la clave pública en los servidores (authorized_keys o certificado) y revocá la anterior.',
  'db-url-credentials':
    'Cambiá la contraseña de ese usuario en la base, mové la cadena de conexión a una variable de entorno o gestor de secretos y no dejes credenciales en la URL versionada.',
  'hardcoded-credential':
    'Sacá el literal del código: leelo de process.env (o del gestor de secretos del despliegue), rotá el valor por si ya se filtró y agregá el archivo a .gitignore si no debe versionarse.',
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

/** How to fix each non-secret rule (SAST sinks, IaC misconfig, web headers). */
const RULE_FIXES: Record<string, string> = {
  'sast/sql-injection':
    'Usá consultas parametrizadas (marcadores ? / $1 o el query builder del ORM) en lugar de concatenar o interpolar entrada del usuario en el SQL.',
  'sast/xss-innerhtml':
    'Escribí con textContent o innerText; si necesitás HTML, sanitizá primero con una librería como DOMPurify antes de asignar innerHTML.',
  'sast/command-injection':
    'Pasá los argumentos como array a execFile o spawn sin shell: true, validá contra una allowlist y no armes la orden por concatenación.',
  'sast/eval-usage':
    'Eliminá eval y new Function: usá JSON.parse para datos, un mapa de funciones permitidas para el despacho o un parser real.',
  'sast/weak-hash':
    'Cambiá a SHA-256 o SHA-512 para integridad; para contraseñas usá bcrypt, scrypt o argon2 con salt y factor de trabajo.',
  'sast/insecure-random':
    'Usá crypto.randomBytes o crypto.getRandomValues para tokens, contraseñas y saltos; Math.random no es criptográfico.',

  'iac/s3-public-acl':
    'Cambiá acl a private y agregá un aws_s3_bucket_public_access_block con block_public_acls, block_public_policy, ignore_public_acls y restrict_public_buckets en true.',
  'iac/sg-sensitive-port-open':
    'No expongas ese puerto a Internet: limitá cidr_blocks a los rangos reales (VPN u oficina) o usá bastión / SSM Session Manager en lugar de SSH o RDP públicos.',
  'iac/sg-open-to-world':
    'Reemplazá 0.0.0.0/0 por los CIDR que realmente necesitan acceso y poné el servicio detrás de un balanceador con WAF si debe ser público.',
  'iac/tf-hardcoded-secret':
    'Reemplazá el literal por var.<nombre> (con sensitive = true) o leelo de SSM / Secrets Manager, y rotá el valor porque ya quedó en el state y en el repo.',
  'iac/k8s-privileged-container':
    'Quitá securityContext.privileged: true; si necesitás capacidades, declaralas en capabilities.add y poné allowPrivilegeEscalation: false y runAsNonRoot: true.',
  'iac/k8s-host-network':
    'Quitá hostNetwork: true y exponé el pod con un Service o Ingress; si de verdad necesita la red del host, justificalo y acotalo con una NetworkPolicy.',
  'iac/k8s-plaintext-env-secret':
    'Cargá el valor desde un Secret con valueFrom.secretKeyRef (o External Secrets / CSI), no como value literal en el manifiesto.',

  'web/http-not-redirected':
    'Serví el sitio solo por HTTPS y redirigí HTTP con 301 o 308 a la misma URL en https://; después agregá HSTS.',
  'web/missing-hsts':
    'Agregá la cabecera Strict-Transport-Security: max-age=31536000; includeSubDomains en el servidor o el proxy (solo cuando HTTPS funcione en todos los subdominios).',
  'web/missing-csp':
    "Definí una Content-Security-Policy restrictiva (por ejemplo default-src 'self') y evitá unsafe-inline; empezá en report-only si hay que medir el impacto.",
  'web/missing-x-content-type-options':
    'Agregá la cabecera X-Content-Type-Options: nosniff en todas las respuestas.',
  'web/missing-x-frame-options':
    "Agregá X-Frame-Options: DENY (o frame-ancestors 'none' en la CSP) para bloquear el encuadre del sitio.",
  'web/missing-referrer-policy':
    'Agregá Referrer-Policy: strict-origin-when-cross-origin (o no-referrer si no necesitás el referente).',
  'web/insecure-cookie':
    'Marcá las cookies de sesión con Secure y HttpOnly (y SameSite), y serví siempre por HTTPS para que Secure tenga efecto.',
  'web/missing-samesite':
    'Agregá SameSite=Lax (o Strict) a las cookies que no necesiten enviarse en navegaciones cruzadas.',
  'web/server-version-disclosure':
    'Ocultá la versión: server_tokens off en nginx, ServerTokens Prod en Apache, o eliminá la cabecera en el proxy o CDN.',
  'web/redirect-loop-or-exceeded':
    'Revisá las reglas de redirección: cortá el ciclo, apuntá a la URL final y limitá la cadena a uno o dos saltos.',
  'web/fetch-failed':
    'Verificá que la URL resuelva por DNS, presente un certificado válido y no esté detrás de un firewall o autenticación que bloquee el escaneo.',
};

/** Upgrade command per ecosystem, used to make the dependency fix concrete. */
const ECOSYSTEM_UPGRADE: Record<string, (pkg: string, version: string) => string> = {
  npm: (pkg, version) => `npm install ${pkg}@${version}`,
  PyPI: (pkg, version) => `pip install -U "${pkg}>=${version}"`,
};

const PROPERTY_LABELS: Record<string, string> = {
  type: 'Patrón',
  entropy: 'Entropía',
  source: 'Origen',
  commit: 'Commit',
  package: 'Paquete',
  version: 'Versión',
  ecosystem: 'Ecosistema',
  direct: 'Dependencia directa',
  dev: 'Solo desarrollo',
  introducedBy: 'Introducida por',
  paths: 'Rutas de introducción',
  pathsTotal: 'Rutas totales',
  pathsTruncated: 'Rutas truncadas',
  vulnerabilityId: 'ID de vulnerabilidad',
  aliases: 'Alias',
  severity: 'Severidad OSV',
  fixedIn: 'Corregido en',
  advisoryModified: 'Aviso actualizado',
  advisoryPublished: 'Aviso publicado',
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
  'ecosystem',
  'direct',
  'dev',
  'introducedBy',
  'paths',
  'pathsTotal',
  'pathsTruncated',
  'vulnerabilityId',
  'aliases',
  'severity',
  'fixedIn',
  'advisoryModified',
  'advisoryPublished',
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
  // A clone is also a working tree; the label names what was read (the
  // current checkout) without calling it "local", and provenance says where
  // the checkout came from.
  'working-tree': 'contenido actual del checkout (sin historial)',
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
  const base = id
    ? `La dependencia ${target} figura como afectada por ${id} en la base de datos OSV.`
    : `La dependencia ${target} figura como afectada en la base de datos OSV.`;

  const direct = properties?.direct;
  if (direct === true) return `${base} Es una dependencia directa del proyecto.`;
  if (direct === false) {
    const introducedBy = Array.isArray(properties?.introducedBy)
      ? properties.introducedBy.filter((item): item is string => typeof item === 'string')
      : [];
    return introducedBy.length > 0
      ? `${base} Es transitiva: llega a través de ${introducedBy.join(', ')}.`
      : `${base} Es transitiva: llega a través de otro paquete, no del manifiesto raíz.`;
  }
  return base;
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

/** How to fix a leaked secret: rotate it, relocate it, purge the history. */
function secretFix(properties: Record<string, unknown> | undefined, ruleId: string): string {
  const type =
    typeof properties?.type === 'string' ? properties.type : ruleId.replace(/^leakscan\//, '');
  const base =
    SECRET_FIXES[type] ??
    'Rotá el secreto, movelo a una variable de entorno o a un gestor de secretos y sacalo del código y del historial de git.';
  if (properties?.source !== 'git-history') return base;
  if (/historial|filter-repo|BFG/i.test(base)) return base;
  return `${base} Además, el valor quedó en un commit: purgalo del historial con git filter-repo o BFG.`;
}

/** First fixed version, accepting both the array and the plain-string shape. */
function firstFixedVersion(properties: Record<string, unknown> | undefined): string | null {
  const fixed = properties?.fixedIn;
  if (typeof fixed === 'string' && fixed.trim() !== '') return fixed.trim();
  if (Array.isArray(fixed)) {
    const first = fixed.find((item) => typeof item === 'string' && item.trim() !== '');
    return typeof first === 'string' ? first.trim() : null;
  }
  return null;
}

/** How to fix a vulnerable dependency, with the upgrade command when known. */
function dependencyFix(properties: Record<string, unknown> | undefined): string {
  const pkg = typeof properties?.package === 'string' ? properties.package : null;
  const ecosystem = typeof properties?.ecosystem === 'string' ? properties.ecosystem : null;
  const fixed = firstFixedVersion(properties);
  const urgency =
    properties?.kev === true
      ? ' Está catalogada como explotada en el mundo real (CISA KEV): priorizala sobre el resto.'
      : '';

  if (!pkg) {
    return `Actualizá la dependencia a una versión corregida o reemplazala por una alternativa mantenida.${urgency}`;
  }

  // A transitive package is never a direct install, and updating its parent
  // is not guaranteed to change the resolved version.
  if (properties?.direct === false) {
    const introducedBy = Array.isArray(properties?.introducedBy)
      ? properties.introducedBy.filter((item): item is string => typeof item === 'string')
      : [];
    const parents = introducedBy.length > 0 ? introducedBy.join(', ') : 'el paquete que la requiere';
    const target = fixed ? ` La corrección publicada más cercana es ${fixed}.` : '';
    return (
      `Es una dependencia transitiva: no la instales directamente. Actualizá el paquete que la introduce ` +
      `(${parents}) y volvé a escanear; si el padre sigue fijando esta versión, evaluá un override o ` +
      `resolución y verificá el árbol resultante.${target}${urgency}`
    );
  }

  if (!fixed) {
    return `No hay versión corregida publicada para ${pkg}: aplicá el mitigante que indique el aviso o reemplazá la dependencia.${urgency}`;
  }
  const command = ecosystem ? ECOSYSTEM_UPGRADE[ecosystem]?.(pkg, fixed) : undefined;
  const hint = command ? ` (${command})` : '';
  return `Actualizá ${pkg} a ${fixed} o superior${hint}. Si todavía no podés, aplicá el workaround del aviso y registrá la excepción con su fecha de revisión.${urgency}`;
}

function fallbackFix(ruleId: string): string {
  if (ruleId.startsWith('leakscan/')) {
    return 'Rotá el secreto, movelo a una variable de entorno o a un gestor de secretos y sacalo del código y del historial de git.';
  }
  if (ruleId.startsWith('sca/')) {
    return 'Actualizá la dependencia a una versión corregida o reemplazala por una alternativa mantenida.';
  }
  if (ruleId.startsWith('iac/')) {
    return 'Corregí la configuración según la recomendación del proveedor y volvé a aplicar el plan revisando el diff.';
  }
  if (ruleId.startsWith('sast/')) {
    return 'Validá o parametrizá el dato en el punto señalado y agregá un test que cubra el caso.';
  }
  if (ruleId.startsWith('web/')) {
    return 'Agregá o corregí la cabecera indicada en el servidor o en el proxy que responde.';
  }
  return 'Aplicá la corrección que indica la documentación de la regla y volvé a escanear para confirmar.';
}

/** Builds the Spanish "why was this reported" explanation and its evidence. */
export function explainFinding(finding: Finding): FindingExplanation {
  const properties = finding.properties;
  const evidence = evidenceFor(properties);

  let why: string;
  let fix: string;
  if (finding.ruleId.startsWith('leakscan/')) {
    why = secretWhy(properties, finding.ruleId);
    fix = secretFix(properties, finding.ruleId);
  } else if (finding.ruleId.startsWith('sca/')) {
    why = dependencyWhy(properties);
    fix = dependencyFix(properties);
  } else {
    why = RULE_NOTES[finding.ruleId] ?? fallbackWhy(finding.ruleId);
    fix = RULE_FIXES[finding.ruleId] ?? fallbackFix(finding.ruleId);
  }

  return { why, evidence, fix };
}
