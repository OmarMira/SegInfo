import { describe, expect, it } from 'vitest';
import { scanSastContent } from '../../src/modules/sast/sast-rules.js';

function js(code: string) {
  return scanSastContent(code, 'src/app.ts', 'js');
}
function py(code: string) {
  return scanSastContent(code, 'src/app.py', 'py');
}
function ids(findings: ReturnType<typeof js>): string[] {
  return findings.map((f) => f.ruleId);
}

describe('sast/sql-injection', () => {
  it('flags concatenation into a query call', () => {
    const f = js('const q = db.query("SELECT * FROM t WHERE id = " + userId);\n');
    expect(ids(f)).toContain('sast/sql-injection');
    expect(f[0].level).toBe('error');
    expect(f[0].line).toBe(1);
    expect(f[0].file).toBe('src/app.ts');
  });

  it('flags template-literal interpolation into a query call', () => {
    const f = js('const q = db.query(`SELECT * FROM t WHERE id = ${id}`);\n');
    expect(ids(f)).toContain('sast/sql-injection');
  });

  it('does not flag parameterized queries', () => {
    const f = js("const q = db.query('SELECT * FROM t WHERE id = ?', [userId]);\n");
    expect(ids(f)).not.toContain('sast/sql-injection');
  });

  it('does not flag literal-only template interpolation', () => {
    const f = js('const q = db.query(`SELECT * FROM t WHERE id = ${1 + 2}`);\n');
    expect(ids(f)).not.toContain('sast/sql-injection');
  });

  it('flags f-string concatenation in Python execute', () => {
    const f = py('cursor.execute("SELECT * FROM t WHERE id = " + str(uid))\n');
    expect(ids(f)).toContain('sast/sql-injection');
  });

  it('does not flag Python parameterized execute', () => {
    const f = py("cursor.execute('SELECT * FROM t WHERE id = ?', (uid,))\n");
    expect(ids(f)).not.toContain('sast/sql-injection');
  });
});

describe('sast/xss-innerhtml', () => {
  it('flags assignment of a variable to innerHTML', () => {
    const f = js('el.innerHTML = userInput;\n');
    expect(ids(f)).toContain('sast/xss-innerhtml');
    expect(f[0].level).toBe('warning');
  });

  it('flags template interpolation into innerHTML', () => {
    const f = js('el.innerHTML = `<b>${name}</b>`;\n');
    expect(ids(f)).toContain('sast/xss-innerhtml');
  });

  it('does not flag a plain string literal', () => {
    const f = js("el.innerHTML = '<b>hi</b>';\n");
    expect(ids(f)).not.toContain('sast/xss-innerhtml');
  });

  it('does not flag insertAdjacentHTML with a literal', () => {
    const f = js("el.insertAdjacentHTML('beforeend', '<b>hi</b>');\n");
    expect(ids(f)).not.toContain('sast/xss-innerhtml');
  });

  it('flags document.write with a variable', () => {
    const f = js('document.write(content);\n');
    expect(ids(f)).toContain('sast/xss-innerhtml');
  });
});

describe('sast/command-injection', () => {
  it('flags execSync with a concatenated argument', () => {
    const f = js("const out = execSync('ls ' + dir);\n");
    expect(ids(f)).toContain('sast/command-injection');
    expect(f[0].level).toBe('warning');
  });

  it('does not flag execSync with a pure literal', () => {
    const f = js("const out = execSync('ls -la');\n");
    expect(ids(f)).not.toContain('sast/command-injection');
  });

  it('flags os.system with a variable', () => {
    const f = py('os.system(command)\n');
    expect(ids(f)).toContain('sast/command-injection');
  });

  it('does not flag os.system with a literal', () => {
    const f = py("os.system('ls -la')\n");
    expect(ids(f)).not.toContain('sast/command-injection');
  });

  it('flags subprocess with shell=True and a variable', () => {
    const f = py('subprocess.run(cmd, shell=True)\n');
    expect(ids(f)).toContain('sast/command-injection');
  });

  it('does not flag subprocess list form without shell', () => {
    const f = py("subprocess.run(['ls', '-la'])\n");
    expect(ids(f)).not.toContain('sast/command-injection');
  });
});

describe('sast/eval-usage', () => {
  it('flags eval with a variable', () => {
    const f = js('eval(code);\n');
    expect(ids(f)).toContain('sast/eval-usage');
    expect(f[0].level).toBe('warning');
  });

  it('does not flag eval with a literal', () => {
    const f = js("eval('1 + 1');\n");
    expect(ids(f)).not.toContain('sast/eval-usage');
  });

  it('flags new Function with a variable', () => {
    const f = js('const f = new Function(body);\n');
    expect(ids(f)).toContain('sast/eval-usage');
  });

  it('does not flag new Function with literals', () => {
    const f = js("const f = new Function('a', 'return a');\n");
    expect(ids(f)).not.toContain('sast/eval-usage');
  });
});

describe('sast/weak-hash', () => {
  it('flags createHash("md5")', () => {
    const f = js("crypto.createHash('md5');\n");
    expect(ids(f)).toContain('sast/weak-hash');
    expect(f[0].level).toBe('warning');
  });

  it('does not flag createHash("sha256")', () => {
    const f = js("crypto.createHash('sha256');\n");
    expect(ids(f)).not.toContain('sast/weak-hash');
  });

  it('flags Python hashlib.md5', () => {
    const f = py('hashlib.md5(data)\n');
    expect(ids(f)).toContain('sast/weak-hash');
  });

  it('does not flag Python hashlib.sha256', () => {
    const f = py('hashlib.sha256(data)\n');
    expect(ids(f)).not.toContain('sast/weak-hash');
  });
});

describe('sast/insecure-random', () => {
  it('flags Math.random near token', () => {
    const f = js('const token = Math.random().toString(36);\n');
    expect(ids(f)).toContain('sast/insecure-random');
    expect(f[0].level).toBe('note');
  });

  it('does not flag plain Math.random', () => {
    const f = js('const dice = Math.random();\n');
    expect(ids(f)).not.toContain('sast/insecure-random');
  });

  it('flags Python random.randint near password', () => {
    const f = py('password = random.randint(1000, 9999)\n');
    expect(ids(f)).toContain('sast/insecure-random');
  });

  it('does not flag plain Python random.random', () => {
    const f = py('value = random.random()\n');
    expect(ids(f)).not.toContain('sast/insecure-random');
  });
});

describe('fp controls', () => {
  it('ignores matches inside line comments', () => {
    const f = js('// db.query("SELECT " + userId);\nel.innerHTML = userInput;\n');
    expect(ids(f)).not.toContain('sast/sql-injection');
    expect(ids(f)).toContain('sast/xss-innerhtml');
  });

  it('ignores matches inside Python comments', () => {
    const f = py('# cursor.execute("SELECT " + uid)\nvalue = random.random()\n');
    expect(ids(f)).not.toContain('sast/sql-injection');
  });

  it('never echoes matched code into the message', () => {
    const f = js('const q = db.query("SELECT * FROM t WHERE id = " + userId);\n');
    expect(f[0].message).not.toContain('userId');
    expect(f[0].message).not.toContain('SELECT');
  });
});
