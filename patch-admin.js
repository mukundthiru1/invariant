const fs = require('fs');
const typesPath = '/home/mukund-thiru/Santh/intel/src/lib/types.ts';
let types = fs.readFileSync(typesPath, 'utf8');
types = types.replace(/ADMIN_API_KEY: string/, 'ADMIN_API_KEY: string\n    ADMIN_SECRET?: string');
fs.writeFileSync(typesPath, types);

const distPath = '/home/mukund-thiru/Santh/intel/src/api/rule-distribution.ts';
let dist = fs.readFileSync(distPath, 'utf8');
dist = dist.replace(/env\\.ADMIN_API_KEY/g, '(env.ADMIN_SECRET || env.ADMIN_API_KEY)');
fs.writeFileSync(distPath, dist);
