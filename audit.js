const fs = require('fs');
const path = require('path');

function getFiles(dir, files = []) {
  const list = fs.readdirSync(dir);
  for (const file of list) {
    const fullPath = path.join(dir, file);
    if (fs.statSync(fullPath).isDirectory()) {
      getFiles(fullPath, files);
    } else if (fullPath.endsWith('.ts') && !fullPath.includes('.test.') && !fullPath.includes('.spec.')) {
      files.push(fullPath);
    }
  }
  return files;
}

const files = getFiles('packages/engine/src/classes');

files.forEach(file => {
  const content = fs.readFileSync(file, 'utf8');
  
  if (content.match(/detect\s*\([^)]*\)\s*\{\s*return\s+(true|false|\[\]|\{\});?\s*\}/)) {
      console.log(`LAW 1: detect() returns hardcoded value in ${file}`);
  }
  
  if (content.match(/detectL2\s*\([^)]*\)\s*\{\s*return\s+null;?\s*\}/)) {
      console.log(`LAW 1: detectL2() always returns null in ${file}`);
  }
  
  if (content.match(/generateVariants\s*\([^)]*\)\s*\{\s*return\s*\[(.*?)\];?\s*\}/s)) {
      console.log(`LAW 1: generateVariants() returns fixed array in ${file}`);
  }
  
  const payloadsMatches = [...content.matchAll(/knownPayloads:\s*\[(.*?)\]/gs)];
  for (const match of payloadsMatches) {
      const items = match[1].split(',').filter(x => x.trim().length > 0 && !x.trim().startsWith('//'));
      if (items.length < 3) {
         console.log(`LAW 1: knownPayloads has fewer than 3 entries (${items.length}) in ${file}`);
      }
  }
  
  const benignMatches = [...content.matchAll(/knownBenign:\s*\[(.*?)\]/gs)];
  for (const match of benignMatches) {
      const items = match[1].split(',').filter(x => x.trim().length > 0 && !x.trim().startsWith('//'));
      if (items.length < 3) {
         console.log(`LAW 1: knownBenign has fewer than 3 entries (${items.length}) in ${file}`);
      }
  }

  const detectBodyMatches = [...content.matchAll(/detect\s*\([^)]*\)\s*\{([\s\S]*?)\n    (?:,|knownBenign|knownPayloads|detectL2|generateVariants|id|name|description)/g)];
  for (const match of detectBodyMatches) {
      const lines = match[1].split('\n').length;
      if (lines > 30) {
         console.log(`LAW 4: detect() is longer than 30 lines (${lines} lines) in ${file}`);
      }
  }
  
  const regexes = content.match(/\/[^\/]+\/[a-z]*/g);
  if (regexes) {
      for (const r of regexes) {
         if (r.length > 200) {
             console.log(`LAW 4: regex wider than 200 chars (${r.length} chars) in ${file}`);
         }
      }
  }
  
  const decodes = content.match(/deepDecode\(/g);
  if (decodes && decodes.length > 1) {
       console.log(`LAW 4: deepDecode() called more than once (${decodes.length} times) in ${file}`);
  }
});
