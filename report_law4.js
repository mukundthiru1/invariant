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
  const classRegex = /(?:export\s+const\s+([a-zA-Z0-9_]+)[\s\S]*?(?=export\s+const|$))/g;
  
  let match;
  while ((match = classRegex.exec(content)) !== null) {
      const className = match[1];
      const classBody = match[0];
      
      const idMatch = classBody.match(/id:\s*['"](.*?)['"]/);
      if (!idMatch) continue;
      const classId = idMatch[1];
      
      const detectBodyMatch = classBody.match(/detect\s*\([^)]*\)\s*\{([\s\S]*?)\n    (?:,|knownBenign|knownPayloads|detectL2|generateVariants|id|name|description)/);
      if (detectBodyMatch) {
          const lines = detectBodyMatch[1].split('\n').length;
          if (lines > 30) {
             console.log(`1. Class ID: ${classId}\n2. Law Violated: LAW 4 (Elegance) - detect() longer than 30 lines\n3. Fix: Extract inner logic into helper functions to decompose detect() under 30 lines.\n`);
          }
      }
      
      const regexes = classBody.match(/\/[^\/]+\/[a-z]*/g);
      if (regexes) {
          for (const r of regexes) {
             if (r.length > 200) {
                 console.log(`1. Class ID: ${classId}\n2. Law Violated: LAW 4 (Elegance) - regex wider than 200 chars\n3. Fix: Decompose the long regex (${r.length} chars) into smaller composable regex strings or multiple check statements.\n`);
             }
          }
      }
      
      const decodes = classBody.match(/deepDecode\(/g);
      if (decodes && decodes.length > 1) {
           console.log(`1. Class ID: ${classId}\n2. Law Violated: LAW 4 (Elegance) - deepDecode() called more than once\n3. Fix: Call deepDecode() exactly once at the top of the method and reuse the result.\n`);
      }
  }
});
