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
  
  const payloadsMatches = [...content.matchAll(/knownPayloads:\s*\[(.*?)\]/gs)];
  for (const match of payloadsMatches) {
      // split by comma but only outside of quotes
      const items = match[1].match(/(['"`])(.*?)\1/g);
      if (!items || items.length < 3) {
         console.log(`LAW 1: knownPayloads has fewer than 3 entries (${items ? items.length : 0}) in ${file}`);
      }
  }
  
  const benignMatches = [...content.matchAll(/knownBenign:\s*\[(.*?)\]/gs)];
  for (const match of benignMatches) {
      const items = match[1].match(/(['"`])(.*?)\1/g);
      if (!items || items.length < 3) {
         console.log(`LAW 1: knownBenign has fewer than 3 entries (${items ? items.length : 0}) in ${file}`);
      }
  }
});
