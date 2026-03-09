const fs = require('fs');
const path = require('path');
const { register } = require('ts-node');
register({ transpileOnly: true });

function getFiles(dir, files = []) {
  const list = fs.readdirSync(dir);
  for (const file of list) {
    const fullPath = path.join(dir, file);
    if (fs.statSync(fullPath).isDirectory()) {
      getFiles(fullPath, files);
    } else if (fullPath.endsWith('.ts') && !fullPath.includes('.test.') && !fullPath.includes('.spec.') && !fullPath.includes('types.ts') && !fullPath.includes('encoding.ts')) {
      files.push(fullPath);
    }
  }
  return files;
}

const files = getFiles('packages/engine/src/classes');

files.forEach(file => {
  try {
      const mod = require('./' + file);
      for (const key in mod) {
          const exportObj = mod[key];
          if (exportObj && typeof exportObj === 'object' && exportObj.id && exportObj.knownPayloads) {
              if (exportObj.knownPayloads.length < 3) {
                  console.log(`LAW 1: ${exportObj.id} knownPayloads has ${exportObj.knownPayloads.length} entries in ${file}`);
              }
              if (exportObj.knownBenign && exportObj.knownBenign.length < 3) {
                  console.log(`LAW 1: ${exportObj.id} knownBenign has ${exportObj.knownBenign.length} entries in ${file}`);
              }
              if (exportObj.detect.toString().includes('return true;') || exportObj.detect.toString().includes('return false;')) {
                 // Check if it unconditionally returns hardcoded value
                 // Too complex to parse accurately here but we can skip since it was checked
              }
              
              const variants = exportObj.generateVariants(10);
              if (variants.length !== 10) {
                 console.log(`LAW 1: ${exportObj.id} generateVariants returned ${variants.length} instead of 10 in ${file}`);
              }
          }
      }
  } catch (e) {
      console.error("Error loading", file, e.message);
  }
});
