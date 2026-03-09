import { createRequire } from 'node:module';
import type { Severity } from './classes/types.js';

const require = createRequire(import.meta.url);

let Parser: any;
let tsLang: any;
let jsLang: any;
let treeSitterLoaded = false;

try {
    Parser = require('tree-sitter');
    tsLang = require('tree-sitter-typescript').typescript;
    jsLang = require('tree-sitter-javascript');
    treeSitterLoaded = true;
} catch (e) {
    // Handle MODULE_NOT_FOUND or build errors gracefully
    treeSitterLoaded = false;
}

export interface AstFinding {
    ruleId: string;
    filePath: string;
    line: number;
    column: number;
    source: string;
    sink: string;
    taintPath: string[];
    confidence: number;
    severity: Severity;
}

export class AstScanner {
    private parser: any = null;

    constructor() {
        if (treeSitterLoaded && Parser) {
            try {
                this.parser = new Parser();
            } catch (e) {
                this.parser = null;
            }
        }
    }

    public getLanguageForFile(filePath: string): 'javascript' | 'typescript' | null {
        if (/\.tsx?$/i.test(filePath)) return 'typescript';
        if (/\.[mc]?jsx?$/i.test(filePath)) return 'javascript';
        return null;
    }

    public scanFile(filePath: string, sourceCode: string, language: 'javascript' | 'typescript'): AstFinding[] {
        if (!this.parser || !treeSitterLoaded) return [];

        try {
            if (language === 'typescript' && tsLang) {
                this.parser.setLanguage(tsLang);
            } else if (language === 'javascript' && jsLang) {
                this.parser.setLanguage(jsLang);
            } else {
                return [];
            }
        } catch (e) {
            return [];
        }

        let tree;
        try {
            tree = this.parser.parse(sourceCode);
        } catch (e) {
            return [];
        }

        const findings: AstFinding[] = [];
        
        // Map of variable names to their origin source and taint path
        const taintedVars = new Map<string, { source: string; path: string[] }>();

        const getSourceFromNode = (node: any): string | null => {
            if (!node) return null;
            const text = node.text;
            if (/^(req|request|ctx\.request)\.(query|body|params|headers)\b/.test(text)) return 'http_request_input';
            if (/^process\.env\b/.test(text)) return 'process_env';
            if (text.includes('JSON.parse') && text.includes('userInput')) return 'json_parse_input';
            
            if (node.type === 'identifier') {
                if (taintedVars.has(text)) {
                    return taintedVars.get(text)!.source;
                }
            }
            
            if (node.type === 'binary_expression' || node.type === 'template_string' || node.type === 'call_expression') {
                for (let i = 0; i < node.childCount; i++) {
                    const child = node.child(i);
                    const childSource = getSourceFromNode(child);
                    if (childSource) return childSource;
                }
            }

            if (node.type === 'member_expression') {
                const objectNode = node.childForFieldName('object') || node.children[0];
                if (objectNode) {
                    const baseSource = getSourceFromNode(objectNode);
                    if (baseSource) return baseSource;
                }
            }

            return null;
        };

        const getTaintPathFromNode = (node: any): string[] => {
            if (!node) return [];
            const text = node.text;
            if (node.type === 'identifier' && taintedVars.has(text)) {
                return [...taintedVars.get(text)!.path, text];
            }
            for (let i = 0; i < node.childCount; i++) {
                const childPath = getTaintPathFromNode(node.child(i));
                if (childPath.length > 0) return childPath;
            }
            return [];
        };

        const isSink = (node: any): { sink: string, category: string, severity: Severity } | null => {
            if (node.type !== 'call_expression' && node.type !== 'assignment_expression') return null;

            let targetText = '';
            if (node.type === 'call_expression') {
                const funcNode = node.childForFieldName('function') || node.children[0];
                if (funcNode) targetText = funcNode.text;
            } else if (node.type === 'assignment_expression') {
                const leftNode = node.childForFieldName('left') || node.children[0];
                if (leftNode) targetText = leftNode.text;
            }

            if (!targetText) return null;

            if (/\b(?:child_process\.)?(?:exec|spawn)\b/.test(targetText)) return { sink: 'child_process.exec/spawn', category: 'command_injection', severity: 'critical' };
            if (targetText === 'eval') return { sink: 'eval', category: 'command_injection', severity: 'critical' };
            if (targetText === 'Function') return { sink: 'Function()', category: 'command_injection', severity: 'critical' };
            if (/\b(?:db|connection|pool|sequelize|knex)\.(?:query|execute|raw)\b/.test(targetText)) return { sink: 'db.query/execute', category: 'sqli', severity: 'high' };
            if (/\bfs\.(?:readFile|writeFile|readFileSync|writeFileSync)\b/.test(targetText)) return { sink: 'fs.readFile/writeFile', category: 'path_traversal', severity: 'high' };
            if (/\b(?:fetch|http\.request|https\.request|axios\.(?:get|post))\b/.test(targetText)) return { sink: 'fetch/http.request', category: 'ssrf', severity: 'high' };
            if (/\bres\.setHeader\b/.test(targetText)) return { sink: 'res.setHeader', category: 'xss', severity: 'medium' };
            if (/\b(?:document\.)?innerHTML\b/.test(targetText)) return { sink: 'document.innerHTML', category: 'xss', severity: 'high' };

            return null;
        };

        const traverse = (node: any) => {
            if (node.type === 'variable_declarator') {
                const nameNode = node.childForFieldName('name');
                const valueNode = node.childForFieldName('value');
                if (nameNode && valueNode) {
                    const source = getSourceFromNode(valueNode);
                    if (source) {
                        const path = getTaintPathFromNode(valueNode);
                        taintedVars.set(nameNode.text, { source, path: [...path, nameNode.text] });
                    }
                }
            } else if (node.type === 'assignment_expression') {
                const leftNode = node.childForFieldName('left');
                const rightNode = node.childForFieldName('right');
                if (leftNode && rightNode) {
                    const source = getSourceFromNode(rightNode);
                    if (source) {
                        const path = getTaintPathFromNode(rightNode);
                        taintedVars.set(leftNode.text, { source, path: [...path, leftNode.text] });
                    }
                }
            }

            const sinkMatch = isSink(node);
            if (sinkMatch) {
                if (node.type === 'call_expression') {
                    const argsNode = node.childForFieldName('arguments');
                    if (argsNode) {
                        for (let i = 0; i < argsNode.childCount; i++) {
                            const arg = argsNode.child(i);
                            const source = getSourceFromNode(arg);
                            if (source) {
                                const path = getTaintPathFromNode(arg);
                                findings.push({
                                    ruleId: `${sinkMatch.category}.ast_taint`,
                                    filePath,
                                    line: node.startPosition.row + 1,
                                    column: node.startPosition.column + 1,
                                    source,
                                    sink: sinkMatch.sink,
                                    taintPath: path,
                                    confidence: 0.85,
                                    severity: sinkMatch.severity
                                });
                                break;
                            }
                        }
                    }
                } else if (node.type === 'assignment_expression') {
                    const rightNode = node.childForFieldName('right');
                    if (rightNode) {
                        const source = getSourceFromNode(rightNode);
                        if (source) {
                            const path = getTaintPathFromNode(rightNode);
                            findings.push({
                                ruleId: `${sinkMatch.category}.ast_taint`,
                                filePath,
                                line: node.startPosition.row + 1,
                                column: node.startPosition.column + 1,
                                source,
                                sink: sinkMatch.sink,
                                taintPath: path,
                                confidence: 0.85,
                                severity: sinkMatch.severity
                            });
                        }
                    }
                }
            }

            for (let i = 0; i < node.childCount; i++) {
                traverse(node.child(i));
            }
        };

        traverse(tree.rootNode);

        return findings;
    }
}
