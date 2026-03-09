import { InvariantEngine } from './packages/engine/src/invariant-engine.js'
import { loadRulesFromJson, compileRule, addCustomRules } from './packages/engine/src/rule-format.js'
import * as fs from 'fs'

const engine = new InvariantEngine()
const str = fs.readFileSync('./rules/apache-struts.rule.json', 'utf8')
const rules = loadRulesFromJson(str)
console.log('Parsed rules:', rules)
const plugin = compileRule(rules[0])
const detect = plugin.classes[0].detect
console.log('detect returns:', detect('Content-Type: %{#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS}'))
addCustomRules(rules, engine)
const res = engine.detectDeep('Content-Type: %{#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS}', [])
console.log('Engine matches:', res.matches.map(m => m.class))
