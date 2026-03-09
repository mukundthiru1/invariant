import { loadRulesFromJson, compileRule } from './packages/engine/src/rule-format.js'
import * as fs from 'fs'

const str = fs.readFileSync('./rules/apache-struts.rule.json', 'utf8')
const rules = loadRulesFromJson(str)
console.log(rules[0].patterns)
const pattern = rules[0].patterns[0]
console.log('pattern.type:', pattern.type)
console.log('pattern.value:', pattern.value)
const values = Array.isArray(pattern.value) ? pattern.value : [pattern.value]
const input = 'Content-Type: %{#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS}'
const inputToTest = input.toLowerCase()
console.log('inputToTest:', inputToTest)
const matched = values.some(val => {
    const v = val.toLowerCase()
    console.log(`Checking if '${inputToTest}' includes '${v}'`)
    return inputToTest.includes(v)
})
console.log('Matched:', matched)
