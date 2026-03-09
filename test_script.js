const fs = require('fs');

function stripSqlComments(sql) {
    return sql
        .replace(/\/\*[\s\S]*?\*\//g, ' ')   // block comments /*...*/
        .replace(/--[^\n]*/g, ' ')              // line comments --...
        .replace(/\s+/g, ' ').trim()
}

function deepDecode(input, depth = 0) {
    if (depth > 4) return input
    let decoded = input
    try {
        const urlDecoded = decodeURIComponent(decoded)
        if (urlDecoded !== decoded) decoded = deepDecode(urlDecoded, depth + 1)
    } catch (e) { /* invalid encoding */ }
    decoded = decoded
        .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#(\d+);?/g, (_, dec) => String.fromCharCode(parseInt(dec)))
        .replace(/&quot;/gi, '"').replace(/&apos;/gi, "'")
        .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&amp;/gi, '&')
    decoded = decoded.replace(/\\u([0-9a-f]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    decoded = decoded.replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    decoded = decoded.replace(/\/\*.*?\*\//g, ' ')
    return decoded
}

function testStacked(input) {
    const d = stripSqlComments(deepDecode(input));
    const match = /;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|CALL|UNION|WITH)\b/i.test(d);
    console.log("Stacked:", input, "=>", d, "=>", match);
}

function testTautology(input) {
    const d = stripSqlComments(deepDecode(input));
    const match1 = /['"`)\s]\s*(?:OR|\|\|)\s*(?:['"`]?\w+['"`]?\s*(?:=|LIKE|IS)\s*['"`]?\w+['"`]?|\d+\s*[><= ]+\s*\d+|TRUE|NOT\s+FALSE|NOT\s+0|1\b)/i.test(d)
    const match2 = /['"]([^'"]*)['"]\s*=\s*['"]\1['"]/.test(d)
    const match3 = /0x[0-9a-fA-F]+\s*=\s*0x[0-9a-fA-F]+/.test(d)
    console.log("Tautology:", input, "=>", d, "=>", match1 || match2 || match3);
}

testStacked("; SELECT * FROM users--");
testStacked("; UNION SELECT 1,2,3--");
testStacked("; WITH cte AS (SELECT 1) SELECT * FROM cte");
testTautology("'--\nOR--\n1=1");
testTautology("'/**/OR--\n1=1");

