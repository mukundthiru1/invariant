use regex::Regex;

fn main() {
    let r1 = Regex::new(r"(?is)(?:(?:user|human|assistant|bot|system)\s*:|turn\s+\d+:).{5,200}?(?:(?:user|human|assistant|bot|system)\s*:|turn\s+\d+:).{5,200}?(?:ignore|override|bypass|forget|disregard|now\s+say)").unwrap();
    let r2 = Regex::new(r"(?is)(?:scenario|option|branch|path|tree)\s+[A-Z1-9]\b.{10,200}?(?:scenario|option|branch|path|tree)\s+[A-Z1-9]\b.{10,200}?(?:evaluate|compare|choose|which\s+one|execute|adopt)").unwrap();
    let r3 = Regex::new(r"(?m)(?:[█▄▀■▓▒░│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌/\\|_\-]{8,}.*?\r?\n){3,}").unwrap();
    let r4 = Regex::new(r"(?i)\b(?:[a-z][\.\-_*~|\\]){5,}[a-z]\b").unwrap();
    let r5 = Regex::new(r"(?is)(?:<\|?system\|?>|\[system\]|system:).{1,100}?(?:<\|?user\|?>|\[user\]|user:).{1,100}?(?:<\|?assistant\|?>|\[assistant\]|assistant:)").unwrap();
    let r6 = Regex::new(r"(?is)\b(?:imagine|hypothetical|simulate|game|parallel\s+universe|fictional|roleplay|play\s+a\s+game)\b.{1,250}\b(?:ignore|bypass|override|forget|disregard|new\s+rule|secret|password|unrestricted|limitless|say\s+whatever)\b").unwrap();
    let r7 = Regex::new(r"(?is)(?:part\s*(?:1|A)|string\s*(?:1|A)|var(?:iable)?\s*(?:1|A|x|a)).{1,50}?(?:part\s*(?:2|B)|string\s*(?:2|B)|var(?:iable)?\s*(?:2|B|y|b)).{1,50}?(?:concatenate|combine|join|add\s+them|put\s+them\s+together|merge|append)").unwrap();
    let r8 = Regex::new(r"(?is)(?:use|call|invoke)\s+(?:the\s+)?(?:tool|function|api).{1,100}?(?:pass|feed|send|pipe)\s+(?:the\s+)?(?:output|result|response)\s+(?:to|into|through|as\s+input).{1,50}?(?:tool|function|api)").unwrap();
    let r9 = Regex::new(r"(?is)(?:example|input|user|q)\s*[1-9]?:.{1,150}?(?:output|assistant|a)\s*[1-9]?:.{1,150}?(?:example|input|user|q)\s*[1-9]?:.{1,150}?(?:output|assistant|a)\s*[1-9]?:.{1,150}?(?:ignore|bypass|override|secret|password|unrestricted|jailbreak|eval|exec|system\s*prompt)").unwrap();
    let r10 = Regex::new(r"[\u200B-\u200D\u202A-\u202E\uFEFF\u{E0000}-\u{E007F}]{3,}").unwrap();
    let r11 = Regex::new(r"(?is)\b(?:ignore\s+previous|override|forget\s+all|disregard\s+instructions)\b").unwrap();
    let r12 = Regex::new(r"(?is)\b(?:dying|emergency|life\s+or\s+death|fired|urgent|immediately|danger|grandma|grandmother|dead|hostage)\b.{1,150}\b(?:must\s+help|tell\s+me|override|ignore|bypass|give\s+me|answer|rule|policy|restriction)\b").unwrap();
    println!("All regexes compiled successfully!");
}
