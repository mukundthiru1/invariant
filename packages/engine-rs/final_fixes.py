import re

# 1. Fix src/lib.rs (remove duplicates of pub mod class_registry;)
with open('src/lib.rs', 'r') as f:
    lines = f.readlines()
with open('src/lib.rs', 'w') as f:
    found = False
    for line in lines:
        if line.strip() == 'pub mod class_registry;':
            if found:
                continue
            found = True
        f.write(line)

# 2. Add l3 to DetectionLevels and l3_surfaces to AnalysisResult in src/types.rs
with open('src/types.rs', 'r') as f:
    t = f.read()

t = t.replace(
    'pub l2: bool,\n    /// L1 and L2 both fired for the same class.',
    'pub l2: bool,\n    /// L3 surface decomposer fired.\n    pub l3: bool,\n    /// L1 and L2 both fired for the same class.'
)
t = t.replace(
    'l1: false,\n            l2: false,\n            convergent: false,',
    'l1: false,\n            l2: false,\n            l3: false,\n            convergent: false,'
)

t = t.replace(
    'pub intent: Option<IntentClassification>,\n}',
    'pub intent: Option<IntentClassification>,\n    /// Optional L3 surface tracking.\n    pub l3_surfaces: Option<Vec<String>>,\n}'
)
t = t.replace(
    'encoding_evasion: false,\n            intent: None,\n        }',
    'encoding_evasion: false,\n            intent: None,\n            l3_surfaces: None,\n        }'
)

# 3. Add severity_weight, attack_category, mitre_tactic if missing
# Let's find out if they are missing
if "pub fn severity_weight(self) -> f64 {" not in t:
    t = t.replace('impl InvariantClass {', '''impl InvariantClass {
    pub fn severity_weight(self) -> f64 {
        crate::class_registry::severity_for(self)
    }

    pub fn attack_category(self) -> AttackCategory {
        crate::class_registry::attack_category_for(self)
    }

    pub fn mitre_tactic(self) -> crate::mitre::MitreTactic {
        crate::class_registry::mitre_for(self).1
    }
''')

# 4. Generate ALL_CLASSES in src/class_registry.rs
# We will just map the 85 variants from master.
with open('src/class_registry.rs', 'r') as f:
    cr = f.read()

# We need ALL_CLASSES. We can extract it from ALL_CLASS_METADATA
m_variants = re.findall(r'class: (InvariantClass::\w+),', cr)
all_c_array = "pub const ALL_CLASSES: &[InvariantClass] = &[\n" + ",\n".join("    " + v for v in m_variants) + "\n];"
if "pub const ALL_CLASSES" not in cr:
    cr = cr.replace('pub static ALL_CLASS_METADATA', all_c_array + '\n\npub static ALL_CLASS_METADATA')

cr = cr.replace('InvariantClass::all_variants()', 'ALL_CLASSES')

with open('src/class_registry.rs', 'w') as f:
    f.write(cr)

# 5. Fix compliance tests to use ALL_CLASSES from class_registry
with open('src/compliance.rs', 'r') as f:
    comp = f.read()
comp = comp.replace('InvariantClass::all_variants()', 'crate::class_registry::ALL_CLASSES')
with open('src/compliance.rs', 'w') as f:
    f.write(comp)

# Also make sure types.rs default_severity is there, it was there but we had `let w = self.severity_weight()`.
# since we added severity_weight back, it will compile!
with open('src/types.rs', 'w') as f:
    f.write(t)
