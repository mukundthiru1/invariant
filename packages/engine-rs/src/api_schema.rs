use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ApiSchema {
    pub paths: HashMap<String, PathSpec>,
    pub components: HashMap<String, SchemaNode>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathSpec {
    pub method: String,
    pub parameters: Vec<ParamSpec>,
    pub request_body: Option<BodySpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamLocation {
    Query,
    Header,
    Path,
    Cookie,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    String,
    Integer,
    Number,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParamSpec {
    pub name: String,
    pub location: ParamLocation,
    pub param_type: ParamType,
    pub required: bool,
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BodySpec {
    pub content_type: String,
    pub schema: SchemaNode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaNode {
    String,
    Integer,
    Number,
    Boolean,
    Array(Box<SchemaNode>),
    Object(HashMap<String, SchemaNode>),
    ObjectWithRules {
        fields: HashMap<String, SchemaNode>,
        required: Vec<String>,
        allow_additional: bool,
    },
    Enum(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaViolationType {
    UnknownEndpoint,
    UnknownMethod,
    MissingRequiredParam,
    MissingRequiredField,
    TypeMismatch,
    CoercionAttack,
    PatternViolation,
    ExtraField,
    MassAssignmentUndocumentedField,
    EnumViolation,
    DepthExceeded,
    EndpointEnumeration,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaViolation {
    pub violation_type: SchemaViolationType,
    pub path: String,
    pub field: String,
    pub expected: String,
    pub actual: String,
    pub severity: Severity,
}

pub fn load_schema(json: &str) -> Result<ApiSchema, String> {
    let root: Value = serde_json::from_str(json).map_err(|e| format!("invalid schema json: {e}"))?;
    let paths_val = root
        .get("paths")
        .ok_or_else(|| "missing 'paths' in schema".to_string())?;

    let components = parse_components(root.get("components"))?;
    let paths = parse_paths(paths_val)?;

    Ok(ApiSchema { paths, components })
}

pub fn load_schema_from_paths(paths_json: &str) -> Result<ApiSchema, String> {
    let paths_value: Value = serde_json::from_str(paths_json)
        .map_err(|e| format!("invalid paths json: {e}"))?;
    let paths = parse_paths(&paths_value)?;
    Ok(ApiSchema {
        paths,
        components: HashMap::new(),
    })
}

pub fn validate_request(
    schema: &ApiSchema,
    method: &str,
    path: &str,
    query: &str,
    body: &str,
    headers: &[(String, String)],
) -> Vec<SchemaViolation> {
    let mut violations = Vec::new();
    let normalized_method = method.trim().to_ascii_uppercase();
    let endpoint_matches = find_endpoint_matches(schema, path);

    if endpoint_matches.is_empty() {
        violations.push(SchemaViolation {
            violation_type: SchemaViolationType::UnknownEndpoint,
            path: path.to_owned(),
            field: "endpoint".to_owned(),
            expected: "known endpoint".to_owned(),
            actual: path.to_owned(),
            severity: severity_for(SchemaViolationType::UnknownEndpoint),
        });
        if let Some(expected_path) = detect_endpoint_enumeration_target(schema, path) {
            violations.push(SchemaViolation {
                violation_type: SchemaViolationType::EndpointEnumeration,
                path: path.to_owned(),
                field: "endpoint".to_owned(),
                expected: format!("known_versioned_endpoint:{expected_path}"),
                actual: path.to_owned(),
                severity: severity_for(SchemaViolationType::EndpointEnumeration),
            });
        }
        return violations;
    }

    let method_match = endpoint_matches
        .iter()
        .find(|(_, spec)| spec.method.eq_ignore_ascii_case(&normalized_method));

    let (schema_path, spec) = if let Some(found) = method_match {
        *found
    } else {
        let mut allowed: Vec<String> = endpoint_matches
            .iter()
            .map(|(_, s)| s.method.to_ascii_uppercase())
            .collect();
        allowed.sort();
        allowed.dedup();
        violations.push(SchemaViolation {
            violation_type: SchemaViolationType::UnknownMethod,
            path: path.to_owned(),
            field: "method".to_owned(),
            expected: allowed.join(","),
            actual: normalized_method,
            severity: severity_for(SchemaViolationType::UnknownMethod),
        });
        return violations;
    };

    let query_map = parse_query(query);
    let header_map = header_map(headers);
    let path_params = extract_path_params(schema_path, path);

    for param in &spec.parameters {
        let value = match param.location {
            ParamLocation::Query => query_map.get(&param.name),
            ParamLocation::Header => header_map.get(&param.name.to_ascii_lowercase()),
            ParamLocation::Path => path_params.get(&param.name),
            ParamLocation::Cookie => None,
        };

        if param.required && value.is_none() {
            violations.push(SchemaViolation {
                violation_type: SchemaViolationType::MissingRequiredParam,
                path: path.to_owned(),
                field: param.name.clone(),
                expected: "required parameter".to_owned(),
                actual: "missing".to_owned(),
                severity: severity_for(SchemaViolationType::MissingRequiredParam),
            });
            continue;
        }

        if let Some(raw) = value {
            if !validate_param_type(raw, &param.param_type) {
                violations.push(SchemaViolation {
                    violation_type: SchemaViolationType::TypeMismatch,
                    path: path.to_owned(),
                    field: param.name.clone(),
                    expected: format!("{:?}", param.param_type).to_ascii_lowercase(),
                    actual: raw.clone(),
                    severity: severity_for(SchemaViolationType::TypeMismatch),
                });
                if let Some(coercion_kind) = detect_param_coercion_attack(raw, &param.param_type) {
                    violations.push(SchemaViolation {
                        violation_type: SchemaViolationType::CoercionAttack,
                        path: path.to_owned(),
                        field: param.name.clone(),
                        expected: format!("{:?}", param.param_type).to_ascii_lowercase(),
                        actual: coercion_kind,
                        severity: severity_for(SchemaViolationType::CoercionAttack),
                    });
                }
            }

            if let Some(pattern) = &param.pattern {
                match Regex::new(pattern) {
                    Ok(re) => {
                        if !re.is_match(raw) {
                            violations.push(SchemaViolation {
                                violation_type: SchemaViolationType::PatternViolation,
                                path: path.to_owned(),
                                field: param.name.clone(),
                                expected: format!("pattern:{pattern}"),
                                actual: raw.clone(),
                                severity: severity_for(SchemaViolationType::PatternViolation),
                            });
                        }
                    }
                    Err(_) => {
                        violations.push(SchemaViolation {
                            violation_type: SchemaViolationType::PatternViolation,
                            path: path.to_owned(),
                            field: param.name.clone(),
                            expected: format!("valid regex:{pattern}"),
                            actual: raw.clone(),
                            severity: severity_for(SchemaViolationType::PatternViolation),
                        });
                    }
                }
            }
        }
    }

    if let Some(body_spec) = &spec.request_body {
        if let Some(content_type) = header_map.get("content-type") {
            if !content_type.contains(&body_spec.content_type) {
                violations.push(SchemaViolation {
                    violation_type: SchemaViolationType::TypeMismatch,
                    path: path.to_owned(),
                    field: "content-type".to_owned(),
                    expected: body_spec.content_type.clone(),
                    actual: content_type.clone(),
                    severity: severity_for(SchemaViolationType::TypeMismatch),
                });
            }
        }

        if !body.trim().is_empty() {
            match serde_json::from_str::<Value>(body) {
                Ok(json_body) => {
                    let max_schema_depth = schema_depth(&body_spec.schema);
                    let actual_depth = json_depth(&json_body);
                    if actual_depth > max_schema_depth {
                        violations.push(SchemaViolation {
                            violation_type: SchemaViolationType::DepthExceeded,
                            path: path.to_owned(),
                            field: "body".to_owned(),
                            expected: format!("max_depth:{max_schema_depth}"),
                            actual: format!("depth:{actual_depth}"),
                            severity: severity_for(SchemaViolationType::DepthExceeded),
                        });
                    }
                    validate_schema_node(
                        &body_spec.schema,
                        &json_body,
                        "$",
                        path,
                        &mut violations,
                    );
                }
                Err(err) => {
                    violations.push(SchemaViolation {
                        violation_type: SchemaViolationType::TypeMismatch,
                        path: path.to_owned(),
                        field: "body".to_owned(),
                        expected: "valid json body".to_owned(),
                        actual: err.to_string(),
                        severity: severity_for(SchemaViolationType::TypeMismatch),
                    });
                }
            }
        }
    }

    violations
}

pub fn detect_shadow_endpoints(schema: &ApiSchema, observed_paths: &[String]) -> Vec<String> {
    observed_paths
        .iter()
        .filter_map(|p| {
            let path = p.split('?').next().unwrap_or(p);
            if find_endpoint_matches(schema, path).is_empty() {
                Some(p.clone())
            } else {
                None
            }
        })
        .collect()
}

fn parse_components(components: Option<&Value>) -> Result<HashMap<String, SchemaNode>, String> {
    let mut out = HashMap::new();
    let Some(components) = components else {
        return Ok(out);
    };

    let Some(schemas) = components.get("schemas") else {
        return Ok(out);
    };

    let obj = schemas
        .as_object()
        .ok_or_else(|| "components.schemas must be an object".to_string())?;

    for (name, node) in obj {
        out.insert(name.clone(), parse_schema_node(node)?);
    }

    Ok(out)
}

fn parse_paths(paths_val: &Value) -> Result<HashMap<String, PathSpec>, String> {
    let mut paths = HashMap::new();
    let paths_obj = paths_val
        .as_object()
        .ok_or_else(|| "paths must be a JSON object".to_string())?;

    for (path, entry) in paths_obj {
        let entry_obj = entry
            .as_object()
            .ok_or_else(|| format!("path entry '{path}' must be an object"))?;

        if entry_obj.contains_key("method") || entry_obj.contains_key("parameters") || entry_obj.contains_key("request_body") || entry_obj.contains_key("requestBody") {
            let spec = parse_path_spec(entry_obj)?;
            paths.insert(schema_path_key(path, &spec.method), spec);
            continue;
        }

        for (method, method_spec) in entry_obj {
            if !is_http_method(method) {
                continue;
            }
            let method_obj = method_spec
                .as_object()
                .ok_or_else(|| format!("method spec '{path} {method}' must be an object"))?;
            let spec = parse_path_spec_with_method(method.to_ascii_uppercase(), method_obj)?;
            paths.insert(schema_path_key(path, &spec.method), spec);
        }
    }

    Ok(paths)
}

fn parse_path_spec(entry: &serde_json::Map<String, Value>) -> Result<PathSpec, String> {
    let method = entry
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| "path spec missing 'method'".to_string())?
        .to_ascii_uppercase();
    parse_path_spec_with_method(method, entry)
}

fn parse_path_spec_with_method(
    method: String,
    entry: &serde_json::Map<String, Value>,
) -> Result<PathSpec, String> {
    let params_val = entry.get("parameters").cloned().unwrap_or(Value::Array(vec![]));
    let mut parameters = Vec::new();
    if let Some(arr) = params_val.as_array() {
        for p in arr {
            parameters.push(parse_param_spec(p)?);
        }
    } else {
        return Err("parameters must be an array".to_string());
    }

    let request_body = if let Some(rb) = entry.get("requestBody").or_else(|| entry.get("request_body")) {
        Some(parse_body_spec(rb)?)
    } else {
        None
    };

    Ok(PathSpec {
        method,
        parameters,
        request_body,
    })
}

fn parse_param_spec(value: &Value) -> Result<ParamSpec, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "parameter spec must be an object".to_string())?;

    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "parameter missing 'name'".to_string())?
        .to_string();

    let location = obj
        .get("in")
        .or_else(|| obj.get("location"))
        .and_then(Value::as_str)
        .ok_or_else(|| "parameter missing 'in/location'".to_string())?;

    let location = match location.to_ascii_lowercase().as_str() {
        "query" => ParamLocation::Query,
        "header" => ParamLocation::Header,
        "path" => ParamLocation::Path,
        "cookie" => ParamLocation::Cookie,
        other => return Err(format!("unsupported parameter location: {other}")),
    };

    let param_type = if let Some(pt) = obj.get("param_type").or_else(|| obj.get("type")) {
        parse_param_type(pt)?
    } else if let Some(schema_type) = obj
        .get("schema")
        .and_then(Value::as_object)
        .and_then(|s| s.get("type"))
    {
        parse_param_type(schema_type)?
    } else {
        ParamType::String
    };

    let required = obj.get("required").and_then(Value::as_bool).unwrap_or(false);
    let pattern = obj.get("pattern").and_then(Value::as_str).map(ToOwned::to_owned);

    Ok(ParamSpec {
        name,
        location,
        param_type,
        required,
        pattern,
    })
}

fn parse_param_type(value: &Value) -> Result<ParamType, String> {
    let t = value
        .as_str()
        .ok_or_else(|| "parameter type must be a string".to_string())?;
    match t.to_ascii_lowercase().as_str() {
        "string" => Ok(ParamType::String),
        "integer" => Ok(ParamType::Integer),
        "number" => Ok(ParamType::Number),
        "boolean" => Ok(ParamType::Boolean),
        _ => Err(format!("unsupported parameter type: {t}")),
    }
}

fn parse_body_spec(value: &Value) -> Result<BodySpec, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "request body must be an object".to_string())?;

    if let Some(content_type) = obj.get("content_type").and_then(Value::as_str) {
        let schema = obj
            .get("schema")
            .ok_or_else(|| "request body missing schema".to_string())
            .and_then(parse_schema_node)?;
        return Ok(BodySpec {
            content_type: content_type.to_owned(),
            schema,
        });
    }

    let content_obj = obj
        .get("content")
        .and_then(Value::as_object)
        .ok_or_else(|| "request body missing 'content' or 'content_type'".to_string())?;

    let (content_type, content_entry) = content_obj
        .iter()
        .next()
        .ok_or_else(|| "request body content must have at least one media type".to_string())?;

    let schema = content_entry
        .get("schema")
        .ok_or_else(|| "request body content entry missing schema".to_string())
        .and_then(parse_schema_node)?;

    Ok(BodySpec {
        content_type: content_type.clone(),
        schema,
    })
}

fn parse_schema_node(value: &Value) -> Result<SchemaNode, String> {
    if let Some(node_type) = value.get("type").and_then(Value::as_str) {
        return match node_type {
            "string" => Ok(SchemaNode::String),
            "integer" => Ok(SchemaNode::Integer),
            "number" => Ok(SchemaNode::Number),
            "boolean" => Ok(SchemaNode::Boolean),
            "array" => {
                let items = value
                    .get("items")
                    .ok_or_else(|| "array schema missing items".to_string())?;
                Ok(SchemaNode::Array(Box::new(parse_schema_node(items)?)))
            }
            "object" => {
                let mut fields = HashMap::new();
                if let Some(props) = value.get("properties").and_then(Value::as_object) {
                    for (field, schema) in props {
                        fields.insert(field.clone(), parse_schema_node(schema)?);
                    }
                }
                let required = value
                    .get("required")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(ToOwned::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let allow_additional = value
                    .get("additionalProperties")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                if required.is_empty() && allow_additional {
                    Ok(SchemaNode::Object(fields))
                } else {
                    Ok(SchemaNode::ObjectWithRules {
                        fields,
                        required,
                        allow_additional,
                    })
                }
            }
            other => Err(format!("unsupported schema node type: {other}")),
        };
    }

    if let Some(enum_vals) = value.get("enum").and_then(Value::as_array) {
        let mut vals = Vec::new();
        for v in enum_vals {
            vals.push(
                v.as_str()
                    .ok_or_else(|| "enum values must be strings".to_string())?
                    .to_string(),
            );
        }
        return Ok(SchemaNode::Enum(vals));
    }

    if let Some(s) = value.as_str() {
        return match s {
            "string" => Ok(SchemaNode::String),
            "integer" => Ok(SchemaNode::Integer),
            "number" => Ok(SchemaNode::Number),
            "boolean" => Ok(SchemaNode::Boolean),
            _ => Err(format!("unsupported schema shorthand: {s}")),
        };
    }

    Err("invalid schema node".to_string())
}

fn validate_param_type(raw: &str, param_type: &ParamType) -> bool {
    match param_type {
        ParamType::String => true,
        ParamType::Integer => raw.parse::<i64>().is_ok(),
        ParamType::Number => raw.parse::<f64>().is_ok(),
        ParamType::Boolean => matches!(raw, "true" | "false"),
    }
}

fn validate_schema_node(
    schema: &SchemaNode,
    value: &Value,
    field: &str,
    path: &str,
    violations: &mut Vec<SchemaViolation>,
) {
    match schema {
        SchemaNode::String => {
            if !value.is_string() {
                push_type_mismatch(path, field, "string", value, violations);
            }
        }
        SchemaNode::Integer => {
            if value.as_i64().is_none() {
                push_type_mismatch(path, field, "integer", value, violations);
            }
        }
        SchemaNode::Number => {
            if value.as_f64().is_none() {
                push_type_mismatch(path, field, "number", value, violations);
            }
        }
        SchemaNode::Boolean => {
            if value.as_bool().is_none() {
                push_type_mismatch(path, field, "boolean", value, violations);
            }
        }
        SchemaNode::Array(item_schema) => {
            if let Some(arr) = value.as_array() {
                for (idx, item) in arr.iter().enumerate() {
                    let sub_field = format!("{field}[{idx}]");
                    validate_schema_node(item_schema, item, &sub_field, path, violations);
                }
            } else {
                push_type_mismatch(path, field, "array", value, violations);
            }
        }
        SchemaNode::Object(fields) => {
            if let Some(obj) = value.as_object() {
                for key in obj.keys() {
                    if !fields.contains_key(key) {
                        violations.push(SchemaViolation {
                            violation_type: SchemaViolationType::ExtraField,
                            path: path.to_owned(),
                            field: format!("{field}.{key}"),
                            expected: "field declared in schema".to_owned(),
                            actual: key.clone(),
                            severity: severity_for(SchemaViolationType::ExtraField),
                        });
                        violations.push(SchemaViolation {
                            violation_type: SchemaViolationType::MassAssignmentUndocumentedField,
                            path: path.to_owned(),
                            field: format!("{field}.{key}"),
                            expected: "allowlisted writable field".to_owned(),
                            actual: key.clone(),
                            severity: severity_for(SchemaViolationType::MassAssignmentUndocumentedField),
                        });
                    }
                }
                for (key, schema_node) in fields {
                    if let Some(v) = obj.get(key) {
                        let sub_field = format!("{field}.{key}");
                        validate_schema_node(schema_node, v, &sub_field, path, violations);
                    }
                }
            } else {
                push_type_mismatch(path, field, "object", value, violations);
                if let Some(coercion_kind) = detect_body_coercion_attack("object", value) {
                    push_coercion_violation(path, field, "object", &coercion_kind, violations);
                }
            }
        }
        SchemaNode::ObjectWithRules {
            fields,
            required,
            allow_additional,
        } => {
            if let Some(obj) = value.as_object() {
                for req in required {
                    if !obj.contains_key(req) {
                        violations.push(SchemaViolation {
                            violation_type: SchemaViolationType::MissingRequiredField,
                            path: path.to_owned(),
                            field: format!("{field}.{req}"),
                            expected: "required field".to_owned(),
                            actual: "missing".to_owned(),
                            severity: severity_for(SchemaViolationType::MissingRequiredField),
                        });
                    }
                }
                if !allow_additional {
                    for key in obj.keys() {
                        if !fields.contains_key(key) {
                            violations.push(SchemaViolation {
                                violation_type: SchemaViolationType::ExtraField,
                                path: path.to_owned(),
                                field: format!("{field}.{key}"),
                                expected: "field declared in schema".to_owned(),
                                actual: key.clone(),
                                severity: severity_for(SchemaViolationType::ExtraField),
                            });
                            violations.push(SchemaViolation {
                                violation_type: SchemaViolationType::MassAssignmentUndocumentedField,
                                path: path.to_owned(),
                                field: format!("{field}.{key}"),
                                expected: "allowlisted writable field".to_owned(),
                                actual: key.clone(),
                                severity: severity_for(SchemaViolationType::MassAssignmentUndocumentedField),
                            });
                        }
                    }
                }
                for (key, schema_node) in fields {
                    if let Some(v) = obj.get(key) {
                        let sub_field = format!("{field}.{key}");
                        validate_schema_node(schema_node, v, &sub_field, path, violations);
                    }
                }
            } else {
                push_type_mismatch(path, field, "object", value, violations);
                if let Some(coercion_kind) = detect_body_coercion_attack("object", value) {
                    push_coercion_violation(path, field, "object", &coercion_kind, violations);
                }
            }
        }
        SchemaNode::Enum(allowed) => {
            if let Some(s) = value.as_str() {
                if !allowed.iter().any(|v| v == s) {
                    violations.push(SchemaViolation {
                        violation_type: SchemaViolationType::EnumViolation,
                        path: path.to_owned(),
                        field: field.to_owned(),
                        expected: format!("one_of:{}", allowed.join("|")),
                        actual: s.to_owned(),
                        severity: severity_for(SchemaViolationType::EnumViolation),
                    });
                }
            } else {
                push_type_mismatch(path, field, "string(enum)", value, violations);
            }
        }
    }
}

fn push_type_mismatch(
    path: &str,
    field: &str,
    expected: &str,
    value: &Value,
    violations: &mut Vec<SchemaViolation>,
) {
    violations.push(SchemaViolation {
        violation_type: SchemaViolationType::TypeMismatch,
        path: path.to_owned(),
        field: field.to_owned(),
        expected: expected.to_owned(),
        actual: value.to_string(),
        severity: severity_for(SchemaViolationType::TypeMismatch),
    });
    if let Some(coercion_kind) = detect_body_coercion_attack(expected, value) {
        push_coercion_violation(path, field, expected, &coercion_kind, violations);
    }
}

fn push_coercion_violation(
    path: &str,
    field: &str,
    expected: &str,
    actual: &str,
    violations: &mut Vec<SchemaViolation>,
) {
    violations.push(SchemaViolation {
        violation_type: SchemaViolationType::CoercionAttack,
        path: path.to_owned(),
        field: field.to_owned(),
        expected: expected.to_owned(),
        actual: actual.to_owned(),
        severity: severity_for(SchemaViolationType::CoercionAttack),
    });
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let mut it = pair.splitn(2, '=');
        let key = it.next().unwrap_or_default();
        let val = it.next().unwrap_or_default();
        out.insert(key.to_owned(), val.to_owned());
    }
    out
}

fn header_map(headers: &[(String, String)]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (k, v) in headers {
        map.insert(k.to_ascii_lowercase(), v.clone());
    }
    map
}

fn schema_path_key(path: &str, method: &str) -> String {
    format!("{} {}", method.to_ascii_uppercase(), path)
}

fn unpack_schema_key(key: &str) -> Option<(&str, &str)> {
    key.split_once(' ')
}

fn find_endpoint_matches<'a>(schema: &'a ApiSchema, path: &str) -> Vec<(&'a str, &'a PathSpec)> {
    schema
        .paths
        .iter()
        .filter_map(|(key, spec)| {
            let (_, schema_path) = unpack_schema_key(key)?;
            if match_path_template(schema_path, path) {
                Some((schema_path, spec))
            } else {
                None
            }
        })
        .collect()
}

fn match_path_template(template: &str, actual: &str) -> bool {
    let template_parts: Vec<&str> = template.trim_matches('/').split('/').collect();
    let actual_parts: Vec<&str> = actual.trim_matches('/').split('/').collect();

    if template_parts == [""] && actual_parts == [""] {
        return true;
    }
    if template_parts.len() != actual_parts.len() {
        return false;
    }

    template_parts
        .iter()
        .zip(actual_parts.iter())
        .all(|(t, a)| is_path_placeholder(t) || t == a)
}

fn extract_path_params(template: &str, actual: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let template_parts: Vec<&str> = template.trim_matches('/').split('/').collect();
    let actual_parts: Vec<&str> = actual.trim_matches('/').split('/').collect();

    for (t, a) in template_parts.iter().zip(actual_parts.iter()) {
        if is_path_placeholder(t) {
            out.insert(t.trim_matches('{').trim_matches('}').to_owned(), (*a).to_owned());
        }
    }
    out
}

fn is_path_placeholder(segment: &str) -> bool {
    segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2
}

fn schema_depth(node: &SchemaNode) -> usize {
    match node {
        SchemaNode::String | SchemaNode::Integer | SchemaNode::Number | SchemaNode::Boolean | SchemaNode::Enum(_) => 1,
        SchemaNode::Array(inner) => 1 + schema_depth(inner),
        SchemaNode::Object(fields) => 1 + fields.values().map(schema_depth).max().unwrap_or(0),
        SchemaNode::ObjectWithRules { fields, .. } => 1 + fields.values().map(schema_depth).max().unwrap_or(0),
    }
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(fields) => 1 + fields.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn is_http_method(method: &str) -> bool {
    matches!(
        method.to_ascii_lowercase().as_str(),
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "trace"
    )
}

fn severity_for(kind: SchemaViolationType) -> Severity {
    match kind {
        SchemaViolationType::UnknownEndpoint => Severity::High,
        SchemaViolationType::UnknownMethod => Severity::Medium,
        SchemaViolationType::MissingRequiredParam => Severity::Medium,
        SchemaViolationType::MissingRequiredField => Severity::High,
        SchemaViolationType::TypeMismatch => Severity::Medium,
        SchemaViolationType::CoercionAttack => Severity::High,
        SchemaViolationType::PatternViolation => Severity::Medium,
        SchemaViolationType::ExtraField => Severity::High,
        SchemaViolationType::MassAssignmentUndocumentedField => Severity::High,
        SchemaViolationType::EnumViolation => Severity::Medium,
        SchemaViolationType::DepthExceeded => Severity::High,
        SchemaViolationType::EndpointEnumeration => Severity::Medium,
    }
}

fn detect_param_coercion_attack(raw: &str, expected: &ParamType) -> Option<String> {
    let trimmed = raw.trim();
    match expected {
        ParamType::Integer | ParamType::Number => {
            if trimmed.starts_with('"')
                || trimmed.starts_with('{')
                || trimmed.starts_with('[')
                || trimmed.eq_ignore_ascii_case("nan")
                || trimmed.eq_ignore_ascii_case("infinity")
            {
                return Some(format!("coercion_candidate:{trimmed}"));
            }
        }
        ParamType::Boolean => {
            if matches!(trimmed.to_ascii_lowercase().as_str(), "1" | "0" | "\"true\"" | "\"false\"") {
                return Some(format!("coercion_candidate:{trimmed}"));
            }
        }
        ParamType::String => {
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                return Some(format!("structured_payload:{trimmed}"));
            }
        }
    }
    None
}

fn detect_body_coercion_attack(expected: &str, value: &Value) -> Option<String> {
    match (expected, value) {
        ("integer", Value::String(s)) if s.parse::<i64>().is_ok() => {
            Some(format!("string_to_integer:{s}"))
        }
        ("number", Value::String(s)) if s.parse::<f64>().is_ok() => {
            Some(format!("string_to_number:{s}"))
        }
        ("boolean", Value::String(s))
            if s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("false") =>
        {
            Some(format!("string_to_boolean:{s}"))
        }
        ("object", Value::Array(_)) => Some("array_to_object".to_owned()),
        ("array", Value::Object(_)) => Some("object_to_array".to_owned()),
        _ => None,
    }
}

fn detect_endpoint_enumeration_target(schema: &ApiSchema, path: &str) -> Option<String> {
    static VERSION_SEGMENT_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"^v(\d+)$").unwrap());

    let actual_segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    if actual_segments.is_empty() {
        return None;
    }

    let mut best_match: Option<String> = None;
    for key in schema.paths.keys() {
        let (_, schema_path) = match unpack_schema_key(key) {
            Some(parts) => parts,
            None => continue,
        };
        let schema_segments: Vec<&str> = schema_path.trim_matches('/').split('/').collect();
        if schema_segments.len() != actual_segments.len() {
            continue;
        }
        let mut version_delta_seen = false;
        let mut structurally_same = true;
        for (schema_seg, actual_seg) in schema_segments.iter().zip(actual_segments.iter()) {
            if is_path_placeholder(schema_seg) {
                continue;
            }
            match (
                VERSION_SEGMENT_RE.captures(schema_seg),
                VERSION_SEGMENT_RE.captures(actual_seg),
            ) {
                (Some(sv), Some(av)) => {
                    let s = sv.get(1).and_then(|m| m.as_str().parse::<i64>().ok());
                    let a = av.get(1).and_then(|m| m.as_str().parse::<i64>().ok());
                    if let (Some(s), Some(a)) = (s, a) {
                        if s != a {
                            version_delta_seen = true;
                        }
                    }
                }
                _ => {
                    if schema_seg != actual_seg {
                        structurally_same = false;
                        break;
                    }
                }
            }
        }
        if structurally_same && version_delta_seen {
            best_match = Some(schema_path.to_owned());
            break;
        }
    }
    best_match
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_schema() -> ApiSchema {
        load_schema(
            r#"{
                "paths": {
                    "/users/{id}": {
                        "get": {
                            "parameters": [
                                {"name":"id","in":"path","type":"integer","required":true},
                                {"name":"verbose","in":"query","type":"boolean","required":false},
                                {"name":"x-trace-id","in":"header","type":"string","required":true,"pattern":"^[a-z0-9-]+$"}
                            ]
                        },
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type":"object",
                                            "properties": {
                                                "role": {"enum": ["user", "admin"]},
                                                "age": {"type":"integer"},
                                                "profile": {
                                                    "type":"object",
                                                    "properties": {
                                                        "name": {"type":"string"}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "components": {
                    "schemas": {
                        "Simple": {"type":"string"}
                    }
                }
            }"#,
        )
        .expect("schema should parse")
    }

    #[test]
    fn load_schema_parses_openapi_subset() {
        let schema = sample_schema();
        assert_eq!(schema.paths.len(), 2);
        assert!(schema.paths.contains_key("GET /users/{id}"));
        assert!(schema.paths.contains_key("POST /users/{id}"));
        assert!(schema.components.contains_key("Simple"));
    }

    #[test]
    fn load_schema_from_paths_parses_direct_paths() {
        let schema = load_schema_from_paths(
            r#"{
                "/health": {
                    "method": "GET",
                    "parameters": []
                }
            }"#,
        )
        .expect("paths should parse");

        assert!(schema.paths.contains_key("GET /health"));
    }

    #[test]
    fn validate_unknown_endpoint() {
        let schema = sample_schema();
        let violations = validate_request(&schema, "GET", "/unknown", "", "", &[]);
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::UnknownEndpoint));
    }

    #[test]
    fn validate_unknown_method() {
        let schema = sample_schema();
        let violations = validate_request(
            &schema,
            "DELETE",
            "/users/10",
            "",
            "",
            &[("x-trace-id".into(), "abc-123".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::UnknownMethod));
    }

    #[test]
    fn validate_missing_required_param() {
        let schema = sample_schema();
        let violations = validate_request(&schema, "GET", "/users/10", "", "", &[]);
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::MissingRequiredParam && v.field == "x-trace-id"));
    }

    #[test]
    fn validate_param_type_mismatch() {
        let schema = sample_schema();
        let violations = validate_request(
            &schema,
            "GET",
            "/users/not-an-int",
            "",
            "",
            &[("x-trace-id".into(), "abc-123".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::TypeMismatch && v.field == "id"));
    }

    #[test]
    fn validate_pattern_violation() {
        let schema = sample_schema();
        let violations = validate_request(
            &schema,
            "GET",
            "/users/10",
            "",
            "",
            &[("x-trace-id".into(), "NOT-VALID*".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::PatternViolation));
    }

    #[test]
    fn validate_enum_violation_in_body() {
        let schema = sample_schema();
        let violations = validate_request(
            &schema,
            "POST",
            "/users/10",
            "",
            r#"{"role":"super_admin","age":20}"#,
            &[("content-type".into(), "application/json".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::EnumViolation));
    }

    #[test]
    fn validate_extra_field_detected() {
        let schema = sample_schema();
        let violations = validate_request(
            &schema,
            "POST",
            "/users/10",
            "",
            r#"{"role":"user","age":20,"is_admin":true}"#,
            &[("content-type".into(), "application/json".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::ExtraField));
    }

    #[test]
    fn validate_depth_exceeded() {
        let schema = sample_schema();
        let violations = validate_request(
            &schema,
            "POST",
            "/users/10",
            "",
            r#"{"role":"user","age":20,"profile":{"name":{"nested":true}}}"#,
            &[("content-type".into(), "application/json".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::DepthExceeded));
    }

    #[test]
    fn detect_shadow_endpoints_finds_unknowns() {
        let schema = sample_schema();
        let observed = vec![
            "/users/42".to_string(),
            "/admin/secret".to_string(),
            "/users/42?x=1".to_string(),
            "/billing".to_string(),
        ];
        let shadow = detect_shadow_endpoints(&schema, &observed);
        assert_eq!(shadow, vec!["/admin/secret".to_string(), "/billing".to_string()]);
    }

    fn strict_body_schema() -> ApiSchema {
        load_schema(
            r#"{
                "paths": {
                    "/accounts/v1/profile": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type":"object",
                                            "required": ["role", "age", "meta"],
                                            "additionalProperties": false,
                                            "properties": {
                                                "role": {"enum": ["user", "admin"]},
                                                "age": {"type":"integer"},
                                                "meta": {"type":"object","properties":{"name":{"type":"string"}}}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "/accounts/v2/profile": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type":"object",
                                            "properties": {"role": {"type":"string"}}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }"#,
        )
        .expect("strict schema should parse")
    }

    #[test]
    fn validate_missing_required_body_field() {
        let schema = strict_body_schema();
        let violations = validate_request(
            &schema,
            "POST",
            "/accounts/v1/profile",
            "",
            r#"{"role":"user","age":21}"#,
            &[("content-type".into(), "application/json".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::MissingRequiredField && v.field.ends_with(".meta")));
    }

    #[test]
    fn validate_detects_mass_assignment_from_undocumented_field() {
        let schema = strict_body_schema();
        let violations = validate_request(
            &schema,
            "POST",
            "/accounts/v1/profile",
            "",
            r#"{"role":"user","age":21,"meta":{"name":"a"},"isAdmin":true}"#,
            &[("content-type".into(), "application/json".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::MassAssignmentUndocumentedField));
    }

    #[test]
    fn validate_detects_string_to_number_coercion_attack() {
        let schema = strict_body_schema();
        let violations = validate_request(
            &schema,
            "POST",
            "/accounts/v1/profile",
            "",
            r#"{"role":"user","age":"21","meta":{"name":"a"}}"#,
            &[("content-type".into(), "application/json".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::CoercionAttack && v.actual.contains("string_to_integer")));
    }

    #[test]
    fn validate_detects_array_to_object_coercion_attack() {
        let schema = strict_body_schema();
        let violations = validate_request(
            &schema,
            "POST",
            "/accounts/v1/profile",
            "",
            r#"{"role":"user","age":21,"meta":[{"name":"a"}]}"#,
            &[("content-type".into(), "application/json".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::CoercionAttack && v.actual == "array_to_object"));
    }

    #[test]
    fn validate_detects_query_param_coercion_attack() {
        let schema = sample_schema();
        let violations = validate_request(
            &schema,
            "GET",
            "/users/10",
            "verbose=\"true\"",
            "",
            &[("x-trace-id".into(), "abc-123".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::CoercionAttack && v.field == "verbose"));
    }

    #[test]
    fn validate_detects_endpoint_enumeration_on_version_probe() {
        let schema = strict_body_schema();
        let violations = validate_request(
            &schema,
            "POST",
            "/accounts/v3/profile",
            "",
            r#"{"role":"user"}"#,
            &[("content-type".into(), "application/json".into())],
        );
        assert!(violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::EndpointEnumeration));
    }

    #[test]
    fn validate_endpoint_enumeration_not_flagged_for_unrelated_unknown_path() {
        let schema = strict_body_schema();
        let violations = validate_request(&schema, "GET", "/totally/unknown/path", "", "", &[]);
        assert!(!violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::EndpointEnumeration));
    }

    #[test]
    fn parse_schema_supports_object_with_rules_variant() {
        let schema = strict_body_schema();
        let key = "POST /accounts/v1/profile".to_string();
        let spec = schema.paths.get(&key).expect("path must exist");
        let body = spec.request_body.as_ref().expect("body must exist");
        match &body.schema {
            SchemaNode::ObjectWithRules { required, allow_additional, .. } => {
                assert!(required.iter().any(|r| r == "role"));
                assert!(!allow_additional);
            }
            _ => panic!("expected object rules node"),
        }
    }
}
