"""A deliberately small JSON-Schema checker for tool arguments: object, string, integer, boolean, enum, bounds, pattern, required, additionalProperties false.
Anything else in a schema is refused at registration (`check_schema`), never silently ignored."""
import re

_SCALARS = {"string", "integer", "boolean"}


def validate(schema, value):
    """List of human-readable problems (empty when valid)."""
    if not isinstance(value, dict):
        return ["arguments must be an object"]
    errors = []
    props = schema.get("properties", {})
    for name in schema.get("required", []):
        if name not in value:
            errors.append(f"'{name}' is required")
    if schema.get("additionalProperties") is False:
        for name in value:
            if name not in props:
                errors.append(f"'{name}' is not an accepted argument")
    for name, v in value.items():
        spec = props.get(name)
        if spec is None:
            continue
        t = spec.get("type")
        if t == "string":
            if not isinstance(v, str):
                errors.append(f"'{name}' must be a string")
                continue
            if len(v) < spec.get("minLength", 0):
                errors.append(f"'{name}' is too short")
            if len(v) > spec.get("maxLength", 10_000):
                errors.append(f"'{name}' is too long (max {spec.get('maxLength', 10_000)})")
            if "pattern" in spec and not re.search(spec["pattern"], v):
                errors.append(f"'{name}' has the wrong format")
        elif t == "integer":
            if isinstance(v, bool) or not isinstance(v, int):
                errors.append(f"'{name}' must be an integer")
                continue
            if "minimum" in spec and v < spec["minimum"]:
                errors.append(f"'{name}' must be at least {spec['minimum']}")
            if "maximum" in spec and v > spec["maximum"]:
                errors.append(f"'{name}' must be at most {spec['maximum']}")
        elif t == "boolean":
            if not isinstance(v, bool):
                errors.append(f"'{name}' must be true or false")
        else:
            errors.append(f"'{name}' has an unsupported schema type")
            continue
        if "enum" in spec and v not in spec["enum"]:
            errors.append(f"'{name}' must be one of: {', '.join(map(str, spec['enum']))}")
    return errors[:6]


def check_schema(schema):
    """Registration-time check: the schema is a closed object using only what `validate` understands, with bounded strings and integers."""
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise ValueError("a tool input schema must be an object with additionalProperties false")
    for name, spec in schema.get("properties", {}).items():
        if spec.get("type") not in _SCALARS:
            raise ValueError(f"property '{name}' uses an unsupported type")
        if spec["type"] == "string" and "maxLength" not in spec and "enum" not in spec:
            raise ValueError(f"string property '{name}' needs a maxLength")
        if spec["type"] == "integer" and ("minimum" not in spec or "maximum" not in spec):
            raise ValueError(f"integer property '{name}' needs minimum and maximum")
