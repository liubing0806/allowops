"""Render the Allowops scenarios and check the chart's values schema."""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote

import yaml


HERE = Path(__file__).resolve().parent
CHART = HERE / "allowops"
FIXTURES = HERE / "fixtures"


def expect(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label}: expected {expected!r}, got {actual!r}")


def resources(documents, kind):
    return [doc for doc in documents if doc["kind"] == kind]


def one(documents, kind):
    matches = resources(documents, kind)
    expect(f"{kind} count", len(matches), 1)
    return matches[0]


def pod(workload):
    return workload["spec"]["template"]["spec"]


def by_name(items):
    return {item["name"]: item for item in items}


def render(values_args):
    return subprocess.check_output(["helm", "template", "allowops", CHART, *values_args], text=True)


def manifests(rendered):
    return [doc for doc in yaml.safe_load_all(rendered) if doc is not None]


def check_configs(documents, audit_enabled):
    config_map = one(documents, "ConfigMap")
    configs = {}
    for kind, filename in (("Deployment", "gateway.yaml"), ("StatefulSet", "exporter.yaml")):
        config = yaml.safe_load(config_map["data"][filename])
        if not isinstance(config, dict) or not config:
            raise SystemExit(f"{filename}: expected a non-empty YAML mapping")
        configs[filename] = config

        if kind == "StatefulSet" and not audit_enabled:
            expect("export StatefulSet count", len(resources(documents, kind)), 0)
            continue
        spec = pod(one(documents, kind))
        gateway = by_name(spec["containers"])["gateway"]
        expect(f"{kind} config arguments", gateway["args"], ["serve", "--config", f"/etc/allowops/{filename}"])
        mounts = {mount["mountPath"]: mount["name"] for mount in gateway["volumeMounts"]}
        volume = by_name(spec["volumes"])[mounts["/etc/allowops"]]
        expect(f"{kind} mounted ConfigMap", volume["configMap"]["name"], config_map["metadata"]["name"])
    return configs


def check_availability(documents, values):
    deployment = one(documents, "Deployment")["spec"]
    budget = one(documents, "PodDisruptionBudget")["spec"]
    expect("API replicas", deployment["replicas"], values["replicaCount"])
    expect("PDB minAvailable", budget["minAvailable"], values["podDisruptionBudget"]["minAvailable"])
    expect("PDB selector", budget["selector"], deployment["selector"])


def check_audit_disabled(documents, baseline):
    expect("standalone PVC count", len(resources(documents, "PersistentVolumeClaim")), 0)
    api = pod(one(documents, "Deployment"))
    default_api = pod(one(baseline, "Deployment"))
    claims = [v["name"] for v in api["volumes"] if "persistentVolumeClaim" in v]
    expect("API PVC volumes", claims, [])
    for setting in ("securityContext", "automountServiceAccountToken"):
        expect(f"API {setting}", api[setting], default_api[setting])
    for group in ("initContainers", "containers"):
        contexts = {c["name"]: c["securityContext"] for c in api[group]}
        default_contexts = {c["name"]: c["securityContext"] for c in default_api[group]}
        expect(f"API {group} security contexts", contexts, default_contexts)
    gateway = by_name(api["containers"])["gateway"]
    default_gateway = by_name(default_api["containers"])["gateway"]
    for probe in ("startupProbe", "livenessProbe", "readinessProbe"):
        expect(f"API {probe}", gateway[probe], default_gateway[probe])


def check_ha_custom(documents, configs, values, values_args):
    check_availability(documents, values)
    public_services = [svc for svc in resources(documents, "Service") if svc["spec"].get("type")]
    expect("public Service count", len(public_services), 1)
    service = public_services[0]
    expect("public Service annotations", service["metadata"]["annotations"], values["service"]["annotations"])
    grace = values["gateway"]["shutdownGraceSeconds"]
    for filename, config in configs.items():
        expect(f"{filename} shutdown_grace", config["gateway"]["shutdown_grace"], f"{grace}s")
        expect(f"{filename} ca_pin", config["management"]["ca_pin"], values["gateway"]["management"]["ca_pin"])
        expect(f"{filename} output endpoint", config["output"]["endpoint"], values["output"]["endpoint"])

    # Change just one ConfigMap input, keeping release, replicas and every other value fixed.
    control = manifests(render([*values_args, "--set-string", "output.endpoint="]))
    control_data = one(control, "ConfigMap")["data"]
    for filename in configs:
        expect(f"control {filename} endpoint", yaml.safe_load(control_data[filename])["output"]["endpoint"], "")
    for kind in ("Deployment", "StatefulSet"):
        workload = one(documents, kind)
        expect(f"{kind} termination grace", pod(workload)["terminationGracePeriodSeconds"], grace + 10)
        annotations = workload["spec"]["template"]["metadata"]["annotations"]
        control_annotations = one(control, kind)["spec"]["template"]["metadata"]["annotations"]
        checksum = annotations["checksum/config"]
        control_checksum = control_annotations["checksum/config"]
        for digest in (checksum, control_checksum):
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise SystemExit(f"{kind} checksum/config: expected a SHA-256 digest, got {digest!r}")
        if checksum == control_checksum:
            raise SystemExit(f"{kind} checksum/config stayed {checksum} after changing output.endpoint")


def check_existing_secrets(documents, values):
    expect("rendered Secret count", len(resources(documents, "Secret")), 0)
    volume_names = {
        "secret": values["credentials"]["existingSecret"],
        "audit-secret": values["audit"]["cursorKeySecret"],
        "output-secret": values["output"]["existingSecret"],
    }
    for kind, container_name, database in (
        ("Deployment", "gateway", values["database"]),
        ("StatefulSet", "gateway", values["database"]),
        ("Job", "migrate", values["migration"]),
    ):
        spec = pod(one(documents, kind))
        refs = []
        for container in [*spec.get("initContainers", []), *spec["containers"]]:
            for env in container.get("env", []):
                if "secretKeyRef" in env.get("valueFrom", {}):
                    refs.append((container["name"], env["name"], env["valueFrom"]["secretKeyRef"]))
        db_ref = {"name": database["existingSecret"], "key": database["key"]}
        expect(f"{kind} Secret environment references", refs, [(container_name, "ALLOWOPS_DATABASE_URL", db_ref)])

        secrets = {v["name"]: v["secret"] for v in spec.get("volumes", []) if "secret" in v}
        names = {volume: source["secretName"] for volume, source in secrets.items()}
        expect(f"{kind} Secret volumes", names, {} if kind == "Job" else volume_names)
        if kind != "Job":
            copier = by_name(spec["initContainers"])["copy-secrets"]
            mounts = {m["name"]: m["mountPath"] for m in copier["volumeMounts"] if m["name"] in secrets}
            expect(f"{kind} mounted Secrets", mounts, {name: f"/{name}" for name in volume_names})
            for volume, key, path in (
                ("audit-secret", values["audit"]["cursorKeyKey"], "audit-cursor-key"),
                ("output-secret", values["output"]["credentialsKey"], "aws-credentials"),
            ):
                expect(f"{kind} {volume} projection", secrets[volume]["items"], [{"key": key, "path": path}])


def verify_positive(name, kubeconform, baseline=None):
    print(f"Rendering {name}", flush=True)
    values_args = []
    values_file = CHART / "values.yaml"
    if name != "default":
        values_file = FIXTURES / f"{name}.yaml"
        values_args = ["--values", values_file]
    values = yaml.safe_load(values_file.read_text())
    subprocess.run(["helm", "lint", CHART, *values_args], check=True)
    rendered = render(values_args)
    with tempfile.TemporaryDirectory(prefix="allowops-helm-") as directory:
        manifest = Path(directory) / f"{name}.yaml"
        manifest.write_text(rendered)
        subprocess.run([sys.executable, HERE / "verify.py", manifest], check=True)
        if kubeconform:
            subprocess.run(
                [kubeconform, "-strict", "-summary", "-kubernetes-version", "1.32.0", manifest], check=True,
            )

    documents = manifests(rendered)
    configs = check_configs(documents, name != "audit-disabled")
    if name == "default":
        check_availability(documents, values)
    elif name == "audit-disabled":
        check_audit_disabled(documents, baseline)
    elif name == "ha-custom":
        check_ha_custom(documents, configs, values, values_args)
    elif name == "existing-secrets-disabled-create":
        check_existing_secrets(documents, values)
    else:
        raise SystemExit(f"{name}: missing scenario assertions")
    print(f"PASS render {name}", flush=True)
    return documents


def verify_rejections():
    cases = {
        "replica-count-zero.yaml": "replicaCount",
        "empty-output-bucket.yaml": "output.bucket",
        "audit-enabled-string.yaml": "audit.enabled",
    }
    invalid = FIXTURES / "invalid"
    filenames = sorted(path.name for path in invalid.glob("*.yaml"))
    expect("invalid fixtures with an expected schema error", filenames, sorted(cases))
    for filename, field in cases.items():
        result = subprocess.run(
            ["helm", "template", "allowops", CHART, "--values", invalid / filename],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        if result.returncode == 0:
            raise SystemExit(f"{filename}: helm template accepted invalid {field}")
        # Helm reports the field as a JSON pointer or dotted path depending on its version.
        pointer = "/" + field.replace(".", "/")
        field_reported = f"'{pointer}'" in result.stderr or f"- {field}:" in result.stderr
        if "values don't meet the specifications of the schema" not in result.stderr or not field_reported:
            raise SystemExit(f"{filename}: expected schema rejection of {field}, got:\n{result.stderr}")
        print(f"PASS schema rejected {filename} ({field})", flush=True)


def index_local_schemas(root):
    # Each embedded resource has its own root pointer and named anchors. Only
    # visit schema positions; a literal default value may itself contain "$id".
    resource_roots = {}
    anchors = {}
    pending = [(root, root)]
    while pending:
        schema, resource = pending.pop()
        if isinstance(schema, list):
            pending.extend((item, resource) for item in schema)
        elif isinstance(schema, dict):
            location, _, fragment = schema.get("$id", "").partition("#")
            if location:
                resource = schema
            resource_roots[id(schema)] = resource
            if fragment:
                anchors[id(resource), unquote(fragment)] = schema
            for keyword in ("definitions", "$defs", "properties", "patternProperties", "dependencies"):
                pending.extend((item, resource) for item in schema.get(keyword, {}).values())
            for keyword in ("items", "additionalItems", "contains", "additionalProperties", "propertyNames",
                            "allOf", "anyOf", "oneOf", "not", "if", "then", "else"):
                if keyword in schema:
                    pending.append((schema[keyword], resource))
    return resource_roots, anchors


def resolve_local_refs(schema, resource_roots, anchors):
    visited = set()
    while isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if id(schema) in visited:
            raise ValueError(f"Circular schema reference {ref!r}")
        visited.add(id(schema))
        if not ref.startswith("#"):
            raise ValueError(f"Expected an in-document schema reference, got {ref!r}")
        root = resource_roots[id(schema)]
        fragment = unquote(ref[1:])
        if fragment and not fragment.startswith("/"):
            schema = anchors[id(root), fragment]
            continue
        schema = root
        for token in fragment.split("/")[1:]:
            key = token.replace("~1", "/").replace("~0", "~")
            schema = schema[int(key)] if isinstance(schema, list) else schema[key]
    return schema


def property_schemas(schema, key, path):
    matches = [sub for pattern, sub in schema.get("patternProperties", {}).items() if re.search(pattern, key)]
    properties = schema.get("properties", {})
    if key in properties:
        matches.append(properties[key])
    # A top-level setting requires a name or pattern. For nested maps, only
    # unmatched names use additionalProperties.
    if not matches and path and "additionalProperties" in schema:
        matches.append(schema["additionalProperties"])
    return matches


def item_schema(schema, index):
    items = schema.get("items", False)
    if isinstance(items, list):
        return items[index] if index < len(items) else schema.get("additionalItems", False)
    return items


def undeclared_paths(value, schema, path=""):
    resource_roots, anchors = index_local_schemas(schema)

    def walk(value, candidates, path):
        # Several matching patterns and an explicit property may each declare
        # different descendants. Collect their declarations at each value path.
        resolved = [resolve_local_refs(candidate, resource_roots, anchors) for candidate in candidates]
        if True in resolved:
            return
        declarations = [candidate for candidate in resolved if candidate is not False]
        if not declarations:
            yield path
        elif isinstance(value, dict):
            for key, child in value.items():
                matches = []
                for declaration in declarations:
                    matches.extend(property_schemas(declaration, key, path))
                yield from walk(child, matches, f"{path}.{key}" if path else key)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                matches = [item_schema(declaration, index) for declaration in declarations]
                yield from walk(item, matches, f"{path}[{index}]")

    yield from walk(value, [schema], path)


def verify_schema_coverage():
    defaults = yaml.safe_load((CHART / "values.yaml").read_text())
    schema = json.loads((CHART / "values.schema.json").read_text())
    missing = list(undeclared_paths(defaults, schema))
    if missing:
        raise SystemExit("values.schema.json is missing declarations for:\n  " + "\n  ".join(missing))
    print("PASS schema covers every key in values.yaml")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconform", metavar="BIN", help="also validate against Kubernetes 1.32.0")
    parser.add_argument("--check-schema-coverage", action="store_true",
                        help="fail if values.yaml contains keys or items without schema declarations")
    args = parser.parse_args()
    baseline = verify_positive("default", args.kubeconform)
    cases = ("audit-disabled", "ha-custom", "existing-secrets-disabled-create")
    expect("registered positive fixtures", sorted(p.stem for p in FIXTURES.glob("*.yaml")), sorted(cases))
    for name in cases:
        verify_positive(name, args.kubeconform, baseline)
    verify_rejections()
    if args.check_schema_coverage:
        verify_schema_coverage()


if __name__ == "__main__":
    main()
