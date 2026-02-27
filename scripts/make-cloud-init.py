#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "PyYAML>=6.0.2",
# ]
# ///

from pathlib import Path
import yaml


SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR.joinpath("cloud-init-config.yaml")

class CloudInitDumper(yaml.SafeDumper):
    pass


def _repr_str(dumper: yaml.SafeDumper, value: str):
    if "\n" in value:
        return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", value)


CloudInitDumper.add_representer(str, _repr_str)


def main() -> None:
    cloud_cfg = yaml.safe_load(CONFIG_PATH.read_text())
    if not isinstance(cloud_cfg, dict):
        raise ValueError("cloud-init-config.yaml must parse to a mapping")

    for wf in cloud_cfg.get("write_files", []):
        if "source_file" not in wf:
            raise ValueError(f"write_files entry missing source_file: {wf}")
        wf["content"] = SCRIPT_DIR.joinpath(wf["source_file"]).read_text()
        del wf["source_file"]

    print("#cloud-config")
    print(yaml.dump(cloud_cfg, Dumper=CloudInitDumper, sort_keys=False), end="")


if __name__ == "__main__":
    main()
