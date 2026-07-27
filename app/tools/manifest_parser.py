import os
import xml.etree.ElementTree as ET


def parse_manifest_info(unpack_dir: str) -> dict:
    manifest_path = os.path.join(unpack_dir, "AndroidManifest.xml")
    result = {
        "package_name": None,
        "version_name": None,
        "version_code": None,
        "application_label": None,
    }

    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"AndroidManifest.xml is missing under {unpack_dir}")

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        result["package_name"] = root.attrib.get("package")

        version_name = None
        version_code = None
        for k, v in root.attrib.items():
            if k.endswith("versionName"):
                version_name = v
            if k.endswith("versionCode"):
                version_code = v

        result["version_name"] = version_name
        result["version_code"] = version_code

        for child in root:
            if child.tag.endswith("application"):
                for k, v in child.attrib.items():
                    if k.endswith("label"):
                        result["application_label"] = v
                        break
                break
    except (ET.ParseError, OSError) as exc:
        raise ValueError(
            f"AndroidManifest.xml parse failed: {type(exc).__name__}"
        ) from exc

    return result
