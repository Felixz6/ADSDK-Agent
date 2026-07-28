import os
import xml.etree.ElementTree as ET


ANDROID_NAME = "{http://schemas.android.com/apk/res/android}name"
ANDROID_PERMISSION = "{http://schemas.android.com/apk/res/android}permission"
ANDROID_READ_PERMISSION = "{http://schemas.android.com/apk/res/android}readPermission"
ANDROID_WRITE_PERMISSION = "{http://schemas.android.com/apk/res/android}writePermission"

HIGH_ATTENTION_PERMISSIONS = {
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECORD_AUDIO",
}
SENSITIVE_PERMISSIONS = HIGH_ATTENTION_PERMISSIONS | {
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
}
COMPONENT_TAGS = {
    "activity",
    "activity-alias",
    "service",
    "receiver",
    "provider",
}


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _normalized_names(values) -> list[str]:
    return sorted(
        {
            value.strip()
            for value in values
            if isinstance(value, str) and value.strip()
        }
    )


def parse_manifest_info(unpack_dir: str) -> dict:
    manifest_path = os.path.join(unpack_dir, "AndroidManifest.xml")
    result = {
        "package_name": None,
        "version_name": None,
        "version_code": None,
        "application_label": None,
        "permissions": [],
        "declared_permissions": [],
        "custom_permissions": [],
        "component_permissions": [],
        "sensitive_permissions": [],
        "high_attention_permissions": [],
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
        declared_permissions = _normalized_names(
            child.attrib.get(ANDROID_NAME)
            for child in root
            if _local_name(child.tag)
            in {"uses-permission", "uses-permission-sdk-23"}
        )
        custom_permissions = _normalized_names(
            child.attrib.get(ANDROID_NAME)
            for child in root
            if _local_name(child.tag) == "permission"
        )
        component_permissions = _normalized_names(
            value
            for child in root.iter()
            if _local_name(child.tag) in COMPONENT_TAGS
            for value in (
                child.attrib.get(ANDROID_PERMISSION),
                child.attrib.get(ANDROID_READ_PERMISSION),
                child.attrib.get(ANDROID_WRITE_PERMISSION),
            )
        )
        result["permissions"] = declared_permissions
        result["declared_permissions"] = declared_permissions
        result["custom_permissions"] = custom_permissions
        result["component_permissions"] = component_permissions
        result["sensitive_permissions"] = sorted(
            set(declared_permissions) & SENSITIVE_PERMISSIONS
        )
        result["high_attention_permissions"] = sorted(
            set(declared_permissions) & HIGH_ATTENTION_PERMISSIONS
        )

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
