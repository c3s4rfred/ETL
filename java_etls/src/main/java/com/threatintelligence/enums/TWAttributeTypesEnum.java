package com.threatintelligence.enums;

/*Enum for threat intelligence types values definition used for build entities*/
public enum TWAttributeTypesEnum {
    TYPE_OBJECT("object"),
    TYPE_NORMAL("normal"),
    TYPE_DESCRIPTOR("descriptor"),
    TYPE_TEXT("text"),
    TYPE_SENSITIVE_TEXT("sensitive-text"),
    TYPE_IP("ip"),
    TYPE_CIDR("cidr"),
    TYPE_URL("url"),
    TYPE_LINK("link"),
    TYPE_CVE("cve"),
    TYPE_DOMAIN("domain"),
    TYPE_MD5("md5"),
    TYPE_SHA256("sha256"),
    TYPE_SURICATA_RULE("suricata-rule"),
    // TW Yara
    TYPE_YARA_RULE("yara-rule"),
    TYPE_YARA_CONDITION_NAME("condition"),
    TYPE_YARA_CONDITION("yara-condition"),
    TYPE_YARA_STRING_NAME("string"),
    TYPE_YARA_STRING("yara-string"),
    TYPE_YARA_IMPORT_NAME("import"),
    TYPE_YARA_IMPORT("sensitive-text"),
    TYPE_YARA_MODIFIER_NAME("modifier"),
    TYPE_YARA_MODIFIER("sensitive-text");

    private String valueType;

    private TWAttributeTypesEnum(String valueType) {
        this.valueType = valueType;
    }

    public String getValueType() {
        return valueType;
    }
}
