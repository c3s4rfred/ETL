package utm.threatintelligence.enums;

/*Enum for threat intelligence types values definition used for something*/
public enum TWAttributeTypesEnum {
    TYPE_OBJECT("object"),
    TYPE_NORMAL("normal"),
    TYPE_DESCRIPTOR("descriptor"),
    TYPE_TEXT("text"),
    TYPE_IP("ip"),
    TYPE_CIDR("cidr"),
    TYPE_URL("url"),
    TYPE_LINK("link"),
    TYPE_CVE("cve"),
    // TW Yara
    TYPE_YARA_RULE("yara-rule"),
    TYPE_YARA_CONDITION_NAME("condition"),
    TYPE_YARA_CONDITION("yara-condition"),
    TYPE_YARA_STRING_NAME("string"),
    TYPE_YARA_STRING("yara-string"),
    TYPE_YARA_IMPORT_NAME("import"),
    TYPE_YARA_IMPORT("text"),
    TYPE_YARA_MODIFIER_NAME("modifier"),
    TYPE_YARA_MODIFIER("text");

    private String valueType;

    private TWAttributeTypesEnum(String valueType) {
        this.valueType = valueType;
    }

    public String getValueType() {
        return valueType;
    }
}
