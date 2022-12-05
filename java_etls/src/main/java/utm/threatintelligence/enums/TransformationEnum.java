package utm.threatintelligence.enums;

/*Enum used to define transformations constants*/
public enum TransformationEnum {
    TYPE_TRANSFORMATION("-TYPE-"), // Used for type field values transformations
    REPUTATION_TRANSFORMATION("-REPUTATION-"), // Used for reputation field values transformation
    VALUE_URLS_TRANSFORMATION("-VALUE_URLS-"), // Used for value field values transformations (link and url types)
    EMAIL_COMPONENTS_TRANSFORMATION("-EMAIL_COMP-"), // Used for type field values transformations in case of email types like = (email-src or email-dst)
    MISC_TYPE_TRANSFORMATION("-MISC_TYPE-"), // Used for general type field values transformations like 'weakness'
    DATETIME_VALUE_TRANSFORMATION("-DATETIME_VALUE-"), // Used for datetime type values transformations like '01/01/2022'
    ATTRIBUTE_TYPE_YARA_TRANSFORMATION("-ATTRIBUTE_TYPE_YARA-"); // Used for yara type value transformation (convert to TW yara object)

    private String varName;

    private TransformationEnum(String varName) {
        this.varName = varName;
    }

    public String getVarValue() {
        return varName;
    }
}
