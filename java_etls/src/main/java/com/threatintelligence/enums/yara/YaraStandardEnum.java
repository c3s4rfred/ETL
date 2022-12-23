package com.threatintelligence.enums.yara;

public enum YaraStandardEnum {
    ALLOWED_MODIFIERS("global,private");

    private String varValue;

    private YaraStandardEnum(String varValue) {
        this.varValue = varValue;
    }

    public String getValue() {
        return varValue;
    }
}
