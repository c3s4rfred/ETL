package com.threatintelligence.enums;

/*Enum used to define logs types*/
public enum LogTypeEnum {
    TYPE_EXECUTION("EXECUTION"),
    TYPE_ERROR("ERROR"),
    TYPE_WARNING("WARNING");

    private String varName;

    private LogTypeEnum(String varName) {
        this.varName = varName;
    }

    public String getVarValue() {
        return varName;
    }
}
