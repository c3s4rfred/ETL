package com.threatintelligence.enums.osint.circl;

public enum OCSpecificTypesToCheck {
    VIRUS_TOTAL_REPORT("virustotal-report"),
    LINK("link"),
    URL("url"),
    DATE_TIME("datetime"),
    YARA_RULE("yara");

    private String typeChecked;

    private OCSpecificTypesToCheck(String typeChecked) {
        this.typeChecked = typeChecked;
    }

    public String getTypeChecked() {
        return typeChecked;
    }
}
