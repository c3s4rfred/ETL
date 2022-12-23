package com.threatintelligence.enums;

public enum LinkAllowedExtensionsEnum {
    YARA_RULE(".yar,.yara"),
    SURICATA_RULE(".rules,.N0TD3F1N3D");
    private String extension;

    LinkAllowedExtensionsEnum(String extension) {
        this.extension = extension;
    }

    public String get() {
        return extension;
    }
}
