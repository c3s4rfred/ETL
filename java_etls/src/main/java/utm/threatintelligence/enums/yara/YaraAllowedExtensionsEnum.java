package utm.threatintelligence.enums.yara;

public enum YaraAllowedExtensionsEnum {
    YARA_ALLOWED_EXTENSIONS(".yar,.yara");
    private String extension;

    YaraAllowedExtensionsEnum(String extension) {
        this.extension = extension;
    }

    public String get() {
        return extension;
    }
}
