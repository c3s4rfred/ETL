package utm.threatintelligence.enums.yara.github;

public enum GHYaraGlobalEnum {
    GIT_HUB_YARA_RAW_PREFIX("raw.githubusercontent.com"),
    GIT_HUB_YARA_PREFIX("github.com");
    private String global_enum;

    GHYaraGlobalEnum(String global_enum) {
        this.global_enum = global_enum;
    }

    public String get() {
        return global_enum;
    }
}
