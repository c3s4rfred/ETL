package utm.threatintelligence.enums.github;

public enum GitHubGlobalEnum {
    GIT_HUB_RAW_PREFIX("raw.githubusercontent.com"),
    GIT_HUB_PREFIX("github.com");
    private String global_enum;

    GitHubGlobalEnum(String global_enum) {
        this.global_enum = global_enum;
    }

    public String get() {
        return global_enum;
    }
}
