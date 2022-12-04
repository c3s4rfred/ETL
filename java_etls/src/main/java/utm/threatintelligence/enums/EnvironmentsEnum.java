package utm.threatintelligence.enums;

/*Enum to define all environment variables used in the ETL process*/
public enum EnvironmentsEnum {
    FEED_URL("FEED_URL"),
    LINK_PATTERN("LINK_PATTERN"),
    GITHUB_BRANCH_NAME("GITHUB_BRANCH_NAME"),
    THREAD_POOL_SIZE("THREAD_POOL_SIZE"),
    TW_API_KEY("TW_API_KEY"),
    TW_API_SECRET("TW_API_SECRET"),
    TW_API_URL("TW_API_URL"),
    TW_API_VERSION("TW_API_VERSION"),
    FEED_FORMAT("FEED_FORMAT"),
    TW_API_ENTITY_BASE_TYPE("TW_API_ENTITY_BASE_TYPE"),
    TW_AUTHENTICATION("TW_AUTHENTICATION");

    private String varName;

    EnvironmentsEnum(String varName) {
        this.varName = varName;
    }

    public String getVarName() {
        return varName;
    }
}
