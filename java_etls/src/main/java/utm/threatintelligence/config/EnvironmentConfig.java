package utm.threatintelligence.config;

import utm.threatintelligence.enums.EnvironmentsEnum;

public class EnvironmentConfig {

    // Represents the URL of the feed to be executed
    public static final String FEED_URL = System.getenv(EnvironmentsEnum.FEED_URL.getVarName());
    // Represents the name of the feed to be executed, must be the same defined in enum (FeedTypeEnum)
    private static String feedToExecuteInit = System.getenv(EnvironmentsEnum.FEED_FORMAT.getVarName());
    public static final String FEED_FORMAT = feedToExecuteInit != null && feedToExecuteInit.compareTo("") != 0 ? feedToExecuteInit : "";
    // Represents a pattern to include links that match in case the FEED_URL holds many file links and have to scrap
    private static String linkPatternInit = System.getenv(EnvironmentsEnum.LINK_PATTERN.getVarName());
    public static final String LINK_PATTERN = linkPatternInit != null && linkPatternInit.compareTo("") != 0 ? linkPatternInit : "";
    // Thread pool size, (concurrent executions), by default 8
    private static String threadPoolSizeInit = System.getenv(EnvironmentsEnum.THREAD_POOL_SIZE.getVarName());
    public static final Integer THREAD_POOL_SIZE = threadPoolSizeInit != null && threadPoolSizeInit.compareTo("") != 0
        ? Integer.parseInt(threadPoolSizeInit)
        : 8;
    // Used to access resources inside the FEED_URL
    public static final String LINK_SEPARATOR = "/";
    // Represents the access key to the threat intelligence endpoints URL (TW_API_URL)
    public static final String TW_API_KEY = System.getenv(EnvironmentsEnum.TW_API_KEY.getVarName());
    // Represents the access secret for threat intelligence endpoints URL (TW_API_URL)
    public static final String TW_API_SECRET = System.getenv(EnvironmentsEnum.TW_API_SECRET.getVarName());
    // Represents the threat intelligence endpoints URL
    public static final String TW_API_URL = System.getenv(EnvironmentsEnum.TW_API_URL.getVarName());
    // Represents the base type definition for a top level entity in case you don't have a field from origin to use (Ex: threat)
    private static String entityBaseTypeInit = System.getenv(EnvironmentsEnum.TW_API_ENTITY_BASE_TYPE.getVarName());
    public static final String TW_API_ENTITY_BASE_TYPE = entityBaseTypeInit != null && entityBaseTypeInit.compareTo("") != 0
        ? entityBaseTypeInit
        : "threat";
    // Represents the threat winds API Bearer authentication key
    public static final String TW_AUTHENTICATION = System.getenv(EnvironmentsEnum.TW_AUTHENTICATION.getVarName());
    // Represents the threat winds API version
    private static String twApiVersion = System.getenv(EnvironmentsEnum.TW_API_VERSION.getVarName());
    public static final String TW_API_VERSION = twApiVersion != null && twApiVersion.compareTo("") != 0 ? twApiVersion : "v1";
    // Represents the github branch used to process GitHubYaraFeed
    public static final String GITHUB_BRANCH_NAME = System.getenv(EnvironmentsEnum.GITHUB_BRANCH_NAME.getVarName());
}
