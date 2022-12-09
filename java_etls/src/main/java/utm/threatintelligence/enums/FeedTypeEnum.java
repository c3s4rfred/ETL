package utm.threatintelligence.enums;

/*Enum used to define the Feed Types implemented in ETL process*/
public enum FeedTypeEnum {
    TYPE_OSINT_CIRCL("OSINT_CIRCL"),
    TYPE_OSINT_BOTVRIJ("OSINT_BOTVRIJ"),
    TYPE_OSINT_DIJITAL_SIDE("OSINT_DIJITAL_SIDE"),
    TYPE_GITHUB_YARA("GITHUB_YARA"),
    TYPE_RFXN_YARA("RFXN_YARA"),
    TYPE_GENERIC_IP_LIST("GENERIC_IP_LIST"),
    TYPE_ABUSE_SSLIP_BLACKLIST("ABUSE_SSLIP_BLACKLIST"),
    TYPE_COMMENT_IP_LIST("COMMENT_IP_LIST"),
    TYPE_REPUTATION_ALIEN_VAULT("REPUTATION_ALIEN_VAULT"),
    TYPE_FEODOTRACKER_IP_BLOCKLIST("FEODOTRACKER_IP_BLOCKLIST"),
    UNRECOGNIZED_FEED("UNRECOGNIZED_FEED");

    private String varName;

    private FeedTypeEnum(String varName) {
        this.varName = varName;
    }

    public String getVarValue() {
        return varName;
    }
}
