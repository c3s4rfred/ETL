package utm.threatintelligence.factory;

import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.entity.transform.jobs.DefaultJob;
import utm.threatintelligence.entity.transform.jobs.ElementListJob;
import utm.threatintelligence.entity.transform.jobs.GHYaraJob;
import utm.threatintelligence.entity.transform.jobs.OCJob;
import utm.threatintelligence.enums.FeedTypeEnum;
import utm.threatintelligence.interfaces.IJobExecutor;
import utm.threatintelligence.utilities.UtilitiesService;

/**
* Main class of the API, dedicated to define the IJobExecutor feed to
* be executed
* */
public class TWJobFactory {
    public TWJobFactory() {
    }

    public IJobExecutor getJob (){
        if (UtilitiesService.isEnvironmentOk()) {
            if (
                    FeedTypeEnum.TYPE_OSINT_CIRCL.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                    FeedTypeEnum.TYPE_OSINT_BOTVRIJ.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                    FeedTypeEnum.TYPE_OSINT_DIJITAL_SIDE.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0
            ) {
                return new OCJob();
            } else if (FeedTypeEnum.TYPE_GITHUB_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_RFXN_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                return new GHYaraJob();
            } else if (FeedTypeEnum.TYPE_GENERIC_IP_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_ABUSE_SSLIP_BLACKLIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_COMMENT_IP_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_REPUTATION_ALIEN_VAULT.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_FEODOTRACKER_IP_BLOCKLIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_CYBERCURE_AI_IP.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       // FeedTypeEnum.TYPE_IP_SPAM_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_MALSILO_IP_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_GENERIC_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_PHISHTANK_ONLINE_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_DIAMOND_FOX_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_VXVAULT_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_CYBERCURE_AI_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_MALSILO_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_BENKOW_CC_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_GENERIC_CVE_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_MALSILO_DOMAIN_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_ZIP_HAUS_ABUSE_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_ZIP_WITH_GENERIC_MD5_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_MALSHARE_CURRENT_DAILY_SHA256_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0
            ) {
                return new ElementListJob();
            } else {
                return new DefaultJob();
            }
        }
        return null;
    }
}
