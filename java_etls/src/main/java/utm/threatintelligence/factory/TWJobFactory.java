package utm.threatintelligence.factory;

import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.entity.transform.jobs.DefaultJob;
import utm.threatintelligence.entity.transform.jobs.GHYaraJob;
import utm.threatintelligence.entity.transform.jobs.IPListJob;
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
                       FeedTypeEnum.TYPE_COMMENT_IP_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                return new IPListJob();
            } else {
                return new DefaultJob();
            }
        }
        return null;
    }
}
