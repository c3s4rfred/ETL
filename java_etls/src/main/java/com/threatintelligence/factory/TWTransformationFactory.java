package com.threatintelligence.factory;

import com.threatintelligence.entity.transform.transf.*;
import com.threatintelligence.interfaces.IEntityTransform;
import com.threatintelligence.config.EnvironmentConfig;
import com.threatintelligence.enums.FeedTypeEnum;

/**
* Used to define which ITransformation has to be executed according to FEED_FORMAT
* */
public class TWTransformationFactory {
    public TWTransformationFactory() {
    }

    public IEntityTransform getTransformation (){
            if (
                    FeedTypeEnum.TYPE_OSINT_CIRCL.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                    FeedTypeEnum.TYPE_OSINT_BOTVRIJ.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                    FeedTypeEnum.TYPE_OSINT_DIJITAL_SIDE.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0
            ) {
                return new FromOCToEntity();
            } else if (FeedTypeEnum.TYPE_GITHUB_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                       FeedTypeEnum.TYPE_RFXN_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                return new FromYaraToEntity();
            } else if (FeedTypeEnum.TYPE_GITHUB_SURICATA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0){
                return new FromSuricataToEntity();
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
                return new FromElementListToEntity();
            } else {
                return new DefaultToEntity();
            }
    }
}
