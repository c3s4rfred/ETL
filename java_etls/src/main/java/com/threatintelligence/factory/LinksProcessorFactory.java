package com.threatintelligence.factory;

import com.threatintelligence.scraper.processors.YaraRfxnLinksProcessor;
import com.threatintelligence.config.EnvironmentConfig;
import com.threatintelligence.enums.FeedTypeEnum;
import com.threatintelligence.interfaces.IProcessor;
import com.threatintelligence.scraper.processors.GHLinksProcessor;
import com.threatintelligence.scraper.processors.OCLinksProcessor;

/**
 * LinksProcessorFactory is used to get the IProcessor needed for each FEED_FORMAT
 * each IProcessor returned, define tha way to add links to the final list of links, to be processed by the API
 *  */
public class LinksProcessorFactory {
    public LinksProcessorFactory () {}
    public IProcessor getLinksProcessor(){
        if (
                FeedTypeEnum.TYPE_OSINT_CIRCL.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                        FeedTypeEnum.TYPE_OSINT_BOTVRIJ.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                        FeedTypeEnum.TYPE_OSINT_DIJITAL_SIDE.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0
        ) {
            return new OCLinksProcessor();
        } else if (FeedTypeEnum.TYPE_GITHUB_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                   FeedTypeEnum.TYPE_GITHUB_SURICATA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
            return new GHLinksProcessor();
        } else if (FeedTypeEnum.TYPE_RFXN_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
            return new YaraRfxnLinksProcessor();
        }
        return null;
    }
}
