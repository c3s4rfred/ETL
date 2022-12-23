package com.threatintelligence.scraper.processors;

import com.threatintelligence.scraper.LinkPage;
import com.threatintelligence.config.EnvironmentConfig;
import com.threatintelligence.interfaces.IProcessor;

import java.io.IOException;

public class OCLinksProcessor implements IProcessor {

    public OCLinksProcessor(){}
    @Override
    public <T> T process() throws IOException {
        return null;
    }

    @Override
    public String process(Object params) throws IOException {
        String tmpLink = (String)params;
        if (tmpLink.matches(EnvironmentConfig.LINK_PATTERN)) {
            LinkPage.getUniqueListOfLinks().put(tmpLink, tmpLink);
        } else {
            // Link Removed -> tmpLink
        }
        return "";
    }
}
