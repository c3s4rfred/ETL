package utm.threatintelligence.scraper.processors;

import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.interfaces.IProcessor;
import utm.threatintelligence.scraper.LinkPage;

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
