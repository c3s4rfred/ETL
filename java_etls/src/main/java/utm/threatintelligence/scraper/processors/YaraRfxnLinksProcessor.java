package utm.threatintelligence.scraper.processors;

import utm.threatintelligence.interfaces.IProcessor;
import utm.threatintelligence.scraper.LinkListGenerator;
import utm.threatintelligence.scraper.LinkPage;

import java.io.IOException;

public class YaraRfxnLinksProcessor implements IProcessor {
    @Override
    public <T> T process() throws IOException {
        return null;
    }

    @Override
    public String process(Object params) throws IOException {
        String tmpLink = (String) params;
        if (LinkListGenerator.isExtensionAllowed(tmpLink)) {
                LinkPage.getUniqueListOfLinks().put(tmpLink, tmpLink);
        }
        return "";
    }
}
