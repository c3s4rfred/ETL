package utm.threatintelligence.urlcreator;

import java.net.MalformedURLException;
import java.net.URL;
import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.interfaces.IURLCreator;

public class OsintCirclUrlCreator implements IURLCreator {

    @Override
    public URL createURL(String resource, String separator) throws MalformedURLException {
        URL url = new URL(EnvironmentConfig.FEED_URL + resource);
        return url;
    }
}
