package utm.threatintelligence.urlcreator;

import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.interfaces.IURLCreator;

import java.net.MalformedURLException;
import java.net.URL;

public class FullPathUrlCreator implements IURLCreator {

    @Override
    public URL createURL(String resource, String separator) throws MalformedURLException {
        URL url = new URL(resource);
        return url;
    }
}
