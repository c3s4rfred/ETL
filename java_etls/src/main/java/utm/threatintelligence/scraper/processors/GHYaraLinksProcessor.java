package utm.threatintelligence.scraper.processors;

import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.enums.yara.github.GHYaraGlobalEnum;
import utm.threatintelligence.interfaces.IProcessor;
import utm.threatintelligence.scraper.LinkListGenerator;
import utm.threatintelligence.scraper.LinkPage;

import java.io.IOException;

public class GHYaraLinksProcessor implements IProcessor {
    private static String[] github_url_parts = EnvironmentConfig.FEED_URL.split(EnvironmentConfig.LINK_SEPARATOR);
    static String PUBLIC_ORGANIZATON_OR_USER = github_url_parts[3];
    static String PUBLIC_REPOSITORY = github_url_parts[4];

    public GHYaraLinksProcessor() {}

    @Override
    public <T> T process() throws IOException {
        return null;
    }

    @Override
    public String process(Object params) throws IOException {
        String tmpLink = (String) params;
        if (LinkListGenerator.isExtensionAllowed(tmpLink)) {
            if (tmpLink.startsWith("/"+this.PUBLIC_ORGANIZATON_OR_USER+"/"+this.PUBLIC_REPOSITORY+"/blob/"+EnvironmentConfig.GITHUB_BRANCH_NAME+"/")) {
                tmpLink = "https://" + GHYaraGlobalEnum.GIT_HUB_YARA_RAW_PREFIX.get() + tmpLink.replace("/blob", "");
                LinkPage.getUniqueListOfLinks().put(tmpLink, tmpLink);
            } else if (tmpLink.startsWith("https://" + GHYaraGlobalEnum.GIT_HUB_YARA_PREFIX.get() + "/"+this.PUBLIC_ORGANIZATON_OR_USER+"/"+this.PUBLIC_REPOSITORY+"/blob/"+EnvironmentConfig.GITHUB_BRANCH_NAME+"/")) {
                tmpLink = tmpLink.replace("/blob", "")
                        .replace(GHYaraGlobalEnum.GIT_HUB_YARA_PREFIX.get(), GHYaraGlobalEnum.GIT_HUB_YARA_RAW_PREFIX.get());
                LinkPage.getUniqueListOfLinks().put(tmpLink, tmpLink);
            }

        } else {
            if (tmpLink.startsWith("/"+this.PUBLIC_ORGANIZATON_OR_USER+"/"+this.PUBLIC_REPOSITORY+"/tree/"+EnvironmentConfig.GITHUB_BRANCH_NAME+"/") ||
                    tmpLink.startsWith("https://" + GHYaraGlobalEnum.GIT_HUB_YARA_PREFIX.get() + "/"+this.PUBLIC_ORGANIZATON_OR_USER+"/"+this.PUBLIC_REPOSITORY +"/tree/"+EnvironmentConfig.GITHUB_BRANCH_NAME+"/")
            ) {
                tmpLink = tmpLink.startsWith("https://" + GHYaraGlobalEnum.GIT_HUB_YARA_PREFIX.get()) ? tmpLink : "https://" + GHYaraGlobalEnum.GIT_HUB_YARA_PREFIX.get() + tmpLink;
                if (!LinkPage.getVisitedPaths().containsKey(tmpLink)) {
                    LinkPage.getListOfPaths().add(tmpLink);
                    LinkPage.getVisitedPaths().put(tmpLink, tmpLink);
                }
            }
        }
        return "";
    }
}
