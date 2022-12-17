package utm.threatintelligence.scraper.processors;

import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.enums.github.GitHubGlobalEnum;
import utm.threatintelligence.interfaces.IProcessor;
import utm.threatintelligence.scraper.LinkListGenerator;
import utm.threatintelligence.scraper.LinkPage;

import java.io.IOException;

/**
 * Used to process links from github and convert them to raw processable links
 * to fill
 * */
public class GHLinksProcessor implements IProcessor {
    private static String[] github_url_parts = EnvironmentConfig.FEED_URL.split(EnvironmentConfig.LINK_SEPARATOR);
    static String PUBLIC_ORGANIZATON_OR_USER = github_url_parts[3];
    static String PUBLIC_REPOSITORY = github_url_parts[4];

    public GHLinksProcessor() {}

    @Override
    public <T> T process() throws IOException {
        return null;
    }

    @Override
    public String process(Object params) throws IOException {
        String tmpLink = (String) params;
        // Add allowed links to the list of the links, converted to github raw links
        if (LinkListGenerator.isExtensionAllowed(tmpLink)) {
            if (tmpLink.startsWith("/"+this.PUBLIC_ORGANIZATON_OR_USER+"/"+this.PUBLIC_REPOSITORY+"/blob/"+EnvironmentConfig.GITHUB_BRANCH_NAME+"/")) {
                tmpLink = "https://" + GitHubGlobalEnum.GIT_HUB_RAW_PREFIX.get() + tmpLink.replace("/blob", "");
                LinkPage.getUniqueListOfLinks().put(tmpLink, tmpLink);
            } else if (tmpLink.startsWith("https://" + GitHubGlobalEnum.GIT_HUB_PREFIX.get() + "/"+this.PUBLIC_ORGANIZATON_OR_USER+"/"+this.PUBLIC_REPOSITORY+"/blob/"+EnvironmentConfig.GITHUB_BRANCH_NAME+"/")) {
                tmpLink = tmpLink.replace("/blob", "")
                        .replace(GitHubGlobalEnum.GIT_HUB_PREFIX.get(), GitHubGlobalEnum.GIT_HUB_RAW_PREFIX.get());
                LinkPage.getUniqueListOfLinks().put(tmpLink, tmpLink);
            }

        // If it is not an allowed link, register the path as visited and add it to the list of paths to check
        } else {
            if (tmpLink.startsWith("/"+this.PUBLIC_ORGANIZATON_OR_USER+"/"+this.PUBLIC_REPOSITORY+"/tree/"+EnvironmentConfig.GITHUB_BRANCH_NAME+"/") ||
                    tmpLink.startsWith("https://" + GitHubGlobalEnum.GIT_HUB_PREFIX.get() + "/"+this.PUBLIC_ORGANIZATON_OR_USER+"/"+this.PUBLIC_REPOSITORY +"/tree/"+EnvironmentConfig.GITHUB_BRANCH_NAME+"/")
            ) {
                tmpLink = tmpLink.startsWith("https://" + GitHubGlobalEnum.GIT_HUB_PREFIX.get()) ? tmpLink : "https://" + GitHubGlobalEnum.GIT_HUB_PREFIX.get() + tmpLink;
                if (!LinkPage.getVisitedPaths().containsKey(tmpLink)) {
                    LinkPage.getListOfPaths().add(tmpLink);
                    LinkPage.getVisitedPaths().put(tmpLink, tmpLink);
                }
            }
        }
        return "";
    }
}
