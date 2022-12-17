package utm.threatintelligence.scraper;

import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import javax.swing.text.html.parser.ParserDelegator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.enums.FeedTypeEnum;
import utm.threatintelligence.enums.LinkAllowedExtensionsEnum;
import utm.threatintelligence.interfaces.IProcessor;

public class LinkListGenerator implements IProcessor {
    private static final Logger log = LoggerFactory.getLogger(LinkListGenerator.class);
    private static final String CLASSNAME = "LinkListGenerator";

    public LinkListGenerator() {
    }

    @Override
    public String process() throws IOException {
        scrapLinks();
        return "";
    }

    @Override
    public String process(Object params) throws IOException {
        scrapLinksRecursive((String) params);
        return "";
    }

    // Extract links from a URL and return it in a list (Deprecated, use scrapLinksRecursive() instead)
    public static void scrapLinks() throws IOException {
        URL url = new URL(EnvironmentConfig.FEED_URL);
        Reader reader = new InputStreamReader((InputStream) url.getContent());
        new ParserDelegator().parse(reader, new LinkPage(), false);

        // Set the listOfLinks with all unique links (Very important step)
        LinkPage.setListOfLinks();
    }

    public static void scrapLinksRecursive(String BASE_URL) throws IOException {
        log.info("Searching sub-elements in path -> " + BASE_URL);
        URL url = new URL(BASE_URL);
        Reader reader = new InputStreamReader((InputStream) url.getContent());
        new ParserDelegator().parse(reader, new LinkPage(), false);
        if (LinkPage.getListOfPaths().size() > 0) {
            scrapLinksRecursive((String) LinkPage.getListOfPaths().remove(0));
        }

        // Set the listOfLinks with all unique links (Very important step)
        LinkPage.setListOfLinks();
    }

    // This method can be used to print the list of links extracted
    public static void showLinks(ArrayList links) {
        System.out.println("****************************Link list****************************");
        Iterator it;
        for (it = links.iterator(); it.hasNext(); ) {
            System.out.println("--> " + it.next().toString());
        }
    }

    // This method can be used to verify if link file extension is allowed for the feed
    public static boolean isExtensionAllowed(String linkToVerify) {
        if (FeedTypeEnum.TYPE_RFXN_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                FeedTypeEnum.TYPE_GITHUB_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                FeedTypeEnum.TYPE_GITHUB_SURICATA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
            String[] allowedExt = new String[0];
            // Checking RFXN and Github Yara feeds
            if (FeedTypeEnum.TYPE_RFXN_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                    FeedTypeEnum.TYPE_GITHUB_YARA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                allowedExt = LinkAllowedExtensionsEnum.YARA_RULE.get().split(",");
            }
            // Checking Github suricata feeds
            if (FeedTypeEnum.TYPE_GITHUB_SURICATA.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                allowedExt = LinkAllowedExtensionsEnum.SURICATA_RULE.get().split(",");
            }
            if (allowedExt.length > 0) {
                for (int i = 0; i < allowedExt.length; i++) {
                    if (linkToVerify.endsWith(allowedExt[i])) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // This method is for testing purposes (fill the list with test filenames)
    public static ArrayList getForTestListOfLinks() {
        LinkPage.getListOfLinks().add("https://raw.githubusercontent.com/Yara-Rules/rules/master/deprecated/Android/Android_AliPay_smsStealer.yar");
        return LinkPage.getListOfLinks();
    }
}
