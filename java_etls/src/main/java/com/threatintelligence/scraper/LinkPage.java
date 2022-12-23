package com.threatintelligence.scraper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.swing.text.MutableAttributeSet;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLEditorKit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.threatintelligence.factory.LinksProcessorFactory;
import com.threatintelligence.interfaces.IProcessor;

public class LinkPage extends HTMLEditorKit.ParserCallback {

    private static ArrayList listOfLinks = new ArrayList();
    private static ArrayList listOfPaths = new ArrayList();
    private static Map<String, String> visitedPaths = new LinkedHashMap<>();
    private static Map<String, String> uniqueListOfLinks = new LinkedHashMap<>();
    private static final Logger log = LoggerFactory.getLogger(LinkPage.class);

    public void handleStartTag(HTML.Tag t, MutableAttributeSet a, int pos) {
        if (t == HTML.Tag.A) {
            String tmpLink = a.getAttribute(HTML.Attribute.HREF).toString();
            IProcessor linksProc = new LinksProcessorFactory().getLinksProcessor();
            if (linksProc != null) {
                try {
                    linksProc.process(tmpLink);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static ArrayList getListOfLinks() {
        return listOfLinks;
    }
    public static void setListOfLinks() {
        listOfLinks = new ArrayList();
        listOfLinks.addAll(uniqueListOfLinks.values());
    }

    public static ArrayList getListOfPaths() {
        return listOfPaths;
    }

    public static Map<String, String> getVisitedPaths() {
        return visitedPaths;
    }

    public static Map<String, String> getUniqueListOfLinks() {
        return uniqueListOfLinks;
    }
}
