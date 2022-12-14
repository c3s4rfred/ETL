package utm.threatintelligence.entity.transform.jobs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utm.sdk.threatwinds.enums.TWEndPointEnum;
import utm.sdk.threatwinds.factory.RequestFactory;
import utm.sdk.threatwinds.interfaces.IRequestExecutor;
import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.entity.ein.common.CommonEntityObject;
import utm.threatintelligence.entity.ein.common.ElementWithAssociations;
import utm.threatintelligence.entity.transform.transf.FromElementListToEntity;
import utm.threatintelligence.enums.FeedTypeEnum;
import utm.threatintelligence.enums.FlowPhasesEnum;
import utm.threatintelligence.enums.LogTypeEnum;
import utm.threatintelligence.enums.TWAttributeTypesEnum;
import utm.threatintelligence.interfaces.IJobExecutor;
import utm.threatintelligence.json.parser.GenericParser;
import utm.threatintelligence.logging.LogDef;
import utm.threatintelligence.readers.FileStreamReader;
import utm.threatintelligence.scraper.LinkPage;
import utm.threatintelligence.urlcreator.FullPathUrlCreator;

import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class ElementListJob implements IJobExecutor {
    private final Logger log = LoggerFactory.getLogger(ElementListJob.class);
    private static final String CLASSNAME = "ElementListJob";
    static List<String> listDirectLinkFeeds;

    public ElementListJob() {
        this.listDirectLinkFeeds = new ArrayList<>();
        FillListOfDirectLinkFeeds();
    }

    @Override
    public void executeFlow() throws Exception {
        final String ctx = CLASSNAME + ".executeElementList";
        String feedSelected = EnvironmentConfig.FEED_FORMAT;

        // ----------------------- Log the process init -------------------------//
        log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), feedSelected,
                FlowPhasesEnum.P0_BEGIN_PROCESS.getVarValue()).logDefToString());

        // ----------------------- Log the feed scrap to search for links -------------------------//
        try {
            // Those FEED_FORMAT below are direct resource and don't have content-type, so, the feed url have to
            // be inserted directly in the list of links
            if (isIPDirectLink()) {
                LinkPage.getListOfLinks().add(EnvironmentConfig.FEED_URL);
            }
        } catch (Exception ex) {
            log.error(ctx + ": " + new LogDef(LogTypeEnum.TYPE_ERROR.getVarValue(),
                    feedSelected, "Problem getting data from host: " + ex.getLocalizedMessage()).logDefToString());
        }
        //First we create fixed thread pool executor with 8 threads, one per file
        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(EnvironmentConfig.THREAD_POOL_SIZE);

        //--------------------------------The concurrent ETL process is here-------------------------------------------
        while (LinkPage.getListOfLinks().size() > 0) {
            executor.execute(new ElementListJob.ElementListParallelTask((String) LinkPage.getListOfLinks().remove(0)));
        }

        //Thread end is called
        executor.shutdown();
        //Wait 1 sec until termination
        while (!executor.isTerminated()) {
            try {
                executor.awaitTermination(1, TimeUnit.SECONDS);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), feedSelected,
                FlowPhasesEnum.PN_END_PROCESS.getVarValue()).logDefToString());

    }

    public class ElementListParallelTask implements Runnable {

        String link;

        public ElementListParallelTask(String link) {
            this.link = link;
        }

        @Override
        public void run() {
            final String ctx = CLASSNAME + ".parallelElementListExecutor";
            GenericParser gp = new GenericParser();
            FileStreamReader reader = new FileStreamReader();
            String linkToProcess = "";

            try {
                // ----------------------- Log and execute the file reading from internet -------------------------//
                linkToProcess = this.link;
                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P1_READ_FILE.getVarValue()).logDefToString());

                List<String> dataFromFile = reader.readFileAsList(
                        new FullPathUrlCreator().createURL(linkToProcess, EnvironmentConfig.LINK_SEPARATOR)
                );

                // ----------------------- Log and execute mapping from file to class -------------------------//
                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P2_MAP_JSON_TO_CLASS.getVarValue()).logDefToString());

                // ----------------------- Cleaning the list values and generate final structure --------------------//
                // Because have comments beginning with # and or it is a csv, or have headers, or empty lines
                List<ElementWithAssociations> elementWithAssociations = createElemWithAssocList(dataFromFile);

                // ----------------------- Log and execute transformation to Entity class -------------------------//
                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P3_TRANSFORM_TO_ENTITY.getVarValue()).logDefToString());

                FromElementListToEntity fromElementListToEntity = new FromElementListToEntity();
                fromElementListToEntity.transform(elementWithAssociations, null);

                // ----------------------- Log and execute mapping Entity to JSON -------------------------//
                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P4_MAP_ENTITY_TO_JSON.getVarValue()).logDefToString());

                // ----------------------- Inserting via sdk -------------------------//
                IRequestExecutor mainJob = new RequestFactory(500).getExecutor();
                if (mainJob != null) {
                    String output = (String) mainJob.executeRequest(TWEndPointEnum.POST_ENTITIES.get(), fromElementListToEntity.getThreatIntEntityList());
                    log.info(ctx + " " + linkToProcess + ": " + output);
                }

                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P5_END_FILE_PROCESS.getVarValue()).logDefToString());
            } catch (Exception jne) {
                log.error(ctx + ": " + new LogDef(LogTypeEnum.TYPE_ERROR.getVarValue(), linkToProcess,
                        jne.getLocalizedMessage()).logDefToString()
                );
            }
        }
    }

    public static List<ElementWithAssociations> createElemWithAssocList(List<String> origin) {
        // Do different cleaning process for different feeds
        List<ElementWithAssociations> cleanedList = new ArrayList<>();
        Iterator<String> it;
        for (it = origin.iterator(); it.hasNext(); ) {
            String attr = it.next().trim();
            if (!attr.startsWith("#") && attr.compareTo("") != 0) {
                // IP lists
                if (FeedTypeEnum.TYPE_GENERIC_IP_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                        FeedTypeEnum.TYPE_COMMENT_IP_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_IP.getValueType(),
                            generateProtocol(attr), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                            EnvironmentConfig.FEED_BASE_REPUTATION);
                    ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                    cleanedList.add(element);
                }
                if (FeedTypeEnum.TYPE_ABUSE_SSLIP_BLACKLIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    String[] arrayCSV = attr.split(",");
                    CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_IP.getValueType(),
                            arrayCSV[1].trim(), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                            EnvironmentConfig.FEED_BASE_REPUTATION);
                    ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                    cleanedList.add(element);
                }
                if (FeedTypeEnum.TYPE_REPUTATION_ALIEN_VAULT.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    String[] arrayIP = attr.split("#");
                    CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_IP.getValueType(),
                            arrayIP[0].trim(), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                            EnvironmentConfig.FEED_BASE_REPUTATION);
                    ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                    cleanedList.add(element);
                }
                if (FeedTypeEnum.TYPE_FEODOTRACKER_IP_BLOCKLIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    attr = attr.replace("\"", "");
                    if (!attr.startsWith("first_seen")) {
                        String[] arrayCSV = attr.split(",");
                        CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_IP.getValueType(),
                                arrayCSV[1].trim(), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                                EnvironmentConfig.FEED_BASE_REPUTATION);
                        ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                        cleanedList.add(element);
                    }
                }
                if (FeedTypeEnum.TYPE_CYBERCURE_AI_IP.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    String[] array = attr.split(",");
                    for (int i = 0; i < array.length; i++) {
                        String tempIp = array[i].trim();
                        if (attr.compareTo("") != 0) {
                            CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_IP.getValueType(),
                                    tempIp, EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                                    EnvironmentConfig.FEED_BASE_REPUTATION);
                            ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                            cleanedList.add(element);
                        }
                    }
                }
                if (FeedTypeEnum.TYPE_IP_SPAM_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    attr = attr.replace("\"", "");
                    if (!attr.startsWith("first_seen")) {
                        String[] arrayCSV = attr.split(",");
                        CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_IP.getValueType(),
                                arrayCSV[2].trim(), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                                EnvironmentConfig.FEED_BASE_REPUTATION);
                        ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                        cleanedList.add(element);
                    }
                }
                if (FeedTypeEnum.TYPE_MALSILO_IP_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    attr = attr.replace("\"", "");
                    String[] arrayCSV = attr.split(",");
                    // Second split is because the field value is ip:port
                    CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_IP.getValueType(),
                            arrayCSV[2].split(":")[0].trim(), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                            EnvironmentConfig.FEED_BASE_REPUTATION);
                    ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                    cleanedList.add(element);
                }
                // URL lists
                if (FeedTypeEnum.TYPE_GENERIC_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0){
                    // Generating default protocol if not exists
                    attr = generateProtocol(attr);

                    CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_URL.getValueType(),
                            attr, EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                            EnvironmentConfig.FEED_BASE_REPUTATION);
                    ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                    cleanedList.add(element);
                }
                if (FeedTypeEnum.TYPE_PHISHTANK_ONLINE_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0){
                    // Phishtank feed csv data lines begins with the phish_id
                    if (attr.matches("^(\\d+)(.+)")) {
                        String[] arrayCSV = attr.split(",");
                        // With generation of default protocol if not exists
                        CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_URL.getValueType(),
                                generateProtocol(arrayCSV[1].trim()), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                                EnvironmentConfig.FEED_BASE_REPUTATION);
                        ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                        cleanedList.add(element);
                    }
                }
                if (FeedTypeEnum.TYPE_DIAMOND_FOX_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0){
                        String[] arrayCSV = attr.split(",");
                        // With generation of default protocol if not exists
                        CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_URL.getValueType(),
                                generateProtocol(arrayCSV[0].trim()), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                                EnvironmentConfig.FEED_BASE_REPUTATION);
                        ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                        cleanedList.add(element);
                }
                if (FeedTypeEnum.TYPE_VXVAULT_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0){
                    if (attr.matches("^(http)(.+)")) {
                        // With generation of default protocol if not exists
                        CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_LINK.getValueType(),
                                generateProtocol(attr), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                                EnvironmentConfig.FEED_BASE_REPUTATION);
                        ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                        cleanedList.add(element);
                    }
                }
                if (FeedTypeEnum.TYPE_CYBERCURE_AI_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    String[] array = attr.split(",");
                    for (int i = 0; i < array.length; i++) {
                        String tempIp = array[i].trim();
                        if (attr.compareTo("") != 0) {
                            CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_URL.getValueType(),
                                    generateProtocol(tempIp), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                                    EnvironmentConfig.FEED_BASE_REPUTATION);
                            ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                            cleanedList.add(element);
                        }
                    }
                }
                if (FeedTypeEnum.TYPE_MALSILO_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    attr = attr.replace("\"", "");
                    String[] arrayCSV = attr.split(",");
                    // Second split is because the field value is ip:port
                    CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_URL.getValueType(),
                            generateProtocol(arrayCSV[2].trim()), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                            EnvironmentConfig.FEED_BASE_REPUTATION);
                    ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                    cleanedList.add(element);
                }
                if (FeedTypeEnum.TYPE_BENKOW_CC_URL_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    attr = attr.replace("\"", "").trim();
                    if (attr.matches("^(\\d+)(.+)")) {
                        String[] arrayCSV = attr.split(";");

                        CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_URL.getValueType(),
                                generateProtocol(arrayCSV[2].trim()), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                                EnvironmentConfig.FEED_BASE_REPUTATION);
                        ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                        // Adding the ip associated with the url
                        if (arrayCSV[3].trim().compareTo("") != 0) {
                            CommonEntityObject commonEObjectAssoc = new CommonEntityObject(TWAttributeTypesEnum.TYPE_IP.getValueType(),
                                    arrayCSV[3].trim(), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                                    EnvironmentConfig.FEED_BASE_REPUTATION);
                            List<CommonEntityObject> assoc = new ArrayList<>();
                            assoc.add(commonEObjectAssoc);
                            element.setAssociations(assoc);
                        }

                        cleanedList.add(element);
                    }
                }
                if (FeedTypeEnum.TYPE_GENERIC_CVE_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ) {
                    CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_CVE.getValueType(),
                            attr, EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                            EnvironmentConfig.FEED_BASE_REPUTATION);
                    ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                    cleanedList.add(element);
                }
                if (FeedTypeEnum.TYPE_MALSILO_DOMAIN_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    attr = attr.replace("\"", "");
                    String[] arrayCSV = attr.split(",");
                    // Second split is because the field value is ip:port
                    CommonEntityObject commonEObject = new CommonEntityObject(TWAttributeTypesEnum.TYPE_DOMAIN.getValueType(),
                            arrayCSV[2].trim(), EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                            EnvironmentConfig.FEED_BASE_REPUTATION);
                    ElementWithAssociations element = new ElementWithAssociations(commonEObject, new ArrayList<>());
                    cleanedList.add(element);
                }
            }
        }
        return cleanedList;
    }

    // Method to fill the ListDirectLinkFeeds
    public static void FillListOfDirectLinkFeeds() {
        // IP feeds
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_GENERIC_IP_LIST.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_ABUSE_SSLIP_BLACKLIST.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_COMMENT_IP_LIST.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_REPUTATION_ALIEN_VAULT.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_FEODOTRACKER_IP_BLOCKLIST.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_CYBERCURE_AI_IP.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_IP_SPAM_LIST.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_MALSILO_IP_LIST.getVarValue());
        // URL feeds
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_GENERIC_URL_LIST.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_PHISHTANK_ONLINE_URL_LIST.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_DIAMOND_FOX_URL_LIST.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_VXVAULT_URL_LIST.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_CYBERCURE_AI_URL_LIST.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_MALSILO_URL_LIST.getVarValue());
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_BENKOW_CC_URL_LIST.getVarValue());
        // CVE feeds
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_GENERIC_CVE_LIST.getVarValue());
        // Domain feeds
        listDirectLinkFeeds.add(FeedTypeEnum.TYPE_MALSILO_DOMAIN_LIST.getVarValue());
    }

    // Method to know if FEED_FORMAT value is an IP feed, direct link
    public boolean isIPDirectLink() {
        Iterator<String> it;
        for (it = listDirectLinkFeeds.iterator(); it.hasNext(); ) {
            String attr = it.next();
            if (attr.compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                return true;
            }
        }
        return false;
    }
    // Method to check if protocol is present, if not, generates https by default
    public static String generateProtocol(String value){
        if (value.matches("(.+)(https|http)(://)(.+)")) {
            value = value.replaceFirst("(.+)(https|http)", "$2");
        } else if (!value.matches("^(https|http)(://)(.+)")) {
            value = "https://" + value;
        }
        // Replacing security protocol
        value = value.replaceFirst("hxxp","http");
        return value;
    }

}
