package utm.threatintelligence.entity.transform.jobs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utm.sdk.threatwinds.enums.TWEndPointEnum;
import utm.sdk.threatwinds.factory.RequestFactory;
import utm.sdk.threatwinds.interfaces.IRequestExecutor;
import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.entity.ein.common.IPListObject;
import utm.threatintelligence.entity.ein.common.YaraRuleObject;
import utm.threatintelligence.entity.ein.github.yara.GHYaraExtractor;
import utm.threatintelligence.entity.transform.transf.FromIPListToEntity;
import utm.threatintelligence.entity.transform.transf.FromYaraToEntity;
import utm.threatintelligence.enums.FeedTypeEnum;
import utm.threatintelligence.enums.FlowPhasesEnum;
import utm.threatintelligence.enums.LogTypeEnum;
import utm.threatintelligence.interfaces.IJobExecutor;
import utm.threatintelligence.interfaces.IProcessor;
import utm.threatintelligence.json.parser.GenericParser;
import utm.threatintelligence.logging.LogDef;
import utm.threatintelligence.readers.FileStreamReader;
import utm.threatintelligence.scraper.LinkListGenerator;
import utm.threatintelligence.scraper.LinkPage;
import utm.threatintelligence.urlcreator.FullPathUrlCreator;

import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class IPListJob implements IJobExecutor {
    private final Logger log = LoggerFactory.getLogger(IPListJob.class);
    private static final String CLASSNAME = "IPListJob";

    public IPListJob() {
    }

    @Override
    public void executeFlow() throws Exception {
        final String ctx = CLASSNAME + ".executeGitHubYara";
        String feedSelected = EnvironmentConfig.FEED_FORMAT;

        // ----------------------- Log the process init -------------------------//
        log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), feedSelected,
                FlowPhasesEnum.P0_BEGIN_PROCESS.getVarValue()).logDefToString());

        // ----------------------- Log the feed scrap to search for links -------------------------//
        try {
            // GENERIC_IP_LIST, ABUSE_SSLIP_BLACKLIST are direct resource and don't have content-type, so, the feed url have to
            // be inserted directly in the list of links
            if (FeedTypeEnum.TYPE_GENERIC_IP_LIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ||
                    FeedTypeEnum.TYPE_ABUSE_SSLIP_BLACKLIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0 ) {
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
            executor.execute(new IPListJob.IPListParallelTask((String) LinkPage.getListOfLinks().remove(0)));
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

    public class IPListParallelTask implements Runnable {

        String link;

        public IPListParallelTask(String link) {
            this.link = link;
        }

        @Override
        public void run() {
            final String ctx = CLASSNAME + ".parallelIPListExecutor";
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
                // ----------------------- Cleaning the list if is TYPE_ABUSE_SSLIP_BLACKLIST --------------------//
                // Because have comments beginning with # and it is a csv
                if (FeedTypeEnum.TYPE_ABUSE_SSLIP_BLACKLIST.getVarValue().compareToIgnoreCase(EnvironmentConfig.FEED_FORMAT) == 0) {
                    dataFromFile = cleanList(dataFromFile);
                }

                // ----------------------- Log and execute mapping from file to class -------------------------//
                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P2_MAP_JSON_TO_CLASS.getVarValue()).logDefToString());

                IPListObject ipListObject = new IPListObject(dataFromFile, EnvironmentConfig.FEED_THREAT_DESCRIPTION,
                        EnvironmentConfig.FEED_BASE_REPUTATION);

                // ----------------------- Log and execute transformation to Entity class -------------------------//
                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P3_TRANSFORM_TO_ENTITY.getVarValue()).logDefToString());

                FromIPListToEntity fromIPListToEntity = new FromIPListToEntity();
                fromIPListToEntity.transform(ipListObject, null);

                // ----------------------- Log and execute mapping Entity to JSON -------------------------//
                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P4_MAP_ENTITY_TO_JSON.getVarValue()).logDefToString());

                // ----------------------- Inserting via sdk -------------------------//
                IRequestExecutor mainJob = new RequestFactory(500).getExecutor();
                if (mainJob != null) {
                    String output = (String) mainJob.executeRequest(TWEndPointEnum.POST_ENTITIES.get(), fromIPListToEntity.getThreatIntEntityList());
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

    public static List<String> cleanList(List<String> origin) {
        List<String> cleanedList = new ArrayList<>();
        Iterator<String> it;
        for (it = origin.iterator(); it.hasNext(); ) {
            String attr = it.next().trim();
            if (!attr.startsWith("#")) {
                String[] arrayCSV = attr.split(",");
                cleanedList.add(arrayCSV[1].trim());
            }
        }
        return cleanedList;
    }
}
