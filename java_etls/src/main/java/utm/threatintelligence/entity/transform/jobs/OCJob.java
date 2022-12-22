package utm.threatintelligence.entity.transform.jobs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utm.sdk.threatwinds.enums.TWEndPointEnum;
import utm.sdk.threatwinds.factory.RequestFactory;
import utm.sdk.threatwinds.interfaces.IRequestExecutor;
import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.entity.ein.osint.circl.OCJsonEvent;
import utm.threatintelligence.enums.FlowPhasesEnum;
import utm.threatintelligence.enums.LogTypeEnum;
import utm.threatintelligence.factory.TWTransformationFactory;
import utm.threatintelligence.interfaces.IEntityTransform;
import utm.threatintelligence.interfaces.IJobExecutor;
import utm.threatintelligence.interfaces.IProcessor;
import utm.threatintelligence.json.parser.GenericParser;
import utm.threatintelligence.logging.LogDef;
import utm.threatintelligence.readers.FileStreamReader;
import utm.threatintelligence.scraper.LinkListGenerator;
import utm.threatintelligence.scraper.LinkPage;
import utm.threatintelligence.urlcreator.OsintCirclUrlCreator;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class OCJob implements IJobExecutor {
    private final Logger log = LoggerFactory.getLogger(OCJob.class);
    private static final String CLASSNAME = "OCJob";

    public OCJob() {
    }

    @Override
    public void executeFlow() throws Exception {
        final String ctx = CLASSNAME + ".executeOsint";
        String feedSelected = EnvironmentConfig.FEED_FORMAT;

        // ----------------------- Log the process init -------------------------//
        log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), feedSelected,
                FlowPhasesEnum.P0_BEGIN_PROCESS.getVarValue()).logDefToString());

        // ----------------------- Log the feed scrap to search for links -------------------------//
        IProcessor lpro = new LinkListGenerator();
        try {
            lpro.process(EnvironmentConfig.FEED_URL);
        } catch (Exception ex) {
            log.error(ctx + ": " + new LogDef(LogTypeEnum.TYPE_ERROR.getVarValue(), feedSelected,
                    "Problem getting data from host: " + ex.getLocalizedMessage()).logDefToString());
        }

        //First we create fixed thread pool executor with 8 threads, one per file
        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(EnvironmentConfig.THREAD_POOL_SIZE);

        //--------------------------------The concurrent ETL process is here-------------------------------------------
        while (LinkPage.getListOfLinks().size() > 0) {
            executor.execute(new OCParallelTask((String) LinkPage.getListOfLinks().remove(0)));
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

    public class OCParallelTask implements Runnable {

        String link;

        public OCParallelTask(String link) {
            this.link = link;
        }

        @Override
        public void run() {
            final String ctx = CLASSNAME + ".parallelExecutor";
            GenericParser gp = new GenericParser();
            FileStreamReader reader = new FileStreamReader();
            String linkToProcess = "";

            try {
                // ----------------------- Log and execute the file reading from internet -------------------------//
                linkToProcess = this.link;
                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P1_READ_FILE.getVarValue()).logDefToString());

                String jsonFromFile = reader.readFile(
                        new OsintCirclUrlCreator().createURL(linkToProcess, EnvironmentConfig.LINK_SEPARATOR)
                );

                // ----------------------- Log and execute mapping from JSON file to class -------------------------//
                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P2_MAP_JSON_TO_CLASS.getVarValue()).logDefToString());

                OCJsonEvent circl = gp.parseFrom(jsonFromFile, OCJsonEvent.class, new OCJsonEvent());

                // ----------------------- Log and execute transformation to Entity class -------------------------//
                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P3_TRANSFORM_TO_ENTITY.getVarValue()).logDefToString());

                IEntityTransform fromSomethingToEntity = new TWTransformationFactory().getTransformation();
                fromSomethingToEntity.transform(circl);

                // ----------------------- Log and execute mapping Entity to JSON -------------------------//
                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P4_MAP_ENTITY_TO_JSON.getVarValue()).logDefToString());

                // ----------------------- Inserting via sdk -------------------------//
                IRequestExecutor mainJob = new RequestFactory(1).getExecutor();
                if (mainJob != null) {
                    String output = (String) mainJob.executeRequest(TWEndPointEnum.POST_ENTITIES.get(), fromSomethingToEntity.getThreatIntEntityList());
                    log.info(ctx + " " + linkToProcess + ": " + output);
                }

                log.info(ctx + ": " + new LogDef(LogTypeEnum.TYPE_EXECUTION.getVarValue(), linkToProcess,
                        FlowPhasesEnum.P5_END_FILE_PROCESS.getVarValue()).logDefToString());
            } catch (Exception jne) {
                log.error(ctx + ": " + new LogDef(LogTypeEnum.TYPE_ERROR.getVarValue(), linkToProcess,
                        jne.getLocalizedMessage()).logDefToString());
            }
        }
    }
}
