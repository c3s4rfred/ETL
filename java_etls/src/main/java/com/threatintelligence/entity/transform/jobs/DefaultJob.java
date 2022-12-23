package com.threatintelligence.entity.transform.jobs;

import com.threatintelligence.enums.EnvironmentsEnum;
import com.threatintelligence.enums.FeedTypeEnum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.threatintelligence.enums.FlowPhasesEnum;
import com.threatintelligence.enums.LogTypeEnum;
import com.threatintelligence.interfaces.IJobExecutor;
import com.threatintelligence.logging.LogDef;

public class DefaultJob implements IJobExecutor {
    private final Logger log = LoggerFactory.getLogger(OCJob.class);
    private static final String CLASSNAME = "DefaultJob";

    public DefaultJob (){}

    @Override
    public void executeFlow() throws Exception {
        final String ctx = CLASSNAME + ".executeDefaultSourceFeed";
        log.info(
                "*** The value of " +
                        EnvironmentsEnum.FEED_FORMAT +
                        " variable, didn't match with any ETL, make sure you provide a valid value. Executing default (Nothing) ***"
        );
        log.info(
                ctx +
                        ": " +
                        new LogDef(
                                LogTypeEnum.TYPE_EXECUTION.getVarValue(),
                                FeedTypeEnum.UNRECOGNIZED_FEED.getVarValue(),
                                FlowPhasesEnum.UNRECOGNIZED_PROCESS.getVarValue()
                        )
                                .logDefToString()
        );
    }
}
