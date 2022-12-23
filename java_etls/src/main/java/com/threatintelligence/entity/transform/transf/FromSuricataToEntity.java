package com.threatintelligence.entity.transform.transf;

import com.sdk.threatwinds.entity.ein.ThreatIntEntity;
import com.threatintelligence.config.EnvironmentConfig;
import com.threatintelligence.enums.TWAttributeTypesEnum;
import com.threatintelligence.interfaces.IEntityTransform;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class FromSuricataToEntity implements IEntityTransform {

    private List<ThreatIntEntity> threatIntEntityList;

    public FromSuricataToEntity() {
        threatIntEntityList = new ArrayList<>();
    }

    @Override
    public <T> T transform(T origin) throws Exception {
        if (origin instanceof List) {
            List<String> listObject = (List<String>) origin;
            Iterator<String> it;

            for (it = listObject.iterator(); it.hasNext(); ) {
                String suricataRule = it.next();
                ThreatIntEntity threatIntEntity = new ThreatIntEntity(
                        TWAttributeTypesEnum.TYPE_SURICATA_RULE.getValueType(),
                        suricataRule,
                        EnvironmentConfig.FEED_BASE_REPUTATION,
                        new ArrayList<>(),
                        new ArrayList<>()
                );
                threatIntEntityList.add(threatIntEntity);
            }
        }
        return (T) threatIntEntityList;
    }

    @Override
    public List<ThreatIntEntity> getThreatIntEntityList() {
        return threatIntEntityList;
    }
}
