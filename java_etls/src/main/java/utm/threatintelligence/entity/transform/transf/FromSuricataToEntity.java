package utm.threatintelligence.entity.transform.transf;

import utm.sdk.threatwinds.entity.ein.AttrEntity;
import utm.sdk.threatwinds.entity.ein.ThreatIntEntity;
import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.entity.ein.common.CommonEntityObject;
import utm.threatintelligence.entity.ein.common.ElementWithAssociations;
import utm.threatintelligence.enums.TWAttributeTypesEnum;
import utm.threatintelligence.interfaces.IEntityTransform;

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
