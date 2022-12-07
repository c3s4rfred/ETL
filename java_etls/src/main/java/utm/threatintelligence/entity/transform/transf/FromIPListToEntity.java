package utm.threatintelligence.entity.transform.transf;

import utm.sdk.threatwinds.entity.ein.ThreatIntEntity;
import utm.threatintelligence.config.EnvironmentConfig;
import utm.threatintelligence.entity.ein.common.IPListObject;
import utm.threatintelligence.entity.ein.osint.circl.OCAttribute;
import utm.threatintelligence.enums.TWAttributeTypesEnum;
import utm.threatintelligence.interfaces.ITransform;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class FromIPListToEntity implements ITransform {

    private List<ThreatIntEntity> threatIntEntityList;

    public FromIPListToEntity() {
        threatIntEntityList = new ArrayList<>();
    }

    @Override
    public <T> T transform(T origin, T destination) throws Exception {
        if (origin instanceof IPListObject) {
           List<String> ipListObject = ((IPListObject) origin).getIpAddr();
            Iterator<String> it;

            for (it = ipListObject.iterator(); it.hasNext();) {
                String attr = it.next();
                ThreatIntEntity threatIntEntity = new ThreatIntEntity(
                        TWAttributeTypesEnum.TYPE_IP.getValueType(),
                        attr,
                        EnvironmentConfig.FEED_BASE_REPUTATION,
                        new ArrayList<>(),
                        new ArrayList<>()
                );
                threatIntEntityList.add(threatIntEntity);
            }
        }
        return (T) threatIntEntityList;
    }

    public List<ThreatIntEntity> getThreatIntEntityList() {
        return threatIntEntityList;
    }
}
