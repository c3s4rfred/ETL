package utm.threatintelligence.entity.transform.transf;

import utm.sdk.threatwinds.entity.ein.ThreatIntEntity;
import utm.threatintelligence.interfaces.IEntityTransform;

import java.util.ArrayList;
import java.util.List;

public class DefaultToEntity implements IEntityTransform {

    private List<ThreatIntEntity> threatIntEntityList;

    public DefaultToEntity() {
        threatIntEntityList = new ArrayList<>();
    }

    @Override
    public <T> T transform(T origin) throws Exception {
        return (T)threatIntEntityList;
    }
    @Override
    public List<ThreatIntEntity> getThreatIntEntityList() {
        return threatIntEntityList;
    }
}
