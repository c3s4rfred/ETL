package utm.threatintelligence.interfaces;

import utm.sdk.threatwinds.entity.ein.ThreatIntEntity;

import java.util.List;

public interface IEntityTransform {
    <T> T transform(T origin) throws Exception;
    List<ThreatIntEntity> getThreatIntEntityList();
}
