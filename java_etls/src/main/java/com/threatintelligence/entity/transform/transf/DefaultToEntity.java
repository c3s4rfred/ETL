package com.threatintelligence.entity.transform.transf;

import com.threatintelligence.interfaces.IEntityTransform;
import com.sdk.threatwinds.entity.ein.ThreatIntEntity;

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
