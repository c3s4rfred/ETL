package com.threatintelligence.interfaces;

import com.sdk.threatwinds.entity.ein.ThreatIntEntity;

import java.util.List;

public interface IEntityTransform {
    <T> T transform(T origin) throws Exception;
    List<ThreatIntEntity> getThreatIntEntityList();
}
