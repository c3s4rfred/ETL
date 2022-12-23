package com.threatintelligence.entity.transform.transf;

import com.threatintelligence.config.EnvironmentConfig;
import com.threatintelligence.entity.ein.common.CommonEntityObject;
import com.threatintelligence.entity.ein.common.ElementWithAssociations;
import com.threatintelligence.interfaces.IEntityTransform;
import com.sdk.threatwinds.entity.ein.AttrEntity;
import com.sdk.threatwinds.entity.ein.ThreatIntEntity;
import com.threatintelligence.enums.TWAttributeTypesEnum;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class FromElementListToEntity implements IEntityTransform {

    private List<ThreatIntEntity> threatIntEntityList;

    public FromElementListToEntity() {
        threatIntEntityList = new ArrayList<>();
    }

    @Override
    public <T> T transform(T origin) throws Exception {
        if (origin instanceof List) {
            List<ElementWithAssociations> listObject = (List<ElementWithAssociations>) origin;
            Iterator<ElementWithAssociations> it;

            for (it = listObject.iterator(); it.hasNext(); ) {
                ElementWithAssociations elementWithAssociations = it.next();
                CommonEntityObject principal = elementWithAssociations.getPrincipal();
                String finalType = "";
                if (principal.getType().compareTo(TWAttributeTypesEnum.TYPE_IP.getValueType()) == 0) {
                    finalType = (principal.getValue().contains("/")) ? TWAttributeTypesEnum.TYPE_CIDR.getValueType() : TWAttributeTypesEnum.TYPE_IP.getValueType();
                } else {
                    finalType = principal.getType();
                }
                ThreatIntEntity threatIntEntity = new ThreatIntEntity(
                        finalType,
                        principal.getValue(),
                        EnvironmentConfig.FEED_BASE_REPUTATION,
                        new ArrayList<>(),
                        new ArrayList<>()
                );
                // Generate associations
                threatIntEntity.setAssociations(listAssocToEntityAssoc(elementWithAssociations.getAssociations(),
                        (ArrayList<AttrEntity>) threatIntEntity.getAssociations()));
                threatIntEntityList.add(threatIntEntity);
            }
        }
        return (T) threatIntEntityList;
    }

    public ArrayList<AttrEntity> listAssocToEntityAssoc(List<CommonEntityObject> associations,
                                                        ArrayList<AttrEntity> toWriteOn) throws Exception {
        Iterator<CommonEntityObject> it;
        for (it = associations.iterator(); it.hasNext(); ) {
            CommonEntityObject commonEntityObjectTMP = it.next();
            String finalType = "";
            if (commonEntityObjectTMP.getType().compareTo(TWAttributeTypesEnum.TYPE_IP.getValueType()) == 0) {
                finalType = (commonEntityObjectTMP.getValue().contains("/")) ? TWAttributeTypesEnum.TYPE_CIDR.getValueType() : TWAttributeTypesEnum.TYPE_IP.getValueType();
            } else {
                finalType = commonEntityObjectTMP.getType();
            }
            AttrEntity attrEntityTmp = new AttrEntity(
                    "",
                    "",
                    new ThreatIntEntity(
                            finalType,
                            commonEntityObjectTMP.getValue(),
                            commonEntityObjectTMP.getReputation(),
                            new ArrayList<>(),
                            new ArrayList<>()
                    )
            );
            toWriteOn.add(attrEntityTmp);
        }
        return toWriteOn;
    }
    @Override
    public List<ThreatIntEntity> getThreatIntEntityList() {
        return threatIntEntityList;
    }
}
