package utm.threatintelligence.entity.transform.transf;

import utm.sdk.threatwinds.entity.ein.AttrEntity;
import utm.sdk.threatwinds.entity.ein.ThreatIntEntity;
import utm.threatintelligence.entity.ein.common.YaraRuleObject;
import utm.threatintelligence.enums.TWAttributeTypesEnum;
import utm.threatintelligence.interfaces.IEntityTransform;
import utm.threatintelligence.interfaces.ITransform;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class FromYaraToEntity implements IEntityTransform {

    private List<ThreatIntEntity> threatIntEntityList;

    public FromYaraToEntity() {
        threatIntEntityList = new ArrayList<>();
    }

    @Override
    public <T> T transform(T origin) throws Exception {
        if (origin instanceof ArrayList<?>) {
            ArrayList<YaraRuleObject> yaraRuleObjectList = (ArrayList<YaraRuleObject>) origin;
            Iterator<YaraRuleObject> it;
            for (it = yaraRuleObjectList.iterator(); it.hasNext(); ) {
                YaraRuleObject yaraRuleObject = it.next();
                ThreatIntEntity threatIntEntity = new ThreatIntEntity(
                    TWAttributeTypesEnum.TYPE_YARA_RULE.getValueType(),
                    yaraRuleObject.getRuleName(),
                    -3,
                    new ArrayList<>(),
                    new ArrayList<>()
                );
                threatIntEntity.setAttributes(convertYaraAttrToEntityAttr(new ArrayList<>(), yaraRuleObject, ""));

                threatIntEntityList.add(threatIntEntity);
            }
        }

        return (T) threatIntEntityList;
    }

    private ArrayList<AttrEntity> convertYaraAttrToEntityAttr(
        ArrayList<AttrEntity> toWriteOn,
        YaraRuleObject yaraRuleObject,
        String transformations
    ) throws Exception {
        // Creating strings attributes
        if (yaraRuleObject.getStrings() != null && yaraRuleObject.getStrings().size() != 0) {
            toWriteOn.addAll(convertYaraObjectListsToEntityAttr(new ArrayList<>(), yaraRuleObject.getStrings(), TWAttributeTypesEnum.TYPE_YARA_STRING_NAME.getValueType()));
        }
        // Creating condition attribute
        if (yaraRuleObject.getCondition() != null && yaraRuleObject.getCondition().compareTo("") != 0) {
            ArrayList<String> condition = new ArrayList<>();
            condition.add(yaraRuleObject.getCondition());
            toWriteOn.addAll(convertYaraObjectListsToEntityAttr(new ArrayList<>(), condition, TWAttributeTypesEnum.TYPE_YARA_CONDITION_NAME.getValueType()));
        }
        // Creating imports attributes
        if (yaraRuleObject.getImports() != null && yaraRuleObject.getImports().size() != 0) {
            toWriteOn.addAll(convertYaraObjectListsToEntityAttr(new ArrayList<>(), yaraRuleObject.getImports(), TWAttributeTypesEnum.TYPE_YARA_IMPORT_NAME.getValueType()));
        }
        // Creating modifier attribute
        if (yaraRuleObject.getModifier() != null && yaraRuleObject.getModifier().compareTo("") != 0) {
            ArrayList<String> modifier = new ArrayList<>();
            modifier.add(yaraRuleObject.getModifier());
            toWriteOn.addAll(convertYaraObjectListsToEntityAttr(new ArrayList<>(), modifier, TWAttributeTypesEnum.TYPE_YARA_MODIFIER_NAME.getValueType()));
        }
        return toWriteOn;
    }

    private ArrayList<AttrEntity> convertYaraObjectListsToEntityAttr(
        ArrayList<AttrEntity> toWriteOn,
        List<String> attrs,
        String TYPE
    ) throws Exception {
        Iterator<String> it;
        String name = "";
        String type = "";
        if (TYPE.compareTo(TWAttributeTypesEnum.TYPE_YARA_STRING_NAME.getValueType()) == 0) {
            name = TWAttributeTypesEnum.TYPE_YARA_STRING_NAME.getValueType();
            type = TWAttributeTypesEnum.TYPE_YARA_STRING.getValueType();
        } else if (TYPE.compareTo(TWAttributeTypesEnum.TYPE_YARA_CONDITION_NAME.getValueType()) == 0) {
            name = TWAttributeTypesEnum.TYPE_YARA_CONDITION_NAME.getValueType();
            type = TWAttributeTypesEnum.TYPE_YARA_CONDITION.getValueType();
        } else if (TYPE.compareTo(TWAttributeTypesEnum.TYPE_YARA_IMPORT_NAME.getValueType()) == 0) {
            name = TWAttributeTypesEnum.TYPE_YARA_IMPORT_NAME.getValueType();
            type = TWAttributeTypesEnum.TYPE_YARA_IMPORT.getValueType();
        } else if (TYPE.compareTo(TWAttributeTypesEnum.TYPE_YARA_MODIFIER_NAME.getValueType()) == 0) {
            name = TWAttributeTypesEnum.TYPE_YARA_MODIFIER_NAME.getValueType();
            type = TWAttributeTypesEnum.TYPE_YARA_MODIFIER.getValueType();
        }
        for (it = attrs.iterator(); it.hasNext(); ) {
            String attr = it.next();
            AttrEntity attrEntityTmp = new AttrEntity(
                name,
                "",
                new ThreatIntEntity(
                    type,
                    attr,
                    -3,
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
