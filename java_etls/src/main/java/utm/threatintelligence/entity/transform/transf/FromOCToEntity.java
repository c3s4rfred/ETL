package utm.threatintelligence.entity.transform.transf;

import java.util.*;
import utm.threatintelligence.config.EnvironmentConfig;
import utm.sdk.threatwinds.entity.ein.AttrEntity;
import utm.sdk.threatwinds.entity.ein.ThreatIntEntity;
import utm.threatintelligence.entity.ein.common.YaraRuleObject;
import utm.threatintelligence.entity.ein.github.yara.GHYaraExtractor;
import utm.threatintelligence.entity.ein.osint.circl.OCAttribute;
import utm.threatintelligence.entity.ein.osint.circl.OCEvent;
import utm.threatintelligence.entity.ein.osint.circl.OCJsonEvent;
import utm.threatintelligence.entity.ein.osint.circl.OCObject;
import utm.threatintelligence.enums.TWAttributeTypesEnum;
import utm.threatintelligence.enums.TransformationEnum;
import utm.threatintelligence.enums.osint.circl.OCReputationEnum;
import utm.threatintelligence.enums.osint.circl.OCSpecificTypesToCheck;
import utm.threatintelligence.interfaces.IEntityTransform;
import utm.threatintelligence.interfaces.ITransform;
import utm.threatintelligence.utilities.UtilitiesService;

public class FromOCToEntity implements IEntityTransform {

    private List<ThreatIntEntity> threatIntEntityList;
    private final String typeTransf = TransformationEnum.TYPE_TRANSFORMATION.getVarValue();
    private final String reputationTransf = TransformationEnum.REPUTATION_TRANSFORMATION.getVarValue();
    private final String valueUrlTransf = TransformationEnum.VALUE_URLS_TRANSFORMATION.getVarValue();
    private final String emailComponentsTransf = TransformationEnum.EMAIL_COMPONENTS_TRANSFORMATION.getVarValue();
    private final String miscTypeTransformation = TransformationEnum.MISC_TYPE_TRANSFORMATION.getVarValue();
    private final String datetimeValueTransformation = TransformationEnum.DATETIME_VALUE_TRANSFORMATION.getVarValue();
    private final String yaraTypeTransformation = TransformationEnum.ATTRIBUTE_TYPE_YARA_TRANSFORMATION.getVarValue();
    private Integer BASE_REPUTATION = -100;

    public FromOCToEntity() {
        threatIntEntityList = new ArrayList<>();
    }

    @Override
    public <T> T transform(T origin) throws Exception {
        String transformationsToApply = typeTransf + reputationTransf + valueUrlTransf + emailComponentsTransf +
                miscTypeTransformation + datetimeValueTransformation + yaraTypeTransformation;
        if (origin instanceof OCJsonEvent) {
            OCEvent localEvt = ((OCJsonEvent) origin).getEvent();
            setBASE_REPUTATION(OCReputationEnum.getRepValueByOCThreatLvlId(localEvt.getThreat_level_id()));
            ThreatIntEntity threatIntEntity = new ThreatIntEntity(
                EnvironmentConfig.TW_API_ENTITY_BASE_TYPE,
                localEvt.getInfo(),
                BASE_REPUTATION,
                new ArrayList<>(),
                new ArrayList<>()
            );

            if (localEvt.getAttributes() != null && localEvt.getAttributes().size() != 0) {
                threatIntEntity.setAttributes(
                    convertOCAttrToEntityAttr(
                        (ArrayList<AttrEntity>) threatIntEntity.getAttributes(),
                        localEvt.getAttributes(),
                        transformationsToApply,
                        TWAttributeTypesEnum.TYPE_NORMAL.getValueType()
                    )
                );
            }
            if (localEvt.getObjects() != null && localEvt.getObjects().size() != 0) {
                threatIntEntity.setAssociations(
                    convertOCObjectToEntityAssoc(
                        (ArrayList<AttrEntity>) threatIntEntity.getAssociations(),
                        localEvt.getObjects(),
                        transformationsToApply
                    )
                );
            }

            threatIntEntityList.add(threatIntEntity);
        }
        return (T) threatIntEntityList;
    }

    /* Method to generate the list of AttrEntity based on a list of OCAttribute
     *  Iterates the OCAttribute list and create for each one, an AttrEntity, checks
     *  if its a TYPE_OBJECT (Comes from the Object in OSINT json) or "normal" attribute, in case of "normal" it checks if is
     *  compound one*/
    private ArrayList<AttrEntity> convertOCAttrToEntityAttr(
        ArrayList<AttrEntity> toWriteOn,
        List<OCAttribute> Attributes,
        String transformations,
        String attrType
    ) throws Exception {
        Iterator<OCAttribute> it;

        for (it = Attributes.iterator(); it.hasNext();) {
            OCAttribute attr = it.next();
            toWriteOn.addAll(getAttributesBySplitType(attr, transformations, attrType));
        }

        return toWriteOn;
    }

    private ArrayList<AttrEntity> convertOCObjectToEntityAssoc(
        ArrayList<AttrEntity> toWriteOn,
        List<OCObject> objectList,
        String transformations
    ) throws Exception {
        Iterator<OCObject> it;
        for (it = objectList.iterator(); it.hasNext();) {
            OCObject objTemp = it.next();
            AttrEntity attrEntityTmp = new AttrEntity(
                "",
                objTemp.getComment(),
                new ThreatIntEntity(
                    TWAttributeTypesEnum.TYPE_OBJECT.getValueType(),
                    objTemp.getUuid(),
                    BASE_REPUTATION,
                    new ArrayList<>(),
                    new ArrayList<>()
                )
            );
            attrEntityTmp.setEntity(applyTransformations(transformations, attrEntityTmp.getEntity(), null));
            // Add descriptor attribute
            attrEntityTmp.getEntity().getAttributes().add(getDescriptorAttribute(objTemp, transformations));
            // Then add rest of attributes
            attrEntityTmp
                .getEntity()
                .setAttributes(
                    convertOCAttrToEntityAttr(
                        (ArrayList<AttrEntity>) attrEntityTmp.getEntity().getAttributes(),
                        objTemp.getAttributes(),
                        transformations,
                        TWAttributeTypesEnum.TYPE_OBJECT.getValueType()
                    )
                );
            toWriteOn.add(attrEntityTmp);
        }

        return toWriteOn;
    }

    /*Transformations are over a ThreatIntEntity objects, they get executed sequentially, so
     * if you perform a transformation on a field value (for example set to "First"), and after that, perform another
     * transformation on the same field value (for example set to "Second"), the final value will be "Second"*/
    public ThreatIntEntity applyTransformations(String transformation, ThreatIntEntity valueToTransform, OCAttribute somethingToCheck)
        throws Exception {
        ITransform baseTransf;
        // Transformation for types are executed
        if (transformation.contains(typeTransf)) {
            baseTransf = new OCTypeTransform();
            valueToTransform.setType(baseTransf.transform(valueToTransform.getType(), ""));
        }
        // Reputation transformation for some specific types like virus total report are executed
        if (transformation.contains(reputationTransf)) {
            if (
                valueToTransform.getType().compareTo(OCSpecificTypesToCheck.VIRUS_TOTAL_REPORT.getTypeChecked()) == 0 ||
                valueToTransform.getValue().compareTo(OCSpecificTypesToCheck.VIRUS_TOTAL_REPORT.getTypeChecked()) == 0
            ) {
                valueToTransform.setReputation(0);
            } else {
                if ((somethingToCheck != null) && !somethingToCheck.getTo_ids()) {
                    valueToTransform.setReputation(0);
                }
            }
        }
        // Transformation for the value of URLs and LINKs are executed
        if (transformation.contains(valueUrlTransf)) {
            if (
                valueToTransform.getType().compareToIgnoreCase(OCSpecificTypesToCheck.LINK.getTypeChecked()) == 0 ||
                valueToTransform.getType().compareToIgnoreCase(OCSpecificTypesToCheck.URL.getTypeChecked()) == 0
            ) {
                String vToCheck = valueToTransform.getValue();
                if (vToCheck.matches("(.+)(https|http)(://)(.+)")) {
                    valueToTransform.setValue(vToCheck.replaceFirst("(.+)(https|http)", "$2"));
                } else if (!vToCheck.matches("^(https|http)(://)(.+)")) {
                    vToCheck = "https://" + vToCheck;
                    valueToTransform.setValue(vToCheck);
                }
            }
        }
        // Transformation for the value of datetime are executed
        if (transformation.contains(datetimeValueTransformation)) {
            if (valueToTransform.getType().compareToIgnoreCase(OCSpecificTypesToCheck.DATE_TIME.getTypeChecked()) == 0) {
                String vToCheck = valueToTransform.getValue();
                valueToTransform.setValue(UtilitiesService.getEpochFormatDate(vToCheck));
            }
        }
        return valueToTransform;
    }

    public AttrEntity applyTransformations(String transformation, AttrEntity valueToTransform, OCAttribute somethingToCheck)
        throws Exception {
        ITransform baseTransf;
        // Transformation for some email components are executed
        if (transformation.contains(emailComponentsTransf)) {
            baseTransf = new OCEmailComponentsTypeTransform();
            valueToTransform.setName(baseTransf.transform(valueToTransform.getName(), ""));
        }
        // Transformation for miscellaneous types are executed
        if (transformation.contains(miscTypeTransformation)) {
            baseTransf = new OCMiscelaneousTypeTransform();
            valueToTransform.setName(baseTransf.transform(valueToTransform.getName(), ""));
        }
        // Transformation of types are executed
        if (transformation.contains(typeTransf)) {
            baseTransf = new OCTypeTransform();
            valueToTransform.setName(baseTransf.transform(valueToTransform.getName(), ""));
        }
        // Transformation of type = yara (generating threat winds yara object)
        if (transformation.contains(yaraTypeTransformation)) {
            baseTransf = new OCYaraTypeTransform();
            valueToTransform.setEntity((ThreatIntEntity)baseTransf.transform(valueToTransform.getEntity(), ""));
        }
        return valueToTransform;
    }

    /*Some OSINT Types and its values are composed like md5|hash, so we have to create
     * one AttrEntity for each value in array (array = split by "|")*/
    public ArrayList<AttrEntity> getAttributesBySplitType(OCAttribute ocAttr, String transformations, String attrType) throws Exception {
        ArrayList<AttrEntity> toWriteOn = new ArrayList<>();
        if (ocAttr.getType().matches("(.+)\\|(.+)")) {
            // Create one AttrEntity for each value in array
            String[] splitArrayTypes = ocAttr.getType().split("\\|");
            String[] splitArrayValues = ocAttr.getValue().split("\\|");

            for (int i = 0; i < splitArrayTypes.length; i++) {
                AttrEntity attrEntityTmp;
                ThreatIntEntity attrOrObjectEntity = new ThreatIntEntity(
                    splitArrayTypes[i],
                    splitArrayValues[i],
                    BASE_REPUTATION,
                    new ArrayList<>(),
                    new ArrayList<>()
                );
                if (attrType.compareTo(TWAttributeTypesEnum.TYPE_OBJECT.getValueType()) == 0) {
                    // In case of attributes of osint objects, the name is the value of object relation
                    // field; if the value is composed we check the split value position, in case of error (no value at the position)
                    // returns the inner value (full)
                    String objRel = (String) ocAttr.getObject_relation();
                    String finalRelToName;
                    if (objRel.matches("(.+)\\|(.+)")) {
                        try {
                            finalRelToName = objRel.split("\\|")[i];
                        } catch (NullPointerException npe) {
                            finalRelToName = objRel;
                        }
                    } else {
                        finalRelToName = objRel;
                    }
                    attrEntityTmp =
                        applyTransformations(
                            transformations,
                            new AttrEntity(finalRelToName, ocAttr.getComment(), attrOrObjectEntity),
                            ocAttr
                        );
                } else {
                    attrEntityTmp =
                        applyTransformations(
                            transformations,
                            new AttrEntity(splitArrayTypes[i], ocAttr.getComment(), attrOrObjectEntity),
                            ocAttr
                        );
                }

                attrEntityTmp.setEntity(applyTransformations(transformations, attrEntityTmp.getEntity(), ocAttr));
                toWriteOn.add(attrEntityTmp);
            }
            // End for loop
        } else {
            // Only one is created
            AttrEntity attrEntityTmp;
            ThreatIntEntity attrOrObjectEntity = new ThreatIntEntity(
                ocAttr.getType(),
                ocAttr.getValue(),
                BASE_REPUTATION,
                new ArrayList<>(),
                new ArrayList<>()
            );
            if (attrType.compareTo(TWAttributeTypesEnum.TYPE_OBJECT.getValueType()) == 0) {
                attrEntityTmp =
                    applyTransformations(
                        transformations,
                        new AttrEntity((String) ocAttr.getObject_relation(), ocAttr.getComment(), attrOrObjectEntity),
                        ocAttr
                    );
            } else {
                attrEntityTmp =
                    applyTransformations(
                        transformations,
                        new AttrEntity(ocAttr.getType(), ocAttr.getComment(), attrOrObjectEntity),
                        ocAttr
                    );
            }

            attrEntityTmp.setEntity(applyTransformations(transformations, attrEntityTmp.getEntity(), ocAttr));
            toWriteOn.add(attrEntityTmp);
        }

        return toWriteOn;
    }

    // Method to generate an AttrEntity (New attribute) as a descriptor of the every OSINT Object (each child of Object node in json)
    public AttrEntity getDescriptorAttribute(OCObject ocObject, String transformations) throws Exception {
        AttrEntity descriptor = new AttrEntity(
            TWAttributeTypesEnum.TYPE_DESCRIPTOR.getValueType(),
            ocObject.getComment(),
            new ThreatIntEntity(
                TWAttributeTypesEnum.TYPE_SENSITIVE_TEXT.getValueType(),
                ocObject.getName(),
                BASE_REPUTATION,
                new ArrayList<>(),
                new ArrayList<>()
            )
        );
        descriptor.setEntity(applyTransformations(transformations, descriptor.getEntity(), null));
        return descriptor;
    }

    @Override
    public List<ThreatIntEntity> getThreatIntEntityList() {
        return threatIntEntityList;
    }

    public void setThreatIntEntityList(List<ThreatIntEntity> threatIntEntityList) {
        this.threatIntEntityList = threatIntEntityList;
    }

    public void setBASE_REPUTATION(Integer threat_level_id) {
        try {
            this.BASE_REPUTATION = this.BASE_REPUTATION == -100 ? threat_level_id : this.BASE_REPUTATION;
        } catch (NumberFormatException nfe) {
            this.BASE_REPUTATION = -1;
        }
    }

    //************************ Transformation classes goes here ****************************//
    // Implementation of utilities to transform something, in this case the type
    public static class OCTypeTransform implements ITransform {

        public OCTypeTransform() {}

        @Override
        public <T> T transform(T origin, T destination) throws Exception {
            String checkType = (String) origin;
            if (checkType.compareToIgnoreCase("ip-dst") == 0) {
                return (T) ("ip");
            } else if (checkType.compareToIgnoreCase("ip-src") == 0) {
                return (T) ("ip");
            } else if (checkType.compareToIgnoreCase("JARM-fingerprint") == 0) {
                return (T) ("jarm-fingerprint");
            } else if (checkType.compareToIgnoreCase("JARM") == 0) {
                return (T) ("jarm-fingerprint");
            } else if (checkType.contains("link")) {
                return (T) ("link");
            } else if (checkType.compareToIgnoreCase("original-imported-file") == 0) {
                return (T) ("file");
            } else if (checkType.compareToIgnoreCase("attachment") == 0) {
                return (T) ("filename");
            } else if (checkType.compareToIgnoreCase("port") == 0) {
                return (T) ("integer");
            } else if (checkType.compareToIgnoreCase("vulnerability") == 0) {
                return (T) ("cve");
            } else if (checkType.compareToIgnoreCase("comment") == 0) {
                return (T) ("text");
            } else if (checkType.compareToIgnoreCase("email-src") == 0) {
                return (T) ("email-address");
            } else if (checkType.compareToIgnoreCase("email-dst") == 0) {
                return (T) ("email-address");
            } else if (checkType.compareToIgnoreCase("email-reply-to") == 0) {
                return (T) ("email-address");
            } else if (checkType.compareToIgnoreCase("email-src-display-name") == 0) {
                return (T) ("email-display-name");
            } else if (checkType.compareToIgnoreCase("email-dst-display-name") == 0) {
                return (T) ("email-display-name");
            } else if (checkType.compareToIgnoreCase("email-message-id") == 0) {
                return (T) ("email");
            } else if (checkType.compareToIgnoreCase("whois-registrant-email") == 0) {
                return (T) ("email-address");
            } else if (checkType.compareToIgnoreCase("dns-soa-email") == 0) {
                return (T) ("email-address");
            } else if (checkType.compareToIgnoreCase("email-attachment") == 0) {
                return (T) ("filename");
            } else if (checkType.compareToIgnoreCase("report") == 0) {
                return (T) ("text");
            } else if (checkType.compareToIgnoreCase("ssdeep") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("imphash") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("pdb") == 0) {
                return (T) ("path");
            } else if (checkType.compareToIgnoreCase("crypto-material") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("value") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("mutex") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("other") == 0) {
                return (T) ("text");
            } else if (checkType.compareToIgnoreCase("annotation") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("user-agent") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("uri") == 0) {
                return (T) ("path");
            } else if (checkType.compareToIgnoreCase("target-org") == 0) {
                return (T) ("ASO");
            } else if (checkType.compareToIgnoreCase("github-username") == 0) {
                return (T) ("github-user");
            } else if (checkType.compareToIgnoreCase("counter") == 0) {
                return (T) ("integer");
            } else if (checkType.compareToIgnoreCase("stix2-pattern") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("target-location") == 0) {
                return (T) ("country-name");
            } else if (checkType.compareToIgnoreCase("phone-number") == 0) {
                return (T) ("phone");
            } else if (checkType.compareToIgnoreCase("nationality") == 0) {
                return (T) ("country-name");
            } else if (checkType.compareToIgnoreCase("named pipe") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("AS") == 0) {
                return (T) ("ASO");
            } else if (checkType.compareToIgnoreCase("http-method") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("campaign-name") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("target-user") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("mobile-application-id") == 0) {
                return (T) ("mobile-app-id");
            } else if (checkType.compareToIgnoreCase("target-external") == 0) {
                return (T) ("ASO");
            } else if (checkType.compareToIgnoreCase("whois-creation-date") == 0) {
                return (T) ("datetime");
            } else if (checkType.compareToIgnoreCase("campaign-id") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("pehash") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("threat-actor") == 0) {
                return (T) ("adversary");
            } else if (checkType.compareToIgnoreCase("weakness") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("tlsh") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("sha512/224") == 0) {
                return (T) ("sha512-224");
            } else if (checkType.compareToIgnoreCase("sha512/256") == 0) {
                return (T) ("sha512-256");
            } else if (checkType.compareToIgnoreCase("authentihash") == 0) {
                return (T) ("md5");
            } else if (checkType.compareToIgnoreCase("vhash") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("sigma") == 0) {
                return (T) ("sensitive-text");
            } else if (checkType.compareToIgnoreCase("x509-fingerprint-md5") == 0) {
                return (T) ("md5");
            } else if (checkType.compareToIgnoreCase("x509-fingerprint-sha1") == 0) {
                return (T) ("sha1");
            } else if (checkType.compareToIgnoreCase("x509-fingerprint-sha256") == 0) {
                return (T) ("sha256");
            }
            return (T) checkType;
        }
    }

    // Transformation of specific email components like email-src and email-dst type, for AttrEntity
    public static class OCEmailComponentsTypeTransform implements ITransform {

        public OCEmailComponentsTypeTransform() {}

        @Override
        public <T> T transform(T origin, T destination) throws Exception {
            String checkType = (String) origin;
            if (checkType.compareToIgnoreCase("email-src") == 0) {
                return (T) ("from");
            } else if (checkType.compareToIgnoreCase("email-dst") == 0) {
                return (T) ("to");
            } else if (checkType.compareToIgnoreCase("email-reply-to") == 0) {
                return (T) ("to");
            } else if (checkType.compareToIgnoreCase("reply-to") == 0) {
                return (T) ("to");
            } else if (checkType.compareToIgnoreCase("from-display-name") == 0) {
                return (T) ("display-name");
            } else if (checkType.compareToIgnoreCase("to-display-name") == 0) {
                return (T) ("display-name");
            } else if (checkType.compareToIgnoreCase("return-path") == 0) {
                return (T) ("from");
            } else if (checkType.compareToIgnoreCase("email-body") == 0) {
                return (T) ("body");
            } else if (checkType.compareToIgnoreCase("registrant-email") == 0) {
                return (T) ("from");
            } else if (checkType.compareToIgnoreCase("email-attachment") == 0) {
                return (T) ("attachment");
            } else if (checkType.compareToIgnoreCase("email-message-id") == 0) {
                return (T) ("email");
            } else if (checkType.compareToIgnoreCase("dns-soa-email") == 0) {
                return (T) ("from");
            }
            return (T) checkType;
        }
    }

    // Transformation of miscelaneous types, for AttrEntity
    public static class OCMiscelaneousTypeTransform implements ITransform {

        public OCMiscelaneousTypeTransform() {}

        @Override
        public <T> T transform(T origin, T destination) throws Exception {
            String checkType = (String) origin;
            if (checkType.compareToIgnoreCase("weakness") == 0) {
                return (T) ("cwe");
            }
            return (T) checkType;
        }
    }

    // Transformation of type = yara, for AttrEntity
    public static class OCYaraTypeTransform implements ITransform {

        public OCYaraTypeTransform() {}

        @Override
        public <T> T transform(T origin, T destination) throws Exception {
            ThreatIntEntity checkType = (ThreatIntEntity) origin;
            if (checkType.getType().compareToIgnoreCase(OCSpecificTypesToCheck.YARA_RULE.getTypeChecked()) == 0) {
                try {
                    GHYaraExtractor yaraExtractor = new GHYaraExtractor(checkType.getValue());
                    ArrayList<YaraRuleObject> yaraRuleObjects = yaraExtractor.getYaraRuleObjects();
                    FromYaraToEntity fromYaraToEntity = new FromYaraToEntity();
                    fromYaraToEntity.transform(yaraRuleObjects);
                    ThreatIntEntity yaraEntity = fromYaraToEntity.getThreatIntEntityList().get(0);
                    return (T) yaraEntity;
                } catch (Exception ex) {
                    checkType.setType(TWAttributeTypesEnum.TYPE_SENSITIVE_TEXT.getValueType());
                    return (T)checkType;
                }

            }
            return (T) checkType;
        }
    }
    //************************ Transformation classes End **********************************//
}
