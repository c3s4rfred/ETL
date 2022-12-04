package utm.threatintelligence.entity.ein.osint.circl;

import java.util.List;

public class OCEvent {

    String info;
    List<OCTag> Tag;
    String publish_timestamp;
    String timestamp;
    String analysis;
    List<OCAttribute> Attribute;
    String extends_uuid;
    Boolean published;
    String date;
    OCOrgc Orgc;
    String threat_level_id;
    String uuid;
    List<OCObject> Object;

    public OCEvent(
        String info,
        List<OCTag> Tag,
        String publish_timestamp,
        String timestamp,
        String analysis,
        List<OCAttribute> attribute,
        String extends_uuid,
        Boolean published,
        String date,
        OCOrgc orgc,
        String threat_level_id,
        String uuid,
        List<OCObject> Object
    ) {
        this.info = info;
        this.Tag = Tag;
        this.publish_timestamp = publish_timestamp;
        this.timestamp = timestamp;
        this.analysis = analysis;
        Attribute = attribute;
        this.extends_uuid = extends_uuid;
        this.published = published;
        this.date = date;
        Orgc = orgc;
        this.threat_level_id = threat_level_id;
        this.uuid = uuid;
        this.Object = Object;
    }

    public OCEvent() {}

    public String getInfo() {
        return info;
    }

    public void setInfo(String info) {
        this.info = info;
    }

    public List<OCTag> getTag() {
        return Tag;
    }

    public void setTag(List<OCTag> OCTag) {
        this.Tag = OCTag;
    }

    public String getPublish_timestamp() {
        return publish_timestamp;
    }

    public void setPublish_timestamp(String publish_timestamp) {
        this.publish_timestamp = publish_timestamp;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getAnalysis() {
        return analysis;
    }

    public void setAnalysis(String analysis) {
        this.analysis = analysis;
    }

    public List<OCAttribute> getAttributes() {
        return Attribute;
    }

    public void setAttributes(List<OCAttribute> attributes) {
        Attribute = attributes;
    }

    public String getExtends_uuid() {
        return extends_uuid;
    }

    public void setExtends_uuid(String extends_uuid) {
        this.extends_uuid = extends_uuid;
    }

    public Boolean getPublished() {
        return published;
    }

    public void setPublished(Boolean published) {
        this.published = published;
    }

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public OCOrgc getOrgc() {
        return Orgc;
    }

    public void setOrgc(OCOrgc orgc) {
        Orgc = orgc;
    }

    public String getThreat_level_id() {
        return threat_level_id;
    }

    public void setThreat_level_id(String threat_level_id) {
        this.threat_level_id = threat_level_id;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public List<OCObject> getObjects() {
        return Object;
    }

    public void setObjects(List<OCObject> objects) {
        Object = objects;
    }
}
