package utm.threatintelligence.entity.ein.osint.circl;

public class OCAttribute {

    String comment;
    String category;
    String uuid;
    String timestamp;
    Boolean to_ids;
    String value;
    Boolean disable_correlation;
    Object object_relation;
    String type;

    public OCAttribute(
        String comment,
        String category,
        String uuid,
        String timestamp,
        Boolean to_ids,
        String value,
        Boolean disable_correlation,
        Object object_relation,
        String type
    ) {
        this.comment = comment;
        this.category = category;
        this.uuid = uuid;
        this.timestamp = timestamp;
        this.to_ids = to_ids;
        this.value = value;
        this.disable_correlation = disable_correlation;
        this.object_relation = object_relation;
        this.type = type;
    }

    public OCAttribute() {}

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public Boolean getTo_ids() {
        return to_ids != null ? to_ids : true;
    }

    public void setTo_ids(Boolean to_ids) {
        this.to_ids = to_ids;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Boolean getDisable_correlation() {
        return disable_correlation;
    }

    public void setDisable_correlation(Boolean disable_correlation) {
        this.disable_correlation = disable_correlation;
    }

    public Object getObject_relation() {
        return object_relation;
    }

    public void setObject_relation(Object object_relation) {
        this.object_relation = object_relation;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
