package utm.threatintelligence.entity.ein.common;

/**
 * Is a class to define a generic model to insert objects in a list, this will used to define the principal element and its
 * associations, with this model you can define associations between elements even if they haven't the same type
 * */
public class CommonEntityObject {
    String type;
    String value;
    String description;
    Integer reputation;

    public CommonEntityObject(String type, String value, String description, Integer reputation) {
        this.type = type;
        this.value = value;
        this.description = (description==null || description.compareTo("")==0)?"Association element":description;
        this.reputation = (reputation==null || reputation < -3 || reputation > 0 )? -1:reputation;
    }
    public CommonEntityObject(){}

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Integer getReputation() {
        return reputation;
    }

    public void setReputation(Integer reputation) {
        this.reputation = reputation;
    }
}
