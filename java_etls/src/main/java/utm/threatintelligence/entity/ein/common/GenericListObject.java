package utm.threatintelligence.entity.ein.common;

import java.util.List;

public class GenericListObject {
    List<String> stringList;
    String description;
    Integer reputation;

    public GenericListObject(List<String> stringList, String description, Integer reputation) {
        this.stringList = stringList;
        this.description = (description==null || description.compareTo("")==0)?"Object List":description;
        this.reputation = (reputation==null || reputation < -3 || reputation > 0 )? -1:reputation;
    }
    public GenericListObject(){}

    public List<String> getStringList() {
        return stringList;
    }

    public void setStringList(List<String> stringList) {
        this.stringList = stringList;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
