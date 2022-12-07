package utm.threatintelligence.entity.ein.common;

import java.util.List;

public class IPListObject {
    List<String> ipAddr;
    String description;
    Integer reputation;

    public IPListObject(List<String> ipAddr, String description, Integer reputation) {
        this.ipAddr = ipAddr;
        this.description = (description==null || description.compareTo("")==0)?"IP List":description;
        this.reputation = (reputation==null || reputation < -3 || reputation > 0 )? -1:reputation;
    }
    public IPListObject(){}

    public List<String> getIpAddr() {
        return ipAddr;
    }

    public void setIpAddr(List<String> ipAddr) {
        this.ipAddr = ipAddr;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
