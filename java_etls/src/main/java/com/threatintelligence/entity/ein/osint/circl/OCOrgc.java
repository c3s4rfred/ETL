package com.threatintelligence.entity.ein.osint.circl;

public class OCOrgc {

    String uuid;
    String name;

    public OCOrgc(String uuid, String name) {
        this.uuid = uuid;
        this.name = name;
    }

    public OCOrgc() {}

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
