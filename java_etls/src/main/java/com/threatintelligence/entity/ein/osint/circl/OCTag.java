package com.threatintelligence.entity.ein.osint.circl;

public class OCTag {

    String colour;
    boolean exportable;
    String name;

    public OCTag(String colour, boolean exportable, String name) {
        this.colour = colour;
        this.exportable = exportable;
        this.name = name;
    }

    public OCTag() {}

    public String getColour() {
        return colour;
    }

    public void setColour(String colour) {
        this.colour = colour;
    }

    public boolean isExportable() {
        return exportable;
    }

    public void setExportable(boolean exportable) {
        this.exportable = exportable;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
