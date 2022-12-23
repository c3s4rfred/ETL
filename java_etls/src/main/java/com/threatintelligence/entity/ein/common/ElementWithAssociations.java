package com.threatintelligence.entity.ein.common;

import java.util.List;

public class ElementWithAssociations {
    CommonEntityObject principal;
    List<CommonEntityObject> associations;

    public ElementWithAssociations(CommonEntityObject principal, List<CommonEntityObject> associations) {
        this.principal = principal;
        this.associations = associations;
    }
    public ElementWithAssociations(){}

    public CommonEntityObject getPrincipal() {
        return principal;
    }

    public void setPrincipal(CommonEntityObject principal) {
        this.principal = principal;
    }

    public List<CommonEntityObject> getAssociations() {
        return associations;
    }

    public void setAssociations(List<CommonEntityObject> associations) {
        this.associations = associations;
    }
}
