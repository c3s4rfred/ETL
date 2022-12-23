package com.threatintelligence.entity.ein.osint.circl;

import java.util.List;

public class OCObject {

    Boolean deleted;
    String name;
    String uuid;
    String distribution;
    String template_uuid;
    String sharing_group_id;
    String timestamp;
    String description;
    String template_version;
    String meta_category;
    String comment;
    List<OCAttribute> Attribute;

    public OCObject(
        Boolean deleted,
        String name,
        String uuid,
        String distribution,
        String template_uuid,
        String sharing_group_id,
        String timestamp,
        String description,
        String template_version,
        String meta_category,
        String comment,
        List<OCAttribute> Attribute
    ) {
        this.deleted = deleted;
        this.name = name;
        this.uuid = uuid;
        this.distribution = distribution;
        this.template_uuid = template_uuid;
        this.sharing_group_id = sharing_group_id;
        this.timestamp = timestamp;
        this.description = description;
        this.template_version = template_version;
        this.meta_category = meta_category;
        this.comment = comment;
        this.Attribute = Attribute;
    }

    public OCObject() {}

    public Boolean getDeleted() {
        return deleted;
    }

    public void setDeleted(Boolean deleted) {
        this.deleted = deleted;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getDistribution() {
        return distribution;
    }

    public void setDistribution(String distribution) {
        this.distribution = distribution;
    }

    public String getTemplate_uuid() {
        return template_uuid;
    }

    public void setTemplate_uuid(String template_uuid) {
        this.template_uuid = template_uuid;
    }

    public String getSharing_group_id() {
        return sharing_group_id;
    }

    public void setSharing_group_id(String sharing_group_id) {
        this.sharing_group_id = sharing_group_id;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getTemplate_version() {
        return template_version;
    }

    public void setTemplate_version(String template_version) {
        this.template_version = template_version;
    }

    public String getMeta_category() {
        return meta_category;
    }

    public void setMeta_category(String meta_category) {
        this.meta_category = meta_category;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public List<OCAttribute> getAttributes() {
        return Attribute;
    }

    public void setAttributes(List<OCAttribute> attributes) {
        Attribute = attributes;
    }
}
