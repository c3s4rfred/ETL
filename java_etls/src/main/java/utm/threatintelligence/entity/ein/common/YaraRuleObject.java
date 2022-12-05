package utm.threatintelligence.entity.ein.common;

import java.util.List;

public class YaraRuleObject {
    String ruleName;
    List<String> meta;
    List<String> strings;
    String condition;
    List<String> imports;
    String modifier;

    public YaraRuleObject(String ruleName, List<String> meta, List<String> strings,
                          String condition, List<String> imports, String modifier) {
        this.ruleName = ruleName;
        this.meta = meta;
        this.strings = strings;
        this.condition = condition;
        this.imports = imports;
        this.modifier = modifier;
    }

    public String getRuleName() {
        return ruleName;
    }

    public void setRuleName(String ruleName) {
        this.ruleName = ruleName;
    }

    public List<String> getMeta() {
        return meta;
    }

    public void setMeta(List<String> meta) {
        this.meta = meta;
    }

    public List<String> getStrings() {
        return strings;
    }

    public void setStrings(List<String> strings) {
        this.strings = strings;
    }

    public String getCondition() {
        return condition;
    }

    public void setCondition(String condition) {
        this.condition = condition;
    }

    public List<String> getImports() {
        return imports;
    }

    public void setImports(List<String> imports) {
        this.imports = imports;
    }

    public String getModifier() {
        return modifier;
    }

    public void setModifier(String modifier) {
        this.modifier = modifier;
    }
}
