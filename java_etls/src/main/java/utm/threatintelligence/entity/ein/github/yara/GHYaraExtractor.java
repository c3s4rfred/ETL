package utm.threatintelligence.entity.ein.github.yara;

import utm.threatintelligence.entity.ein.common.YaraRuleObject;

import java.util.ArrayList;
import java.util.Iterator;

/**
 * Used to extract yara rules from a source string
 * Support files with one or more rules inside
 * */
public class GHYaraExtractor {
    ArrayList<YaraRuleObject> yaraRuleObjectArrayList = new ArrayList<>();
    String yaraSource;

    public GHYaraExtractor(String yaraSource) {
        this.yaraSource = yaraSource;
    }

    // Method to extract parts of the Yara rules (Name, meta, strings, condition, imports and modifiers)
    public String[] partExtractor(String ruleToExtract) {
        String[] resultArray = new String[6];
        // Rule name
        resultArray[0] = ruleToExtract.replaceFirst("rule\\s(\\w+)(.+)?\\{(.+)", "$1");
        // Rule imports and modifiers
        String imp = ruleToExtract.replaceFirst("rule\\s(\\w+) #IMP-(.+)?-IMP#\\{(.+)", "$2");
        resultArray[4] = importOrModifierExtractor(imp, true);
        resultArray[5] = importOrModifierExtractor(imp, false);
        // Strings, meta and condition
        if (ruleToExtract.matches("(.+)meta:(.+)(strings):(.+)")) {
            resultArray[1] = ruleToExtract.replaceFirst("(.+)meta:(.+)(strings):(.+)", "$2");
        } else if (ruleToExtract.matches("(.+)meta:(.+)(condition):(.+)")) {
            resultArray[1] = ruleToExtract.replaceFirst("(.+)meta:(.+)(condition):(.+)", "$2");
        } else {
            resultArray[1] = "";
        }
        if (ruleToExtract.matches("(.+)strings:(.+)condition:(.+)")) {
            resultArray[2] = ruleToExtract.replaceFirst("(.+)strings:(.+)condition:(.+)", "$2");
        } else {
            resultArray[2] = "";
        }

        resultArray[3] = ruleToExtract.replaceFirst("(.+)condition:(.+)}(.+)?", "$2");
        return resultArray;
    }

    // Method to split the individual attributes of a part (meta, strings, condition)
    public ArrayList<String> splitPart(String toSplit, ArrayList<String> partArray) {
        String[] splitArray = toSplit.split("@x!S-R!x@");
        boolean commentDetected = false;
        for (int i = 0; i < splitArray.length; i++) {
            String tmpString = splitArray[i].trim();
            // Remove comment block if its in the same line
            tmpString = tmpString.replaceFirst("/\\*(.+)\\*/", "");
            if (tmpString.compareTo("") != 0 && !tmpString.startsWith("//")) {
                if (tmpString.contains("/*")) {
                    commentDetected = true;
                    tmpString = tmpString.replaceFirst("(.+)?/\\*(.+)?", "$1");
                } else if (tmpString.contains("*/")) {
                    commentDetected = false;
                    tmpString = tmpString.replaceFirst("(.+)?\\*/(.+)?", "$2");
                }
                if (tmpString.compareTo("") != 0 && !tmpString.startsWith("//") && (!commentDetected)) {
                    partArray.add(tmpString);
                }
            }
        }
        return partArray;
    }

    // Method to get the list of YaraRuleObjects
    public ArrayList<YaraRuleObject> getYaraRuleObjects() {
        this.yaraSource = cleanYaraSource(this.yaraSource);

        String[] arrayOfRules = yaraSource.split("@x!H-D!x@-");
        for (int i = 0; i < arrayOfRules.length; i++) {
            String toCompare = recursiveRemoveCommentBlock(arrayOfRules[i].trim());
            if (toCompare.matches("rule\\s(\\w+)(.+)?\\{(.+)?(condition:)(.+)}(.+)?")) {
                YaraRuleObject yaraRuleObject = new YaraRuleObject("", new ArrayList<>(),
                        new ArrayList<>(), "", new ArrayList<>(),"");
                String[] parts = partExtractor(toCompare);
                yaraRuleObject.setRuleName(parts[0]);
                yaraRuleObject.setMeta(splitPart(parts[1], (ArrayList<String>) yaraRuleObject.getMeta()));
                yaraRuleObject.setStrings(splitPart(parts[2], (ArrayList<String>) yaraRuleObject.getStrings()));
                yaraRuleObject.setCondition(unifyCondition(splitPart(parts[3], new ArrayList<>())));
                yaraRuleObject.setImports(splitPart(parts[4], (ArrayList<String>) yaraRuleObject.getImports()));
                yaraRuleObject.setModifier(parts[5]);
                yaraRuleObjectArrayList.add(yaraRuleObject);
            }
        }


        return yaraRuleObjectArrayList;
    }

    // Method to unify condition lines in one
    public String unifyCondition(ArrayList<String> conditionLines) {
        String conditionResult = "";
        Iterator<String> it;
        for (it = conditionLines.iterator(); it.hasNext(); ) {
            conditionResult += " " + it.next();
        }
        return conditionResult.trim();
    }

    // Method to recursively remove comment blocks
    public String recursiveRemoveCommentBlock(String sourceRule) {
        if (sourceRule.matches("(.+)?/\\*(.+)\\*/(.+)?")) {
            sourceRule = sourceRule.replaceFirst("/\\*(.+)\\*/", "");
            recursiveRemoveCommentBlock(sourceRule);
        }
        return sourceRule;
    }

    // Method to clean Yara rules and create tokens for parsing later
    // @x!S-R!x@ = Represents line changes in a rule, used to split attributes of a rule ex: yara strings
    // @x!H-D!x@- = Represents rule start, used to split when more than one rule are in the same file
    // #IMP-$1-IMP# = Represents a tag to hold all the rule imports
    public static String cleanYaraSource(String yaraSource) {
        return yaraSource.replaceAll("(\\t+)", "")
                .replaceAll("(\\r+)", "")
                .replaceAll("\\*/", "*/\n")
                .replaceAll("import(.+)(\\s+)", " import$1@x!S-R!x@")
                .replaceAll("(\\s+)\\\\","@x!S-R!x@\\\\")
                .replaceAll("}(\\s+)?((.+)?(rule\\s(\\w+)(.+)?))\\{", "\n}\n$2{")
                .replaceAll("(\\n+)(private|global|rule)","@x!S-R!x@$2")
                .replaceAll("((\\s+)?(import|global|private)(.+))?rule\\s+(\\w+)(.+)?(\\s+)?\\{", "@x!H-D!x@-rule $5 #IMP-$1-IMP#{")
                .replaceAll("\\n", "@x!S-R!x@");
    }

    // Method to extract imports from #IMP-$1-IMP# tag
    public static String importOrModifierExtractor(String impTag, boolean extractImport) {
        impTag = impTag.replaceAll("\\s{2}", " ").trim();
        String result = "";
        if (impTag.length() > 0) {
            if (extractImport) {
                if (impTag.startsWith("import")) {
                    if (impTag.contains("global") || impTag.contains("private")) {
                        return impTag.substring(0, impTag.lastIndexOf("@")+1);
                    } else return impTag;
                }
            } else {
                if (impTag.contains("global")) {
                    return "global";
                } else if (impTag.contains("private")) {
                    return "private";
                }
            }
        }
        return result;
    }

    public void setYaraRuleObjects(ArrayList<YaraRuleObject> yaraRuleObjectArrayList) {
        this.yaraRuleObjectArrayList = yaraRuleObjectArrayList;
    }

    public String getYaraSource() {
        return yaraSource;
    }

    public void setYaraSource(String yaraSource) {
        this.yaraSource = yaraSource;
    }
}
