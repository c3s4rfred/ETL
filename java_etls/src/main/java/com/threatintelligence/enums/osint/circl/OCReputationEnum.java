package com.threatintelligence.enums.osint.circl;

import java.util.Arrays;
import java.util.Optional;

public enum OCReputationEnum {
    OC_REPUTATION_4("4", 0),
    OC_REPUTATION_3("3", -1),
    OC_REPUTATION_2("2", -2),
    OC_REPUTATION_1("1", -3);

    private String threat_level_id;
    private Integer repValue;

    private OCReputationEnum(String threat_level_id, Integer repValue) {
        this.threat_level_id = threat_level_id;
        this.repValue = repValue;
    }

    public Integer getRepValue() {
        return repValue;
    }

    public String getThreat_level_id() {
        return threat_level_id;
    }

    public static Integer getRepValueByOCThreatLvlId(String lvl_id) {
        OCReputationEnum[] allEnums = OCReputationEnum.values();
        try {
            Optional<Integer> tst = Arrays
                .stream(OCReputationEnum.values())
                .filter(repVal -> repVal.getThreat_level_id().compareTo(lvl_id) == 0)
                .map(repVal -> repVal.getRepValue())
                .findFirst();
            return tst.get();
        } catch (java.util.NoSuchElementException ex) {
            return -1;
        }
    }
}
