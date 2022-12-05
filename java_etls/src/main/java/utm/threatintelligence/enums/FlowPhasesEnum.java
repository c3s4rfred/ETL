package utm.threatintelligence.enums;

/*Enum used to define the phases of th ETL process, is used for logs*/
public enum FlowPhasesEnum {
    P0_BEGIN_PROCESS("P0_BEGIN_PROCESS"),
    P1_READ_FILE("P1_READ_FILE"),
    P2_MAP_JSON_TO_CLASS("P2_MAP_JSON_TO_CLASS"),
    P3_TRANSFORM_TO_ENTITY("P3_TRANSFORM_TO_ENTITY"),
    P4_MAP_ENTITY_TO_JSON("P4_MAP_ENTITY_TO_JSON"),
    P5_END_FILE_PROCESS("P5_END_FILE_PROCESS"),
    PN_END_PROCESS("PN_END_PROCESS"),

    UNRECOGNIZED_PROCESS("UNRECOGNIZED_PROCESS");

    private String varName;

    private FlowPhasesEnum(String varName) {
        this.varName = varName;
    }

    public String getVarValue() {
        return varName;
    }
}
