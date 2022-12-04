package utm.threatintelligence.enums;

import java.util.Arrays;
import java.util.Optional;
import utm.threatintelligence.enums.osint.circl.OCReputationEnum;

// This enum is used to hold needed attributes of a month, used to get Epoch Date Format
public enum MonthEnum {
    SHORT_JANUARY("January", "Jan", "1"),
    SHORT_FEBRUARY("February", "Feb", "2"),
    SHORT_MARCH("March", "Mar", "3"),
    SHORT_APRIL("April", "Apr", "4"),
    SHORT_MAY("May", "May", "5"),
    SHORT_JUNE("June", "Jun", "6"),
    SHORT_JULY("July", "Jul", "7"),
    SHORT_AUGUST("August", "Aug", "8"),
    SHORT_SEPTEMBER("September", "Sep", "9"),
    SHORT_OCTOBER("October", "Oct", "10"),
    SHORT_NOVEMBER("November", "Nov", "11"),
    SHORT_DECEMBER("December", "Dec", "12");

    private String fullMonth;
    private String shortMonth;
    private String monthId;

    private MonthEnum(String fullMonth, String shortMonth, String monthId) {
        this.fullMonth = fullMonth;
        this.shortMonth = shortMonth;
        this.monthId = monthId;
    }

    public String getFullMonth() {
        return fullMonth;
    }

    public String getShortMonth() {
        return shortMonth;
    }

    public String getMonthId() {
        return monthId;
    }

    public static String getMonth(String toSearch, boolean isShort) {
        MonthEnum[] allEnums = MonthEnum.values();
        try {
            Optional<String> tst = Arrays
                .stream(MonthEnum.values())
                .filter(repVal -> (isShort ? repVal.getShortMonth() : repVal.getFullMonth()).compareToIgnoreCase(toSearch) == 0)
                .map(repVal -> repVal.getMonthId())
                .findFirst();
            return tst.get();
        } catch (java.util.NoSuchElementException ex) {
            return "Not found";
        }
    }
}
