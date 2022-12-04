package utm.threatintelligence.logging;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 *
 * @author Freddy
 */
public class LogDef {

    String LOG_TYPE;
    Object LOG_DATA;
    String LOG_MESSAGE;
    String LOG_DATE;

    public LogDef(String LOG_TYPE, Object LOG_DATA, String LOG_MESSAGE) {
        this.LOG_TYPE = LOG_TYPE;
        this.LOG_DATA = LOG_DATA;
        this.LOG_MESSAGE = LOG_MESSAGE;
        this.LOG_DATE = getActualDate();
    }

    public void setLOG_TYPE(String LOG_TYPE) {
        this.LOG_TYPE = LOG_TYPE;
    }

    public void setLOG_DATA(Object LOG_DATA) {
        this.LOG_DATA = LOG_DATA;
    }

    public void setLOG_MESSAGE(String LOG_MESSAGE) {
        this.LOG_MESSAGE = LOG_MESSAGE;
    }

    public String getLOG_DATE() {
        return LOG_DATE;
    }

    public String getLOG_TYPE() {
        return LOG_TYPE;
    }

    public Object getLOG_DATA() {
        return LOG_DATA;
    }

    public String getLOG_MESSAGE() {
        return LOG_MESSAGE;
    }

    public String getActualDate() {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        return dtf.format(LocalDateTime.now());
    }

    public String logDefToString() {
        return (
            this.getLOG_DATE() +
            " Type: " +
            this.getLOG_TYPE() +
            " -> Data: " +
            this.getLOG_DATA().toString() +
            " -> Message: " +
            this.getLOG_MESSAGE()
        );
    }

    public String errorToStringWIthOutDate() {
        return "Type: " + this.getLOG_TYPE() + " -> Data: " + this.getLOG_DATA().toString() + " -> Message: " + this.getLOG_MESSAGE();
    }
}
