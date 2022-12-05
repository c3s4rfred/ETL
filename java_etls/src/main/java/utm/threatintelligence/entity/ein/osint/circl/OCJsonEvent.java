package utm.threatintelligence.entity.ein.osint.circl;

public class OCJsonEvent {

    OCEvent Event;

    public OCJsonEvent(OCEvent event) {
        Event = event;
    }

    public OCJsonEvent() {}

    public OCEvent getEvent() {
        return Event;
    }

    public void setEvent(OCEvent event) {
        Event = event;
    }
}
