package utm.threatintelligence.interfaces;

import java.io.IOException;

public interface IProcessor {
    <T> T process() throws IOException;
    <T> T process(Object params) throws IOException;
}
