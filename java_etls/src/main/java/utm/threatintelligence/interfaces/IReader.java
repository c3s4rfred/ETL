package utm.threatintelligence.interfaces;

import java.io.IOException;
import java.net.URL;

public interface IReader {
    String readFile(URL urlFile) throws IOException;
}
