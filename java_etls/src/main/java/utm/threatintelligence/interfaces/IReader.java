package utm.threatintelligence.interfaces;

import java.io.IOException;
import java.net.URL;
import java.util.List;

public interface IReader {
    String readFile(URL urlFile) throws IOException;
    List<String> readFileAsList(URL urlFile) throws Exception;
    String readFileNameFromZipFile(URL urlFile) throws Exception;
}
