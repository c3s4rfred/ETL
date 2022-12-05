package utm.threatintelligence.readers;

import java.io.*;
import java.net.URL;
import utm.threatintelligence.enums.EnvironmentsEnum;
import utm.threatintelligence.interfaces.IReader;

public class FileStreamReader implements IReader {

    @Override
    public String readFile(URL urlFile) throws IOException {
        URL url = urlFile;
        BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));

        String inputLine;
        StringBuilder stb = new StringBuilder();

        while ((inputLine = in.readLine()) != null) {
            stb.append(inputLine+"\n");
        }

        in.close();
        return stb.toString();
    }
}
