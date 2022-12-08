package utm.threatintelligence.readers;

import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import utm.threatintelligence.enums.EnvironmentsEnum;
import utm.threatintelligence.interfaces.IReader;

public class FileStreamReader implements IReader {

    @Override
    public String readFile(URL urlFile) throws IOException {
        System.setProperty("http.agent", "Chrome"); // To avoid error 403
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

    @Override
    public List<String> readFileAsList(URL urlFile) throws Exception {
        System.setProperty("http.agent", "Chrome"); // To avoid error 403
        URL url = urlFile;
        BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));

        String inputLine;
        List<String> lineList = new ArrayList<>();

        while ((inputLine = in.readLine()) != null) {
            lineList.add(inputLine);
        }

        in.close();
        return lineList;
    }
}
