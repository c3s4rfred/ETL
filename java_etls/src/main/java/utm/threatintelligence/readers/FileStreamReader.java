package utm.threatintelligence.readers;

import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
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
            stb.append(inputLine + "\n");
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

    @Override
    public String readFileNameFromZipFile(URL urlFile) throws Exception {
        System.setProperty("http.agent", "Chrome"); // To avoid error 403
        // Variable init and dir structure creation
        File folder = new File("downloads");
        if (!folder.exists()) {
            folder.mkdir();
        }
        String fileName = "";
        URL url = urlFile;
        byte dataBuffer[] = new byte[1024];
        BufferedInputStream in = new BufferedInputStream(url.openStream());
        FileOutputStream fileOutputStream = new FileOutputStream("downloads/ZipEntry.zip");

        // Begin to read from URL and download locally
        int bytesRead;
        while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1) {
            fileOutputStream.write(dataBuffer, 0, bytesRead);
        }
        // Unzip the file downloaded
        File verify = new File("downloads/ZipEntry.zip");
        if (verify.exists() && verify.canRead() && verify.length() > 0) {
            fileName = unZip();
        }
        // Closing channels
        in.close();
        fileOutputStream.close();
        // Returning the name of the file unzipped
        return fileName;
    }

    // Method to unzip a file and return the filename of the compressed file
    public String unZip() throws Exception {

        byte[] buffer = new byte[1024];

        // Unzip the file
        ZipInputStream zis = new ZipInputStream(new FileInputStream("downloads" + File.separator +"ZipEntry.zip"));
        ZipEntry ze = zis.getNextEntry();

        String fileName = ze.getName();
        File newFile = new File("downloads" + File.separator + fileName);

        // Writing the file to disc
        FileOutputStream fos = new FileOutputStream(newFile);
        int len;
        while ((len = zis.read(buffer)) > 0) {
            fos.write(buffer, 0, len);
        }
        // Closing channels
        fos.close();
        zis.closeEntry();
        zis.close();
        // Returning absolute path with protocol of the file created
        return "file:///"+newFile.getAbsolutePath();
    }
}
