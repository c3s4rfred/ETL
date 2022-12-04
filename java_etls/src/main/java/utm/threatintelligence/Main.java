package utm.threatintelligence;

import utm.threatintelligence.factory.TWJobFactory;
import utm.threatintelligence.interfaces.IJobExecutor;

public class Main {

    public static void main(String[] args) {
        try {
            IJobExecutor mainJob = new TWJobFactory().getJob();
            if (mainJob!=null) {
                mainJob.executeFlow();
            }
        } catch (Exception jne){
            System.out.println(jne.getMessage());
        }
    }
}
