package com.threatintelligence;

import com.threatintelligence.factory.TWJobFactory;
import com.threatintelligence.interfaces.IJobExecutor;

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
