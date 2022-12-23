package com.threatintelligence.interfaces;

import java.net.MalformedURLException;
import java.net.URL;

public interface IURLCreator {
    URL createURL(String resource, String separator) throws MalformedURLException;
}
