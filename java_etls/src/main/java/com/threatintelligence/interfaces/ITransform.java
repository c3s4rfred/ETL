package com.threatintelligence.interfaces;

public interface ITransform {
    <T> T transform(T origin, T destination) throws Exception;
}
