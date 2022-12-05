package utm.threatintelligence.interfaces;

public interface IParser {
    <T> T parseFrom(String data, Class<T> type, final T into) throws Exception;
    String parseTo(Object data);
}
