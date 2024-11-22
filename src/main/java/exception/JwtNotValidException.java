package exception;

public class JwtNotValidException extends Exception{

    public JwtNotValidException(String message, Throwable error) {
        super(message, error);
    }

}
