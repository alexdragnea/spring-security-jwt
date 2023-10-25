package net.dg.springsecurityjwt.exception;

public class UserTakenException extends RuntimeException {
  public UserTakenException(String message) {
    super(message);
  }
}
