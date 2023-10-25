package net.dg.springsecurityjwt.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ControllerAdvice {

  @ExceptionHandler({UserTakenException.class})
  public ResponseEntity<ApiErrorResponse> handleUserTakenException(UserTakenException e) {

    return new ResponseEntity<>(
        ApiErrorResponse.builder().message(e.getMessage()).build(), HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler({RoleNotFoundException.class})
  public ResponseEntity<ApiErrorResponse> handleRoleNotFoundException(RoleNotFoundException e) {

    return new ResponseEntity<>(
        ApiErrorResponse.builder().message(e.getMessage()).build(), HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler({UsernameNotFoundException.class})
  public ResponseEntity<ApiErrorResponse> handleUsernameNotFoundException(
      UsernameNotFoundException e) {

    return new ResponseEntity<>(
        ApiErrorResponse.builder().message(e.getMessage()).build(), HttpStatus.NOT_FOUND);
  }
}
