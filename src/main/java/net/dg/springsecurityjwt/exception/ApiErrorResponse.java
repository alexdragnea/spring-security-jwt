package net.dg.springsecurityjwt.exception;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ApiErrorResponse {

  private String message;
}
