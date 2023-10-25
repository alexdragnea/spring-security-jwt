package net.dg.springsecurityjwt.rest;

import lombok.RequiredArgsConstructor;
import net.dg.springsecurityjwt.model.User;
import net.dg.springsecurityjwt.payload.request.LoginRequest;
import net.dg.springsecurityjwt.payload.request.SignupRequest;
import net.dg.springsecurityjwt.payload.response.JwtResponse;
import net.dg.springsecurityjwt.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  private final AuthService authService;

  @PostMapping("/signin")
  public ResponseEntity<JwtResponse> authenticateUser(@RequestBody LoginRequest loginRequest) {

    return ResponseEntity.ok(authService.authenticateUser(loginRequest));
  }

  @PostMapping("/signup")
  public ResponseEntity<User> registerUser(@RequestBody SignupRequest signUpRequest) {
    User user = authService.registerNewUser(signUpRequest);
    return ResponseEntity.ok(user);
  }
}
