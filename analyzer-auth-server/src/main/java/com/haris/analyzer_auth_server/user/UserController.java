package com.haris.analyzer_auth_server.user;

import com.haris.analyzer_auth_server.config.Jwt.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {
    private final UserRepository userRepository; 

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    public UserController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    /**
     * Endpoint for registering a new account. Given an email and password, it checks if the account already exists,
     * and if not, creates a new account.
     *
     * @param request The request with email and password. 
     * @return Response code and body signalling the result of the request. 
     */
    @RequestMapping(path="/auth/register", method=RequestMethod.POST)
    public ResponseEntity<RegisterResponse> requestUserRegister(@RequestBody RegisterRequest request) {
        final String email = request.email();
        final String password = request.password();

        //check that user with given email already exists, return 500
        if (userRepository.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new RegisterResponse("User already exists.")
            );
        }

        //hash password, using passwordHasher bean
        final String passwordHash = passwordEncoder.encode(password);

        //store new User in DB
        User newUser = new User(email, passwordHash);
        userRepository.save(newUser);

        //return OK response, with token
        return ResponseEntity.status(HttpStatus.OK).body(
                new RegisterResponse("User succesfully created.")
        );
    }

    /**
     * Login endpoint. Given an email and password, it authenticates the user and returns a JWT,
     * if the credentials are correct.
     *
     * @param request the request body, containing the email and password.
     * @return The authentication response, containing a JWT bearer token if successful.
     */
    @RequestMapping(path="/auth/login", method=RequestMethod.POST) //should it be post or get? maybe get because they expect to get a token i think
    public ResponseEntity<LoginResponse> requestUserLogin(@RequestBody LoginRequest request) {
        final String email = request.email();
        final String password = request.password();

        // Check that the credentials are correct
        if (!userRepository.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new LoginResponse(null, null, null, "Email or password is incorrect. Please try again.")
            );
        }

        User targetUser = userRepository.findByEmail(email).get();

        if (!passwordEncoder.matches(password, targetUser.getPasswordHash())) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new LoginResponse(null, null, null, "Email or password is incorrect. Please try again.")
            );
        }

        // Create an access token
        final String accessToken = jwtService.generateToken(targetUser);

        // Send OK response with the token
        return ResponseEntity.status(HttpStatus.OK).body(
                new LoginResponse(
                        accessToken,
                        "Bearer",
                        jwtService.extractExpiration(accessToken).toString(),
                        "Successfully logged in."
                )
        );
    }

    /**
     * A testing endpoint to get the currently authenticated user.
     *
     * @return Authentication object for the currently authenticated user in the Security Context.
     */
    @RequestMapping(path="/me", method=RequestMethod.GET)
    public ResponseEntity<Authentication> requestCurrentlyAuthenticatedUser() {
        Authentication userAuth = SecurityContextHolder.getContext().getAuthentication();

        if (userAuth == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }

        return ResponseEntity.status(HttpStatus.OK).body(userAuth);
    }

    /*@RequestMapping(path="/api/auth/logout", method=RequestMethod.POST)
    public ResponseEntity<LogoutResponse> reqestUserLogout(@RequestBody LogoutRequest request) {
        //...
        return ResponseEntity.status(HttpStatus.OK).body(null);
    }*/
}
