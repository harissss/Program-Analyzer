package com.haris.analyzer_auth_server.user;

import java.util.List;
import java.util.Optional;

import com.haris.analyzer_auth_server.config.Jwt.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController 
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
     * Get method for getting users. Specific users can be specified through request parameters. 
     * @param email An optional request parameter specifying the email of a user to search for. 
     * @return A list of all users that matched the given request parameters (or all users if no parameters was given). 
     */
    @GetMapping(path="/api/users")
    public List<User> getUsers(@RequestParam Optional<String> email) {
        // If the email parameter is specified, then try to search for the specific user with the given email
        if(email.isPresent()) {
            return userRepository.findByEmail(email.get())
                .map(List::of)
                .orElse(List.of());
        }
        
        // Otherwise, return all users
        return userRepository.findAll();
    }
    
    /**
     * Dummy post method for creating users (only for testing...)
     * @param user The new User object to add to the database
     * @return The newly created User
     */
    @PostMapping(path="/api/users")
    public User postUser(@RequestBody User user) {       
        return userRepository.save(user);
    }

    /**
     * Endpoint for registering a new account. Given an email and password, it checks if the account already exists, and if not, creates a new account. 
     * @param request The request with email and password. 
     * @return Response code and body signalling the result of the request. 
     */
    @RequestMapping(path="/api/auth/register", method=RequestMethod.POST)
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

    @RequestMapping(path="/api/auth/login", method=RequestMethod.POST) //should it be post or get? maybe get because they expect to get a token i think
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
}
