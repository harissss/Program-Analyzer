package com.haris.analyzer_auth_server.user;

import java.util.List;
import java.util.Optional;

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

    public UserController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
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
    public ResponseEntity<String> requestUserRegister(@RequestBody RegisterRequest request) {
        String email = request.getEmail();
        String password = request.getPassword();

        //check that user with given email already exists, return 500
        if (userRepository.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("User already exists"); 
        }

        //hash password, using passwordHasher bean
        String passwordHash = passwordEncoder.encode(password);

        //store new User in DB
        User newUser = new User(email, passwordHash);
        userRepository.save(newUser);

        //return OK response
        return ResponseEntity.status(HttpStatus.OK).body("User succesfully created");
    }
}
