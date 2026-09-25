package com.haris.analyzer_auth_server.user;

import java.util.List;
import java.util.Optional; 

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController 
public class UserController {
    private final UserRepository userRepository; 

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Get method for getting users. Specific users can be specified through request parameters. 
     * @param email An optional request parameter specifying the email of a user to search for. 
     * @return A list of all users that matched the given request parameters (or all users if no parameters was given). 
     */
    @GetMapping("/api/users")
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
    @PostMapping("/api/users")
    public User postUser(@RequestBody User user) {       
        return userRepository.save(user);
    }
}
