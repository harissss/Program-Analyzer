package com.haris.analyzer_auth_server.jwt_tests;

import com.haris.analyzer_auth_server.config.Jwt.JwtAuthFilter;
import com.haris.analyzer_auth_server.jwt_tests.test_doubles.JwtServiceStub;
import com.haris.analyzer_auth_server.jwt_tests.test_doubles.UserRepositoryStub;
import com.haris.analyzer_auth_server.user.User;

import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.*;

public class TestJwtAuthFilter {
    private final JwtAuthFilter jwtAuthFilter;
    private final JwtServiceStub jwtService;
    private final String testEmail = "me123@test.com";
    private final String testPassword = "abcxyz";
    private final User testUser;

    public TestJwtAuthFilter() {
        String secret = "IBjsiXVNkcPPYWqw+dKcyouP2Pefs71pko8+xeXlfAg=";
        this.jwtService = new JwtServiceStub(new UserRepositoryStub(), secret);
        this.jwtAuthFilter = new JwtAuthFilter(jwtService, new UserRepositoryStub());
        this.testUser = new User(testEmail, testPassword);
    }

    @BeforeEach
    public void setup() {
        //clear the security context before each test
        SecurityContextHolder.clearContext();
    }

    @Test
    public void correctJwtIsAuthenticated() {
        //Given the JwtAuthFilter
        //Given that the JWT is valid
        jwtService.setValid(true);
        jwtService.setEmail(testEmail);

        //When a request with a valid JWT is made
        String token = jwtService.generateToken(testUser);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        //Then the user is authenticated in the SecurityContextHolder
        try {
            jwtAuthFilter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
            assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        } catch (Exception e) {
            fail("The filter threw an exception.");
        }
    }

    @Test
    public void noAuthorizationHeaderIsNotAuthenticated() {
        //Given the JwtAuthFilter
        //Given that the JWT is valid
        jwtService.setValid(true);
        jwtService.setEmail(testEmail);

        //When a request is made, but the valid JWT is not in the Authorization header
        MockHttpServletRequest request = new MockHttpServletRequest();

        //Then the user is not authenticated in the SecurityContextHolder
        try {
            jwtAuthFilter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        } catch (Exception e) {
            fail("The filter threw an exception.");
        }
    }

    @Test
    public void noBearerSchemaIsNotAuthenticated() {
        //Given the JwtAuthFilter
        //Given that the JWT is valid
        jwtService.setValid(true);
        jwtService.setEmail(testEmail);

        //When a request with a valid JWT is made, but the Bearer schema isn't used
        String token = jwtService.generateToken(testUser);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", token);

        //Then the user is not authenticated in the SecurityContextHolder
        try {
            jwtAuthFilter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        } catch (Exception e) {
            fail("The filter threw an exception.");
        }
    }

    @Test
    public void invalidJwtIsNotAuthenticated() {
        //Given the JwtAuthFilter
        //Given that the JWT is invalid
        jwtService.setValid(false);
        jwtService.setEmail(testEmail);

        //When a request with an invalid JWT is made (the test stub returns invalid even though it is a valid token...)
        String token = jwtService.generateToken(testUser);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        //Then the user is not authenticated in the SecurityContextHolder
        try {
            jwtAuthFilter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        } catch (Exception e) {
            fail("The filter threw an exception.");
        }
    }

    @Test
    public void nonExistingUserIsNotAuthenticated() {
        //Given the JwtAuthFilter
        //Given that the JWT is valid, but with a non-existing user (idk if this is even possible)
        jwtService.setValid(true);
        jwtService.setEmail("wrongemail@test.com");

        //When a request with a valid JWT is made
        String token = jwtService.generateToken(new User("wrongemail@test.com", testPassword));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        //Then the user is not authenticated in the SecurityContextHolder
        try {
            jwtAuthFilter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        } catch (Exception e) {
            fail("The filter threw an exception.");
        }
    }

    @Test
    public void userCanNotAlreadyBeAuthenticated() {
        //Given the JwtAuthFilter
        //When the request is already authenticated
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(testUser, null);
        SecurityContextHolder.getContext().setAuthentication(authToken);

        //Then an exception should be thrown
        try {
            jwtAuthFilter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());
        } catch (ServletException e) {
            assertTrue(true);
        } catch (Exception e) {
            fail("Wrong exception encountered.");
        }
    }
}
