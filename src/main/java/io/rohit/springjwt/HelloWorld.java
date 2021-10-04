package io.rohit.springjwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.rohit.springjwt.model.AuthenticationRequest;
import io.rohit.springjwt.model.AuthenticationResponse;
import io.rohit.springjwt.security.service.MyUserDetailsService;
import io.rohit.springjwt.util.JwtUtil;

@RestController
public class HelloWorld {
	
	@Autowired
	private MyUserDetailsService userDetails;
	
	@Autowired
	private AuthenticationManager authManager;

	@Autowired
	JwtUtil jwtUtils;
	
	@RequestMapping("/hello")
	public String helloWord() {return "hello World";}
	
	@PostMapping("/authenticate")
	public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) throws Exception{
		try {
			authManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword()));
		} catch (BadCredentialsException e) {
			// TODO Auto-generated catch block
			throw new Exception("wong creds", e);
		}
		
		final UserDetails user = userDetails.loadUserByUsername(request.getUserName());
		String jwtToken = jwtUtils.generateToken(user);
		
		return new ResponseEntity<AuthenticationResponse>(new AuthenticationResponse(jwtToken),HttpStatus.OK);
	}
}
