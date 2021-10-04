package io.rohit.springjwt.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {

	public String generateToken(UserDetails details) {
		Map<String, Object> claims = new HashMap<String, Object>();
		return createToken(claims, details.getUsername());
	}

	private String createToken(Map<String, Object> claims, String subject) {
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
				.signWith(SignatureAlgorithm.HS256, "Rohit").compact();
	}

	public boolean validateToken(String token, UserDetails user) {
		final String userName = extractUserName(token);
		return (user.getUsername().equals(userName) && !isTokenExpired(token));
	}

	public String extractUserName(String token) {
		return extractClaims(token, Claims::getSubject);
	}

	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaims(token, Claims::getExpiration);
	}

	private <T> T extractClaims(String token, Function<Claims, T> claimsResolver) {
		final Claims claim = extractALLClaims(token);
		return claimsResolver.apply(claim);
	}

	private Claims extractALLClaims(String token) {
		return Jwts.parser().setSigningKey("Rohit").parseClaimsJws(token).getBody();
	}
}
