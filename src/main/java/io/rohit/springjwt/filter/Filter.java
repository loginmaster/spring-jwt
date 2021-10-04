package io.rohit.springjwt.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.rohit.springjwt.security.service.MyUserDetailsService;
import io.rohit.springjwt.util.JwtUtil;

@Component
public class Filter extends OncePerRequestFilter{
	
	@Autowired
	private MyUserDetailsService userDetails;
	
	@Autowired
	JwtUtil jwtUtils;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String authHeader = request.getHeader("Authorization");
		
		String jwtToken = null;
		String userName = null;
		
		if(authHeader != null && authHeader.contains("Bearer ")) {
			jwtToken = authHeader.substring(7);
			userName= jwtUtils.extractUserName(jwtToken);
		}
		
		if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetail = userDetails.loadUserByUsername(userName);
			if(jwtUtils.validateToken(jwtToken, userDetail)) {
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetail, null, userDetail.getAuthorities());
				usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		filterChain.doFilter(request, response);
	}

	
}
