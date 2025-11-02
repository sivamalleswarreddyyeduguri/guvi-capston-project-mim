package com.ecommerce.securityconfig;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ecommerce.service.MyUserService;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtUtil jwtUtil;
	private final MyUserService myUserService;

	public JwtAuthenticationFilter(JwtUtil jwtUtil, MyUserService myUserService) {
		this.jwtUtil = jwtUtil;
		this.myUserService = myUserService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
	        throws ServletException, IOException {

	    String path = request.getServletPath();

	    if (path.startsWith("/api/auth")) {
	        filterChain.doFilter(request, response);
	        return;
	    }

	    final String authHeader = request.getHeader("Authorization");
	    System.out.println("Authorization header: " + authHeader);

	    String token = null;
	    String username = null;

	    if (authHeader != null && authHeader.startsWith("Bearer ")) {
	        token = authHeader.substring(7);
	        username = jwtUtil.extractUsername(token);
	        System.out.println("Extracted username from token: " + username);
	   
	    } else {
	        System.out.println("Missing or invalid Authorization header.");
	    }

	    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
	        UserDetails userDetails = myUserService.loadUserByUsername(username);
	        if (jwtUtil.validateToken(token, userDetails)) {
	            var authorities = jwtUtil.extractAuthorities(token);
	            System.out.println("Token is valid. Authorities: " + authorities);

	            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
	                    userDetails, null, authorities);
	            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		        System.out.println("SecurityContext set with: " + authToken.getAuthorities());

	            SecurityContextHolder.getContext().setAuthentication(authToken);
	        } else {
	            System.out.println("Token validation failed.");
	        }
	    }

	    filterChain.doFilter(request, response);
	}
}
