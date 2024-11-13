package com.back.pid_grupo01.jwt;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{
	private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
       
    	// El método getTokenFromRequest() está en la parte inferior
        final String token = getTokenFromRequest(request);
        final String username;

        //si no ingresa token
        if (token==null)
        {
            filterChain.doFilter(request, response);
            return;
        }

        //Se obtiene el username(email) desde el token
        username=jwtService.getUsernameFromToken(token);

        //Si el username no es nulo y no hay un contexto actual de autentificación
        if (username!=null && SecurityContextHolder.getContext().getAuthentication()==null)
        {
        	// con el método ".loadUserByUsername(username)" se trae el userDetail que tiene información del user.
            UserDetails userDetails=userDetailsService.loadUserByUsername(username);

            if (jwtService.isTokenValid(token, userDetails)) //si es true o false
            {
			            	// crea un objeto UsernamePasswordAuthenticationToken, que representa la autenticación del usuario con el sistema, 
			            	// incluyendo su identidad (userDetails) y sus permisos (authorities).
                UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities());

			                // WebAuthenticationDetailsSource(): Crea un objeto que recoge detalles adicionales de la autenticación.
			                // Usa la solicitud HTTP (HttpServletRequest) actual para construir detalles adicionales, como la IP desde la cual se realiza la solicitud y otros metadatos de la sesión.
			                // Esta línea añade estos detalles al token de autenticación para que estén disponibles en caso de que se necesiten, proporcionando un nivel adicional de información sobre la solicitud.
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                
			                //SecurityContextHolder.getContext(): Obtiene el contexto de seguridad actual de Spring.
			                // .setAuthentication(authToken): Establece authToken como la autenticación actual para el contexto. Esto indica a Spring que el usuario que realiza la solicitud está autenticado y tiene los permisos (roles) especificados en authToken           
                SecurityContextHolder.getContext().setAuthentication(authToken);
                
			                /* El contexto de seguridad de Spring reconoce a la solicitud como autenticada, 
			                 permitiendo acceso a las rutas protegidas y asegurando que el usuario solo pueda realizar 
			                 acciones autorizadas de acuerdo con sus permisos. */
            }

        }
        
					        // Llamar a doFilter() en filterChain le dice al framework que esta clase (el filtro actual) ha terminado su trabajo, 
					        // y la solicitud debe pasar al siguiente filtro en la cadena.
        filterChain.doFilter(request, response);
    }
    
    
    

    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader=request.getHeader(HttpHeaders.AUTHORIZATION);

        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer "))
        {
            return authHeader.substring(7);
        }
        return null;
    }
}
