package com.back.pid_grupo01.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.back.pid_grupo01.repository.UsuarioRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
	private final UsuarioRepository userRepository;

		/*
		 El AuthenticationManager, configurado en ApplicationConfig, administra el proceso de autenticación. 
		 En tu aplicación, este manager se usa para autenticar el usuario en métodos como login() en AuthService.
		  
	     *  Cuando un usuario intenta autenticarse en "AuthService" con el login(), Spring Security (a través del AuthenticationManager) 
	     	crea un objeto de autenticación, como UsernamePasswordAuthenticationToken, con las credenciales 
	     	del usuario, es decir, el username y la password.   
	     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception
    {
        return config.getAuthenticationManager();
    }

    // El AuthenticationManager delega la búsqueda del usuario a su AuthenticationProvider.
    
    @Bean
    public AuthenticationProvider authenticationProvider()
    {
    	//Aqui se crea el provider "authProvider" de SecurityConfig
        DaoAuthenticationProvider authenticationProvider= new DaoAuthenticationProvider();
        
        authenticationProvider.setUserDetailsService(userDetailService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        
        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

	    // Busca el email del username
	    /*
	     Anotado con @Bean, el método indica a Spring que debe crear una instancia de UserDetailsService y
	      gestionarla como un componente que estará disponible para ser inyectado en otras partes de la aplicación.
	     
	     Cuando un usuario intenta autenticarse (por ejemplo, enviando su email y contraseña en una solicitud
	      de inicio de sesión), Spring Security toma el email como el username.
	      
	      Aquí, Spring Security automáticamente pasa el username (es decir, el email) como argumento 
	      al método loadUserByUsername().
	      
	      Si el usuario es encontrado, se devuelve un objeto UserDetails 
	      (normalmente una clase que implementa UserDetails) a Spring Security.
	     */
    @Bean
    public UserDetailsService userDetailService() {
        return username -> userRepository.findByEmail(username)
        								.orElseThrow(()-> new UsernameNotFoundException("Email no encontrado"));
    }
    
    
    /*
     @Bean
		public UserDetailsService userDetailService() {
		    return new UserDetailsService() {
		        @Override
		        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		            return userRepository.findByEmail(username)
		                .orElseThrow(() -> new UsernameNotFoundException("Email no encontrado"));
		        }
		    };
		}

     */
    
	    /*
	     * Aquí, usamos una expresión lambda para simplificar el código. Esta versión es más concisa y hace lo mismo, 
	     * ya que Java infiere que username será el argumento para el método loadUserByUsername
	     */
    
}
