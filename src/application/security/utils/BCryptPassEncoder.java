package application.security.utils;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class BCryptPassEncoder {
	
	@Bean
	public PasswordEncoder bCryptEncoder() {
		return new BCryptPasswordEncoder();
	}

}
