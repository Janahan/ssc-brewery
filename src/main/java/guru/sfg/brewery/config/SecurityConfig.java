package guru.sfg.brewery.config;

import guru.sfg.brewery.security.CustomPasswordEncoderFactory;
import guru.sfg.brewery.security.RestHeaderAuthFilter;
import guru.sfg.brewery.security.RestURLAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    public RestHeaderAuthFilter restHeaderAuthFIlter(AuthenticationManager authenticationManager){
        RestHeaderAuthFilter restHeaderAuthFilter=new RestHeaderAuthFilter(
                new AntPathRequestMatcher("/api/**"));
        restHeaderAuthFilter.setAuthenticationManager(authenticationManager);
        return restHeaderAuthFilter;
    }

    public RestURLAuthFilter restURLAuthFilter(AuthenticationManager authenticationManager){
        RestURLAuthFilter restURLAuthFilter=new RestURLAuthFilter(
                new AntPathRequestMatcher("/api/**"));
        restURLAuthFilter.setAuthenticationManager(authenticationManager);
        return restURLAuthFilter;
    }




    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.addFilterBefore(restHeaderAuthFIlter(authenticationManager()),
                UsernamePasswordAuthenticationFilter.class)
        .csrf().disable();

        http.addFilterBefore(restURLAuthFilter(authenticationManager()),
                UsernamePasswordAuthenticationFilter.class);

                http
                        .authorizeRequests(
                                authorize ->{
                                    authorize
                                            .antMatchers("/h2-console/**").permitAll() //Dont do in prod env
                                            .antMatchers("/","/webjars/**","/login","/resources/**").permitAll();
                                    //.antMatchers("/beers/find","/beers*").permitAll()
                                    //        .mvcMatchers("/beers/find","/beers/{beerId}").hasAnyRole("ADMIN","CUSTOMER","USER")
                                    //.antMatchers(HttpMethod.GET,"/api/v1/beer/**").permitAll()
                                          //  .antMatchers(HttpMethod.GET,"/api/v1/beer/**").hasAnyRole("ADMIN","CUSTOMER","USER")
                                           // .mvcMatchers(HttpMethod.DELETE,"/api/v1/beer/**").hasRole("ADMIN")
                                    //.mvcMatchers(HttpMethod.GET,"/api/v1/beerUpc/{upc}").permitAll()
                                        //    .mvcMatchers(HttpMethod.GET,"/api/v1/beerUpc/{upc}").hasAnyRole("ADMIN","CUSTOMER","USER")
                                            //.mvcMatchers("/brewery/breweries").hasRole("CUSTOMER")
                                            //.mvcMatchers(HttpMethod.GET, "/brewery/api/v1/breweries").hasRole("CUSTOMER");
                                    //        .mvcMatchers("/brewery/breweries").hasAnyRole("ADMIN","CUSTOMER")
                                    //       .mvcMatchers(HttpMethod.GET, "/brewery/api/v1/breweries").hasAnyRole("ADMIN","CUSTOMER");
                                }
                        )
                        .authorizeRequests()
                        .anyRequest()
                        .authenticated()
                        .and()
                        .formLogin()
                        .and()
                        .httpBasic();
                //h2 console config
                http.headers().frameOptions().sameOrigin();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        //return NoOpPasswordEncoder.getInstance();
        //return new LdapShaPasswordEncoder();
        //return new StandardPasswordEncoder();
        //return new BCryptPasswordEncoder();
        //return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        return CustomPasswordEncoderFactory.createDelegatingPasswordEncoder();
    }

    //Option1 Spring boot would detect these because there is no other
    //@Autowired
    //JpaUserDetailsService jpaUserDetailsService;

    //@Override
    //protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //Option1 Spring boot would detect these because there is no other
        //auth.userDetailsService(this.jpaUserDetailsService).passwordEncoder(passwordEncoder());
        /*
        auth.inMemoryAuthentication()
                .withUser("jana")
                //.password("{noop}jana123")
                //.password("jana123")
                .password("{bcrypt}$2a$10$gVhvnG5WM5bJlriFE2Y0leOYEW4ojNwN/xUS9M.pZ2L6JCZXDa14u")
                .roles("ADMIN")
                .and()
                .withUser("user")
                //.password("{noop}password")
                //.password("password")
                //.password("{SSHA}VZfYe7gOxBPWqVsyYxe3ExdllrTPozcNDM0/mg==")
                //.password("9c3323c5b0599053c5b03bebe3444f9c09b9de658a46fd015ed306b1b94f4d08650262cc15ac008e")
                //.password("$2a$10$WoS27ILWnCkOdJzmkoJ4T.JrdH2UbuBgRi/EbAorGgsiE8GqY63vS")
                .password("{sha256}5d811df02e80668f5d4a439d09e9dfd79303dd8cd99e8b2a26580e800c1d5e17d4e81f3b1126c942")
                .roles("USER");

        //auth.inMemoryAuthentication().withUser("scott").password("{noop}tiger").roles("CUSTOMER");
        auth.inMemoryAuthentication()
                .withUser("scott")
                //.password("{noop}tiger")
                //.password("{ldap}{SSHA}jb//u1/ABOB9T2/AmRhFkRu3ffBzcHKgmSGsqA==")
                .password("{bcrypt15}$2a$15$2KYL5D/a8lCAZ.7CRDTghOk0FMtR7mYtQXOMTcPwS82pezxsCqHJ2")
                .roles("CUSTOMER");
    */

    //}

    /*
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails admin= User.withDefaultPasswordEncoder()
                .username("jana")
                .password("jana123")
                .roles("ADMIN")
                .build();

        UserDetails user= User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin,user);
    }
    */

}
