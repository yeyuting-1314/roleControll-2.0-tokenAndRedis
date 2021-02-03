package testdemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import testdemo.config.filter.JWTAuthorizationFilter;
import testdemo.config.handler.AuthenticationAccessDeniedHandler;
import testdemo.config.handler.SimpleAuthenticationEntryPoint;
import testdemo.system.service.impl.UserServiceImpl;

/**
 * @author yeyuting
 * @create 2021/1/28
 */
//将自定义FilterInvocationSecurityMetadataSource和自定义AccessDecisionManager配置到Spring Security的配置类中
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserServiceImpl userDetailsService ;
    @Autowired
    private AuthenticationFailureHandler customAuthenticationFailureHandler;
    @Autowired
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler ;
    @Autowired
    AuthenticationAccessDeniedHandler authenticationAccessDeniedHandler;
    @Autowired
    SimpleAuthenticationEntryPoint simpleAuthenticationEntryPoint;
    /**
     * 配置角色继承关系
     *
     * @return
     */
    @Bean
    RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl() ;
        String hierarchy = "ROLE_SUPERADMIN > ROLE_ADMIN > ROLE_USER" ;
        roleHierarchy.setHierarchy(hierarchy) ;
        return roleHierarchy ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder()) ;

    }

    /**
     * @Author: Galen
     * @Description: 配置放行的资源
     * @Date: 2019/3/28-9:23
     * @Param: [web]
     * @return: void
     **/
    /*@Override
    public void configure(WebSecurity web) throws Exception {
        //web.ignoring().antMatchers("/login/user");
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
                        object.setSecurityMetadataSource(cfisms());
                        object.setAccessDecisionManager(cadm());
                        return object ;
                    }
                })
                .antMatchers("/userLogin").permitAll()
                // 所有访问该应用的http请求都要通过身份认证才可以访问
                .anyRequest().authenticated()
                .and().httpBasic()
                .and()
                .csrf().disable()
                // 指定登陆URL
                .formLogin()
                .loginProcessingUrl("/userLogin")
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .and()
                .exceptionHandling().accessDeniedHandler(authenticationAccessDeniedHandler)
                .authenticationEntryPoint(simpleAuthenticationEntryPoint)
                .and()
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                // 不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }


    /**
     * 自定义的FilterInvocationSecurityMetadataSource
     * 将访问当前资源的URL与数据库中访问该资源的URL进行匹配
     *
     * @return
     */
    @Bean
    FilterInvocationSecurityMetadataSource cfisms() {
        return new FilterInvocationSecurityMetadataSource();
    }

    /**
     * 自定义的AccessDecisionManager
     * 判断登录用户是否具备访问当前URL所需要的角色
     *
     * @return
     */
    @Bean
    AccessDecisionManager cadm() {
        return new AccessDecisionManager();
    }


}
