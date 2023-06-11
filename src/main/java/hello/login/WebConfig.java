package hello.login;

import hello.login.web.argumentresolver.LoginMemberArgumentResolver;
import hello.login.web.filter.LogFilter;
import hello.login.web.filter.LoginCheckFilter;
import hello.login.web.interceptor.LogInterceptor;
import hello.login.web.interceptor.LoginCheckInterceptor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.Filter;
import java.util.List;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver>
                                             resolvers) {
        resolvers.add(new LoginMemberArgumentResolver());
    }

    @Override
    // WebMvcConfigurer 가 제공하는 addInterceptors() 를 사용해서 인터셉터를 등록할 수 있다.
    public void addInterceptors(InterceptorRegistry registry) {
        // registry.addInterceptor(new LogInterceptor()): 인터셉터 등록
        registry.addInterceptor(new LogInterceptor())
                // 호출 순서
                .order(1)
                // 인터셉터 지정할 URL 패턴 지정
                .addPathPatterns("/**")
                // 인터셉터에서 제외할 패턴을 지정
                .excludePathPatterns("/css/**", "/*.ico", "/error");

        registry.addInterceptor(new LoginCheckInterceptor())
                .order(2)
                // 인터셉터를 적용하거나 하지 않을 부분 등록
                // 기본적으로 모든 경로에 해당 인터셉터를 적용
                .addPathPatterns("/**")
                // 로그인 체크 인터셉터 적용 x
                .excludePathPatterns(
                        "/", "/members/add", "/login", "/logout",
                        "/css/**", "/*.ico", "/error"
                );

    }

//    @Bean
    // 스프링 부트를 사용하면 FilterRegistrationBean 을 사용해서 등록
    public FilterRegistrationBean logFilter() {
        FilterRegistrationBean<Filter> filterRegistrationBean = new FilterRegistrationBean<>();
        // setFilter: 등록할 필터 지정
        filterRegistrationBean.setFilter(new LogFilter());
        // setOrder: 필터 체인의 순서 지정, 낮을 수록 우선 동작
        filterRegistrationBean.setOrder(1);
        // addUrlPatterns: 필터를 지정할 URL 패턴 지정, 여러 패턴에 지정을 위한 /*
        filterRegistrationBean.addUrlPatterns("/*");

        return filterRegistrationBean;
    }

//    @Bean
    public FilterRegistrationBean loginCheckFilter() {
        FilterRegistrationBean<Filter> filterRegistrationBean = new
                FilterRegistrationBean<>();
        // 비회원이 접근할 경우 로그인 필터 등록
        filterRegistrationBean.setFilter(new LoginCheckFilter());
        // 순서를 2번으로 잡았다. 로그 필터 다음에 로그인 필터가 적용된다.
        filterRegistrationBean.setOrder(2);
        // 모든 요청에 로그인 필터를 적용한다.
        filterRegistrationBean.addUrlPatterns("/*");
        return filterRegistrationBean;
    }
}
