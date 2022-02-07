# Spring Security



## 프로젝트 생성하기

먼저 dependency로 `spring-boot-starter-web`만 선택 한 후 스프링 프로젝트를 생성하자.

Maven이나 gradle 상관 없지만, 이 게시물에서는 Maven으로 진행한다.



간단한 컨트롤러를 생성해보자.

```java
@RestController
public class SecurityController {
    @GetMapping("/")
    public String index() {
        return "home";
    }
}
```



`http://localhost:8080/`으로 접속을 해보자.

다음과 같은 화면이 뜬다.





이번에는 스프링 시큐리티 디펜던시를 추가해보자.

```xml
<dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```



서버 재시작 후 아까와 동일하게 `http://localhost:8080/`으로 접속을 해보자.

그럼 다음과 같은 로그인 페이지 화면이 뜬다.

뭔가 심플하면서 매력있는 로그인 페이지다.



제공되는 기본 계정을 이용해서 로그인 해보자.

`username: user`, `password: 콘솔창 문자열`

로그인을 하고서야 우리가 만든 페이지로 이동이 가능하다.





우리가 이 페이지를 만든 적이 있나? 없다.

그럼 누가 이 페이지를 만들어서 로그인하게 만드는 것인가.. 바로 스프링 시큐리티다.



스프링 시큐리티의 의존성을 추가만 해도 다음과 같은 일들이 벌어진다.

1. 모든 요청은 인증이 되어야 자원에 접근이 가능하다.
2. 인증 방식은 폼 로그인 방식과 httpBasic 로그인 방식을 제공한다.
3. 기본 로그인 페이지를 제공한다.
4. 기본 계정을 한 개 제공한다.



앞으로 우리가 해야할 일은 스프링 시큐리티가 제공하는 기능들과 설정들을 이용해서 세부적이고 추가적인 보안 기능을 사용하는 것이다.









스프링 시큐리티에서 핵심적인 설정 클래스는 `WebSecurityConfigurerAdapter`이다.

세부적인 보안 기능을 설정할 수 있는 API를 제공하는 클래스는 `HttpSecuritty`이다.

따라서 우리는 사용자 정의 설정 클래스를 만들어서 제공하는 API를 이용해 설정을 마치면 된다.



`HttpSecurity`가 제공하는 API는 2가지 종류이다. 인증 API와 인가 API

그 종류로는 다음과 같다.

인증 API

- http.formLogin()
- http.logout()
- http.csrf()
- http.httpBasic()
- http.SessionManagement()
- http.RememberMe()
- http.ExceptionHandling()
- http.addFilter()

인가 API

- http.authorizeRequests()
- http.antMatchers()
- http.hasRole()
- http.permitAll()
- http.authenticated()
- http.acess(hasRole())
- http.denyAll()



각 API별 디테일한 이야기는 다른 게시물에서 알아보자. 





간단한 보안 설정 클래스를 작성해보자.

```java
@Configuration // 설정 파일이므로 필요
@EnableWebSecurity // 스프링 시큐리티를 사용한다는 의미이다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http    .authorizeRequests() // 시큐리티 처리에 HttpServletRequest를 이용
                .anyRequest().authenticated(); // 모든 요청에 인증 필요

        http    .formLogin(); // 폼 로그인 방식 사용
    }
}
```

핵심 보안 설정 클래스인 `WebSecurityConfigurerAdapter`을 extends한다.

`configure(HttpSecurity http)`를 오버라이드 받아서 설정하면 된다.



매번 콘솔창에 있는 패스워드를 복사, 붙여넣기 하면 귀찮으니, 자동 생성되는 계정의 이름과 비밀번호를 직접 명시해주자.

```properties
# application.properties
spring.security.user.name=user
spring.security.user.password=1111
```









## Form Login 인증

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();

        http.formLogin()
                //.loginPage("/loginPage") // 사용자 정의 로그인 페이지, default: /login
                .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
                .failureUrl("/login") // 로그인 실패 후 이동 페이지
                .usernameParameter("userId") // 아이디 파라미터명 설정, default: username
                .passwordParameter("passwd") // 패스워드 파라미터명 설정, default: password
                .loginProcessingUrl("/login_proc") // 로그인 Form Action Url
                .successHandler( // 로그인 성공 후 핸들러
                        new AuthenticationSuccessHandler() { // 익명 객체 사용
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                System.out.println("authentication: " + authentication.getName());
                                response.sendRedirect("/");
                            }
                        })
                .failureHandler( // 로그인 실패 후 핸들러
                        new AuthenticationFailureHandler() { // 익명 객체 사용
                            @Override
                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                System.out.println("exception: " + exception.getMessage());
                                response.sendRedirect("/login");
                            }
                        })
                .permitAll();
    }
}
```





