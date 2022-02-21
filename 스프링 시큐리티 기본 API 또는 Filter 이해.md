# Spring Security



> 본 게시물은 스스로의 공부를 위한 글입니다.
> 잘못된 내용이 있으면 댓글로 알려주세요!



---

####  Reference

인프런 '스프링 시큐리티 - Spring Boot 기반으로 개발하는 Spring Security' (정수원)





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

그럼 누가 이 페이지를 만들어서 로그인하게 만드는 것인가. 바로 스프링 시큐리티다.



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











# 인증

## Form Login 인증

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();

        http.formLogin() // form 로그인 인증 기능이 작동함
                .loginPage("/loginPage") // 사용자 정의 로그인 페이지, default: /login
                .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
                .failureUrl("/login") // 로그인 실패 후 이동 페이지
                .usernameParameter("userId") // 아이디 파라미터명 설정, default: username
                .passwordParameter("passwd") // 패스워드 파라미터명 설정, default: password
                .loginProcessingUrl("/login_proc") // 로그인 Form Action Url, default: /login
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
                .permitAll(); // loginPage 접근은 인증 없이 접근 가능
    }
}
```



```java
.usernameParameter("userId") // 아이디 파라미터명 설정, default: username
.passwordParameter("passwd") // 패스워드 파라미터명 설정, default: password
.loginProcessingUrl("/login_proc") // 로그인 Form Action Url
```

위 3개는 html의 `<form>` 태그와 맞춰야 한다.





### form 인증 과정(`UsernamePasswordAuthenticationFilter`)

1. `AntPathRequestMatcher(/login)` : 로그인 요청이 올바른 url로 들어왔는지 확인(`loginProcessingUrl()`로 커스텀 가능)
2. 인증객체(`Authentication`) 객체 생성(Username과 password를 담음)
3. 위에서 만든 객체를 이용해 `AuthenticationManager`에서 인증처리 (내부적으로 `AuthenticationProvider`에게 인증 위임)
   - 인증 실패시 `AuthenticationExcepion`
   - 인증 성공시 `Authentication`객체를 만들어서 리턴(User 정보와 권한 정보 등을 담음)
4. `Authentication`객체를 `SecurityContext`에 저장 -> Session에 저장(전역으로 사용 가능하게 함)
5. `SuccessHandler` 실행





### Logout

- 세션 무효화, 인증토큰 삭제, 쿠키 정보 삭제, 로그인 페이지로 리다이렉트

```java
http.logout() // 로그아웃 기능 작동함
  .logoutUrl("/logout") // 로그아웃 처리 URL, default: /logout, 원칙적으로 post 방식만 지원
  .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동페이지
  .deleteCookies("JSESSIONID", "remember-me") // 로그아웃 후 쿠키 삭제
  .addLogoutHandler(new LogoutHandler() { // 로그아웃 핸들러
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
      HttpSession session = request.getSession();
      session.invalidate(); // 세션 무효화
    }
  })
  .logoutSuccessHandler(new LogoutSuccessHandler() {// 로그아웃 성공 후 핸들러
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
      response.sendRedirect("/login");
    }
  });
```



### Logout 로직(`LogoutFilter`)

1. `AntPathRequestMatcher(/logout)` : 로그아웃 요청이 올바른 url로 들어왔는지 확인(`logoutUrl()`로 커스텀 가능)
2. `SecurityContext`에서 `Authentication`객체를 꺼내 `SecurityContextLogoutHandler`에게 전달
3. `SecurityContextLogoutHandler`가 세션 무효화, 쿠키 삭제, `Authentication=null`, `SecurityContextHolder.clearContext()` 등을 진행
4. 로그아웃이 성공되면 `SimpleUrlLogoutSuccessHandler`을 통해 특정 페이지로 redirect







### Remember Me 인증

1. 세션이 만료되고 웹 브라우저가  종료된 후에도 어플리케이션이 사용자를 기억하는 기능
2. Remember-Me 쿠키에 대한 Http 요청을 확인한 후 토큰 기반 인증을 사용해 유효성을 검사하고 토큰이 검증되면 사용자는 로그인 된다.
3. 사용자 라이프 사이클
   - 인증 성공(Remember-Me 쿠키 발급)
   - 인증 실패(remember-me 쿠키가 존재하면 쿠키 무효화)
   - 로그아웃(쿠키가 존재하면 쿠키 무효화)



```java
http.rememberMe() // rememberMe 기능 작동함
  .rememberMeParameter("remember") // default: remember-me, checkbox 등의 이름과 맞춰야함
  .tokenValiditySeconds(3600) // 쿠키의 만료시간 설정(초), default: 14일
  .alwaysRemember(false) // 사용자가 체크박스를 활성화하지 않아도 항상 실행, default: false
  .userDetailsService(userDetailsService); // 기능을 사용할 때 사용자 정보가 필요함. 반드시 이 설정 필요함.
```



- Remember Me를 체크하지 않고 로그인 해보자.
- 로그인 쿠키로 JSESSIONID가 response된다. 세션 쿠키 방식으로, 로그인을 인증할 때 사용된다.
- 하지만 세션이 만료되거나 웹 브라우저를 닫거나 등으로 쿠키가 없어진다면? 다시 로그인 해야한다.



- Remember Me를 체크 후 로그인 해보자.
-  말고도 remember-me 라는 쿠키가 날라왔다.
- 이 쿠키에는 회원 아이디와 비밀번호 등이 인코딩 되어 들어있다. 따라서 JSESSIONID이 다른 요인에 의해 삭제되거나 request header에 보내지 않더라도 서버에서는 회원 인증을 하고, 실제 회원과 일치한 정보가 있다면 자동로그인+JSESSIONID 쿠키를 만들어서 보내준다.







### RememberMe 로직 (RememberMeAuthenticationFilter)

이 필터가 실행될 조건은 다음과 같다.

1. 스프링 시큐리티에서 사용하는 인증객체(`Authentication`)가 Security Context에 없어야 함
   - 세션 만료(time out), 브라우저 종료, 세션id 자체를 모르는 등의 요인이 있다. 인증객체가 있다라는 소리는 로그인이 정상적으로 되었고, 회원 정보도 정상적으로 세션에서 찾을 수 있다라는 이야기이다. 따라서 이 필터가 실행될 필요가 없다.
2. 사용자 request header에 remember-me 쿠키 토큰이 존재해야 한다.



실행 조건이 부합하다면 RememberMeService(인터페이스)가 실행된다. 실제 구현체 2가지 있는데, 그 차이는 다음과 같다.

1. `TokenBasedRememberMeServices`:  서버 메모리에 있는 쿠키와 사용자가 보내온 remember-me 쿠키를 비교(기본적으로 14일간 존재)
2. `PersistentTokenBasedRememberMeServices`: DB에 저장되어 있는 쿠키와 사용자가 보내온 remember-me 쿠키를 비교(이름 그대로 persistent)



다음과 같은 로직으로 진행한다.

1. Token Cookie이 존재하면 추출
2. Decode Token하여 토큰이 정상인지 판단
3. 사용자가 들고온 토큰과 서버에 저장된 토큰이 서로 일치하는지 판단
4. 토큰에 저장된 정보를 이용해 DB에 해당 User 계정이 존재하는지 판단
5. 위 조건을 모두 통과하면 새로운 인증객체(`Authentication`)을 생성 후 `AuthenticationManager`에게 인증 처리를 넘긴다. (물론 Security Context에도 인증 객체를 저장한다.)
6. 이후 response 될 때 `JSESSIONID`를 다시 보내준다.











## AnonymousAuthenticationFilter

익명 사용자와 인증 사용자를 구분해서 처리하기 위한 용도로 사용한다.



사용자가 request 하게 된다.

위 필터가 요청을 받는다.

Authentication(인증 객체)가 security context에 존재하는지 확인한다.

인증 객체가 없다는건 이 사용자가 인증을 받지 못했다는 소리이다. 이 사용자를 익명 사용자로 인식하고 인증객체(Anonymous AuthenticationToken)을 발급해서 SecurityContext 안에 인증 객체를 저장한다.

스프링 시큐리티는 여러 곳에서 현재 사용자가 익명 사용자인지 검사할 수 있는데, 이 때 위 토큰 타입인지로 판단한다.



화면에서 인증 여부를 구현할 때 isAnonymous()와 isAuthenticated()로 구분해서 사용한다.

예를 들어 isAnonymous==true 이면 화면 상단을 로그인 버튼으로 노출시키고, isAuthenticated==true이면 로그아웃 버튼으로 노출시킨다.

인증 객체를 세션에 저장하지 앟는다.









## 동시 세션 제어

동일한 계정으로 로그인 되었을 때, 그 세션을 관리하는 정책이다.

만약 최대 세션 허용 개수를 초과했다 가정하자.

두 가지 방법이 있다.

1. 이전 사용자를 세션 만료시킨다.
![스크린샷 2022-02-12 오후 5.28.10](/Users/hongseungtaeg/Desktop/inflearn spring security/스크린샷 2022-02-12 오후 5.28.10.png)



2. 현재 사용자 인증 실패
![스크린샷 2022-02-12 오후 5.28.10](/Users/hongseungtaeg/Desktop/inflearn spring security/스크린샷 2022-02-12 오후 5.28.17.png)





```java
http.sessionManagement() // 세션 관리 기능이 작동
  .maximumSessions(1) // 최대 허용 가능 세션 수, -1=무제한 로그인 세션 허용
  .maxSessionsPreventsLogin(true) // 동시 로그인 차단함, default: false(기존 세션 만료)
```







## 세션 고정 보호

인증에 성공할 때마다 세션을 다시 만들고, 쿠키도 새롭게 발급 = 세션 고정 보호

공격자가 사용자의 쿠키를 탈취해도 사용자의 쿠키는 계속 달라지기 때문에 그나마 괜찮다..?



기본값으로는 `.changeSessionId()`: 인증 때마다 세션 아이디를 변경, 서블릿 3.1 이상부터 지원

`migrateSession`: 서블릿 3.1 밑에서 지원

`newSession`: 세션을 완전히 새롭게 설정. 세션 id는 당연히 달라짐

`none`: 세션 재생성x, 사용 안하는 꼴임.

따로 설정하지 않아도 기본적으로 스프링 시큐리티가 자동으로 설정해준다.

```java
http
  .sessionManagement()
  .sessionFixation().none();
```







## 세션 정책

```java
http
  .sessionManagement()
  .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
```

SessionCreationPolicy.Always : 스프링 시큐리티가 항상 세션 생성

SessionCreationPolicy.If_Required : 스프링 시큐리티가 필요 시 생성(기본값)

SessionCreationPolicy.Never : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용

SessionCreationPolicy.Stateless : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음(JWT을 사용할 때 사용)







## SessionManagementFilter 정리

1. 세션 관리: 인증 시 사용자의 세션정보를 등록, 조회, 삭제 등의 세션 이력을 관리
2. 동시적 세션 제어: 동일 계정으로 접속이 허용되는 최대 세션수를 제한
3. 세션 고정 보호: 인증 할 때마다 세션쿠키를 새로 발급하여 공격자의 쿠키 조작을 방지
4. 세션 생성 정책: Always, If_Required, Never, Stateless





## ConcurrentSessionFilter

- `SessionManagementFilter `와 함께 동시적 세션 제어
- 매 요청 마다 현재 사용자의 세션 만료 여부 체크
- 세션이 만료되었을 경우 즉시 만료 처리
- `session.isExpired()==true`
  - 로그아웃 처리
  - 즉시 오류 페이지 응답(This session has been expired)

![](C:\Users\s_gmtmoney2357\Desktop\인프런\Spring Security\sessionManagementFilter.PNG)





## 인증 과정(인증이 필요한 자원에 접근할 경우)

1. `UsernamePasswordAuthenticationFilter` 에서 인증한다.
2. 인증에 성공했다면 그 세션에 대한 정보를 `ConcurrentSessionFilter`에서 확인한다. 만약 `session.isExpired()==true`라면 세션이 만료 된것이므로, 로그아웃하고 오류 페이지를응답한다.
3. `ConcurrentSessionControlAuthenticationStrategy`에서 로그인 계정의 세션이 몇개 있나 확인한다. 만약  maxSessions와 동일하다면 2가지 전략을 사용할 수 있다. 인증 실패 전략의 경우 `SessionAuthenticationException`을 통해 현재 로그인 인증을 실패한다. 세션 만료 전략의 경우 전에 등록된 세션을 `session.expireNow()`한다.
4. `ChangeSessionIdAuthenticationStrategy`에서 세션ID를 변경한다(세션 고정 보호)
5. `RegisterSessionAuthenticationStrategy`에서 현재 로그인 계정의 세션을 등록한다.

![](C:\Users\s_gmtmoney2357\Desktop\인프런\Spring Security\인증 과정.PNG)











# 인가

## 권한 설정 및 표현식

- 선언적 방식
  - URL: http.antMatchers("/users/**").hasRole("USER")
  - Method: @PreAuthorize("hasRole('USER')") public void user(){ ~ }
- 동적 방식 - DB 연동 프로그래밍
  - URL
  - Method









### 1. 선언적 방식: URL

```java
http
    .antMatcher("/shop/**") // 이 경로의 요청들에 대해 아래 설정 적용. 생략하면 모든 요청에 대해 적용
    .authorizeRequests()
     .antMatchers("/shop/login", "/shop/users/**").permitAll()
     .antMatchers("/shop/mypage").hasRole("USER")
     .antMatchers("/shop/admin/pay").access("hassRole('ADMIN')")
     .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
     .anyRequest().authenticated(); // 나머지 요청들에 대해서는 인증 필요.
/** 주의 사항 - 구체적인 경로가 먼저 오고, 그것보다 큰 범위의 경로가 뒤에 오도록 해야 한다. **/
/** 위에서부터 해석하면서 인증하기 때문에 그렇다. **/
```

권한을 설정할 때 표현식을 사용할 수 있다.

| 메소드                         | 동작                                                      |
| ------------------------------ | --------------------------------------------------------- |
| **authenticated()**            | 인증된 사용자의 접근을 허용                               |
| **fullyAuthenticated()**       | 인증된 사용자의 접근을 허용,  rememberMe 인증 제외        |
| **permitAll()**                | 무조건 접근을 허용                                        |
| **denyAll()**                  | 무조건 접근을 허용하지 않음                               |
| **anonymous()**                | 익명사용자의 접근을 허용                                  |
| **rememberMe()**               | 기억하기를 통해 인증된 사용자의 접근을 허용               |
| **access(String)**             | 주어진 SpEL 표현식의 평가 결과가 true이면 접근을 허용     |
| **hasRole(String)**            | 사용자가 주어진 역할이 있다면 접근을 허용   (ex USER)     |
| **hasAuthority(String)**       | 사용자가 주어진 역할이 있다면 접근을 허용 (ex Role_USER)  |
| **hasAnyRole(String...)**      | 사용자가 주어진 권한이 있다면 접근을 허용                 |
| **hasAnyAuthority(String...)** | 사용자가 주어진 권한 중 어떤 것이라도 있다면  접근을 허용 |
| **hasIpAddress(String)**       | 주어진 IP로부터 요청이 왔다면 접근을 허용                 |







## 예외 처리 및 요청 캐시 필터

### ExceptionTranslationFilter

#### AuthenticationException(인증 예외 처리)

1. AuthenticationEntryPoint 호출: 로그인 페이지 이동, 401 오류 코드 전달 등
2. 인증 예외가 발생하기 전의 요청 정보를 저장
   - SavedRequest : 사용자가 요청했던 request 파라미터 값들, 그 당시의 헤더값들 등이 저장
   - RequestCache : 사용자의 이전 요청 정보를 세션에 저장하고 이를 꺼내 오는 캐시 메커니즘



#### AccessDeniedException(인가 예외 처리)

- AccessDeniedHandler에서 예외 처리하도록 제공



![](C:\Users\s_gmtmoney2357\Desktop\인프런\Spring Security\exceptionFilter.PNG)





```java
http.exceptionHandling() // 예외 처리 기능 작동
                .authenticationEntryPoint(authenticationEntryPoint()) // 인증 실패시 처리
                .accessDeniedHandler(accessDeniedHandler()) // 인가 실패시 처리
```

`authenticationEntryPoint()`, `accessDeniedHandler()`에는 구현체를 넣으면 된다.

익명 구현체를 사용하면 다음과 같다. 이때 `http.successHandler`와 함께 사용한다면 로그인 후 원래 가려던 페이지로 이동할 수 있다. (원래 가려던 페이지 등의 정보는 `RequestCache`에 저장되어 있다.)

```java
http.formLogin()
    .successHandler(new AuthenticationSuccessHandler() {
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            RequestCache requestCache = new HttpSessionRequestCache();
            SavedRequest savedRequest = requestCache.getRequest(request, response);
            String redirectUrl = savedRequest.getRedirectUrl();
            response.sendRedirect(redirectUrl);
        }
    });

http.exceptionHandling() // 예외 처리 기능 작동
    .authenticationEntryPoint(new AuthenticationEntryPoint() {
        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
            response.sendRedirect("/login");
        }
    })
    .accessDeniedHandler(new AccessDeniedHandler() {

        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
            response.sendRedirect("/denied");
        }
    });
```







### CSRF(사이트 간 요청 위조)

1. 사용자가 정상적으로 쇼핑몰에 로그인 후 쿠키를 받아온다.
2. 공격자가 이용자에게 특정 링크를 클릭하게 만든다. 이때 그 링크는 쇼핑몰의 도메인과 같다.
3. 사용자의 브라우저는 사용자가 클릭한 링크가 쇼핑몰이므로 정상적으로 쿠키까지 전달하면서 접속하게 된다.
4. 쇼핑몰은 정상적인 접근으로 알고, 처리해준다.



스프링 시큐리티는 CsrfFilter을 통해서 이를 방지한다.

모든 요청에 랜덤하게 생성된 토큰을 HTTP 파라미터로 요구한다.

요청시 전달되는 토큰 값과 서버에 저장된 실제 값을 비교한 후 일치하지 않으면 요청은 실패한다.



- Client
  - `<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"`
  - HTTP 메소드: PATCH, POST, PUT, DELETE
- Spring Security
  - http.csrf(): default=활성화
  - http.csrf().disabled() : 비활성화








