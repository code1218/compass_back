package com.aws.compass.security.oauth2;

import com.aws.compass.entity.User;
import com.aws.compass.jwt.JwtProvider;
import com.aws.compass.repository.UserMapper;
import com.aws.compass.security.PrincipalUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserMapper userMapper;
    private final JwtProvider jwtProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            String oauth2Id = authentication.getName(); // loadUser에서 return 했던 DefaultOAuth2User의 key값
            User user = userMapper.findUserByOauth2Id(oauth2Id);

            System.out.println(user);

            if (user == null) { // 소셜 로그인 돼있는 유저가 없다면 -> 새로 회원가입
                DefaultOAuth2User defaultOAuth2User = (DefaultOAuth2User) authentication.getPrincipal();
                String name = defaultOAuth2User.getAttributes().get("name").toString();
                String provider = defaultOAuth2User.getAttributes().get("provider").toString();

                // 회원가입이 안 되었을 때 OAuth2 계정 회원가입 페이지로 이동
                response.sendRedirect("http://localhost:3000/auth/detail/signup" +
                        "?oauth2Id=" + oauth2Id +
                        "&name=" + URLEncoder.encode(name, "UTF-8") +
                        "&provider=" + provider);
                return;
            }
            // 소셜 로그인 돼있는 유저가 있다면 -> 로그인
            PrincipalUser principalUser = new PrincipalUser(user);
            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(principalUser, null, principalUser.getAuthorities());
            String accessToken = jwtProvider.generateToken(authenticationToken);
            response.sendRedirect("http://localhost:3000/auth/oauth2/signin" +  // client로 token을 보낸다
                    "?token=" + URLEncoder.encode(accessToken));

    }
}