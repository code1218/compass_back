package com.aws.compass.service;

import com.aws.compass.dto.EditUserReqDto;
import com.aws.compass.dto.ReviewListRespDto;
import com.aws.compass.entity.Academy;
import com.aws.compass.entity.Review;
import com.aws.compass.entity.User;
import com.aws.compass.exception.AuthMailException;
import com.aws.compass.exception.SendMailException;
import com.aws.compass.jwt.JwtProvider;
import com.aws.compass.repository.AccountMapper;
import com.aws.compass.security.PrincipalUser;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.mail.internet.MimeMessage;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class AccountService {

    private final AccountMapper accountMapper;
    private final JavaMailSender javaMailSender;
    private final JwtProvider jwtProvider;
    private final AuthService authService;

    @Value("${server.serverAddress}")
    private String serverAddress;

    public boolean updateUser(int userId, EditUserReqDto editUserReqDto) {
        User newUser = editUserReqDto.toUser();
        newUser.setUserId(userId);

        int errorCode = accountMapper.checkDuplicateAndIdNot(newUser);
        if(errorCode > 0) {
            authService.responseDuplicateError(errorCode);
        }

        PrincipalUser principalUser = (PrincipalUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        User oldUser = principalUser.getUser();

        if(oldUser.getEnabled() > 0 && !Objects.equals(oldUser.getEmail(), newUser.getEmail())) {  // 이메일 변경 하면 enabled 0으로 업데이트 해줘야 함.
            newUser.setEnabled(0);
        } else {
            newUser.setEnabled(oldUser.getEnabled());
        }

        return accountMapper.updateUser(newUser) > 0;
    }

    public boolean sendAuthMail() {
        PrincipalUser principalUser = (PrincipalUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String toEmail = principalUser.getUser().getEmail();

        MimeMessage mimeMailMessage = javaMailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMailMessage, false, "utf-8");
            helper.setSubject("학습 나침반 이메일 인증");
            helper.setFrom("mini011029@gmail.com");
            helper.setTo(toEmail);

            String token = jwtProvider.generateAuthMailToken(toEmail);      //이메일 인증을 위한 토큰 발행

            mimeMailMessage.setText(
                    //html로 mail을 전송하기 위함
                    "<div>" +
                            "<h1>학습 나침반 이메일 인증 메일</h1>"+
                            "<p>이메일 인증을 완료하려면 아래의 버튼을 클릭하세요.</p>" +
                            "<a href=\"http://" + ("localhost".equals(serverAddress) ? "localhost:8080" : serverAddress) + "/api/account/auth/email?token=" + token + "\">인증하기</a>" +
                    "</div>", "utf-8", "html"
            );
            javaMailSender.send(mimeMailMessage);       //설정한 메시지를 sender를 통해 전달함
        } catch (Exception e) {
            e.printStackTrace();
            throw new SendMailException("이메일 전송이 실패했습니다.");
        }
        return true;
    }

    @Transactional(rollbackFor = Exception.class)
    public boolean authenticateMail(String token) {
        Claims claims = jwtProvider.getClaims(token);
        if(claims == null) {    // 유효하지 않은 토큰
            throw new AuthMailException("만료된 인증 요청입니다.");
        }

        String email = claims.get("email").toString();
        User user = accountMapper.findUserByEmail(email);

        if(user.getEnabled() > 0) { // 이미 인증된 상태
            throw new AuthMailException("이미 인증이 완료된 요청입니다.");
        }

        return accountMapper.updateEnabledToEmail(email) > 0;
    }

    public boolean getLikeState(int userId, int academyId) {
        return accountMapper.getLikeState(userId, academyId) > 0;
    }

    public boolean setLike(int userId, int academyId) {
        return accountMapper.insertLike(userId, academyId) > 0;
    }

    public boolean cancelLike(int userId, int academyId) {
        return accountMapper.deleteLike(userId, academyId) > 0;
    }

    public int getLikeCount(int userId) {
        return accountMapper.getLikeCountByUserId(userId);
    }

    public List<Academy> getLikeAcademy(int userId, int page) {
        int index = (page - 1) * 5;

        return accountMapper.getLikeAcademies(userId, index);
    }

    public int getLikeInfoCount(int academyId) {
        return accountMapper.getLikeCountByAcademyId(academyId);
    }

    public ReviewListRespDto getUserReviews(int userId, int page) {
        int index = (page - 1) * 5;
        return new ReviewListRespDto(accountMapper.getUserReviews(userId, index), accountMapper.getUserReviewCount(userId));
    }

    public int deleteUser(int userId) { return accountMapper.deleteUser(userId); }
}
