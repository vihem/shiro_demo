package cn.ea.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * 进行登录的控制器，和 LoginServlet 一样，获取账号密码进行验证，如果成功了就客户端跳转到index,否则就返回login.jsp页面。
 * 需要注意的是，这里用的是 post 方式
 */
@Controller
@RequestMapping("")
public class LoginController {

    @RequestMapping(value="/login",method = RequestMethod.POST)
    public String login(Model model, String name, String password){
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(name, password);
        try {
            subject.login(token);
            Session session = subject.getSession();
            session.setAttribute("subject", subject);
            return "redirect:index";
        } catch (AuthenticationException e) {
            model.addAttribute("error", "登录失败");
            return "login";
        }
    }
}
