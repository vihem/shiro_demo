package cn.ea.servlet;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * LoginServlet 映射路径/login的访问。
 * 获取账号和密码，然后组成 UsernamePasswordToken 对象，扔给Shiro进行判断。
 * 如果判断不报错，即表示成功，客户端跳转到根目录，否则返回login.jsp，并带上错误信息
 * 登录成功后还会把subject放在shiro的session对象里，shiro的这个session和httpsession之间是同步的，所以在这里放了，它会自动放在httpsession里。
 */
@WebServlet(name = "loginServlet", urlPatterns = "/login")
public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String username = req.getParameter("name");
        String password = req.getParameter("password");
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);

        Subject subject = SecurityUtils.getSubject();
        try {
            subject.login(token);
            Session session = subject.getSession();
            session.setAttribute("subject",subject);
            
            resp.sendRedirect("index.jsp");//响应发送到index.jsp页面
        } catch (AuthenticationException e) {
            req.setAttribute("error", "验证失败");
            req.getRequestDispatcher("login.jsp").forward(req,resp);//转发到login.jsp
        }
    }
}
