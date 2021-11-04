package cn.ea.exception;

import org.apache.shiro.authz.UnauthorizedException;
import org.springframework.http.HttpStatus;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.servlet.ModelAndView;

/**
 * 当发生 UnauthorizedException 异常的时候，就表示访问了无授权的资源，
 * 那么就会跳转到unauthorized.jsp，
 * 而在unauthorized.jsp 中就会把错误信息通过变量 ex 取出来。
 *
 * DefaultExceptionHandler 的使用，是声明在 springMVC.xml 的最后几行：
 */
@ControllerAdvice
public class DefaultExceptionHandler {
    
    @ExceptionHandler
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ModelAndView processUnauthenticatedException(NativeWebRequest request, UnauthorizedException exception){
        ModelAndView mv = new ModelAndView();
//        mv.addObject("ex", exception);
        ModelMap map = mv.getModelMap();
        map.put("ex", exception);
        mv.setViewName("unauthorized");
        return mv;
    }
}
