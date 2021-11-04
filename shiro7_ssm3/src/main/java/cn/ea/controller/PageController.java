package cn.ea.controller;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * 专门用于显示页面的控制器
 * 因为使用 ssm，所以jsp通常都会放在WEB-INF/jsp 下面，而这个位置是无法通过浏览器直接访问的，所以就会专门做这么一个类，便于访问这些jsp。
 * 比如要访问WEB-INF/jsp/index.jsp文件，那么就通过/index 这个路径来访问。
 */
@Controller
@RequestMapping("")
public class PageController {
    
    @RequestMapping("index")
    public String index(){
        return "index";
    }

//    @RequiresPermissions("deleteOrder") //@RequiresPermissions("deleteOrder") 指明了 访问 deleteOrder 需要权限"deleteOrder" 
    @RequestMapping("deleteOrder")
    public String deleteOrder(){
        return "deleteOrder";
    }
    
//    @RequiresRoles("admin")    //@RequiresRoles("admin") 指明了 访问 deleteProduct 需要角色"admin"
    @RequestMapping("deleteProduct")
    public String deleteProduct(){
        return "deleteProduct";
    }
    
    @RequestMapping("listProduct")
    public String listProduct(){
        return "listProduct";
    }

    // /login 只支持get方式。 post方式是后续用来进行登录行为的，这里的get方式仅仅用于显示登录页面
    @RequestMapping(value="/login", method = RequestMethod.GET)
    public String login(){
        return "login";
    }
    
    @RequestMapping("unauthorized")
    public String noPerms(){
        return "unauthorized";
    }
}
