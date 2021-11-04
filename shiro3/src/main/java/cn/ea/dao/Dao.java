package cn.ea.dao;

import cn.ea.entity.User;
import cn.ea.shiro.ShiroUtil;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public class Dao {
    public Dao() {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(
                "jdbc:mysql://127.0.0.1:3306/shiro?serverTimezone=UTC&characterEncoding=UTF-8",
                "root",
                "root"
        );
    }

    public String createUser(String name, String password) {
        String sql = "insert into user values(null,?,?,?)";

        String salt = ShiroUtil.generateSalt(); //盐量随机
        String encodedPassword= ShiroUtil.encryptPassword("md5",password,salt,2);

        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql);) {

            ps.setString(1, name);
            ps.setString(2, encodedPassword);
            ps.setString(3, salt);
            ps.execute();
        } catch (SQLException e) {

            e.printStackTrace();
        }
        return null;
    }
    
    public User getUser(String userName) {
        User user = null;
        String sql = "select * from user where name = ?";
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql);) {
            ps.setString(1, userName);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                user = new User();
                user.setId(rs.getInt("id"));
                user.setName(rs.getString("name"));
                user.setPassword(rs.getString("password"));
                user.setSalt(rs.getString("salt"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return user;
    }

    public String getPassword(String userName) {
        String sql = "select password from user where name = ?";
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql);) {
            ps.setString(1, userName);
            ResultSet rs = ps.executeQuery();
            if (rs.next())
                return rs.getString("password");
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public Set<String> listRoles(String userName) {
        Set<String> roles = new HashSet<>();
        String sql = "select r.name from user u "
                + "left join user_role ur on u.id = ur.uid "
                + "left join Role r on r.id = ur.rid "
                + "where u.name = ?";
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql);) {
            ps.setString(1, userName);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                roles.add(rs.getString(1));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return roles;
    }

    public Set<String> listPermissions(String userName) {
        Set<String> permissions = new HashSet<>();
        String sql =
                "select p.name from user u " +
                        "left join user_role ru on u.id = ru.uid " +
                        "left join role r on r.id = ru.rid " +
                        "left join role_permission rp on r.id = rp.rid " +
                        "left join permission p on p.id = rp.pid " +
                        "where u.name =?";
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql);) {
            ps.setString(1, userName);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                permissions.add(rs.getString(1));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return permissions;
    }

    public static void main(String[] args) {
        System.out.println("zhang3 拥有的角色：" + new Dao().listRoles("zhang3"));
        System.out.println("li4    拥有的角色：" + new Dao().listRoles("li4"));
        System.out.println("zhang3 拥有的权限：" + new Dao().listPermissions("zhang3"));
        System.out.println("li4    拥有的权限：" + new Dao().listPermissions("li4"));
    }
    
}