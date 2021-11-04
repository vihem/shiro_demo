package cn.ea.test;

import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;

public class TestEncryption {
    public static void main(String[] args) {
        String password = "123";
        String md5Pwd = new Md5Hash(password).toString();
        System.out.println("md5Pwd = "+md5Pwd);//202cb962ac59075b964b07152d234b70

        String salt = new SecureRandomNumberGenerator().nextBytes().toString();
        System.out.println(salt);
        System.out.println(ByteSource.Util.bytes(salt));
        int times = 2;
        String algorithmName = "md5";
        String encodedPassword = new SimpleHash(algorithmName,password,salt,times).toString();
        System.out.printf("原始密码是 %s , 盐是： %s, 运算次数是： %d, 运算出来的密文是：%s ",password,salt,times,encodedPassword);
    }
}
