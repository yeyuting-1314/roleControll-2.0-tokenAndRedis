package testdemo.system.dto;

import com.baomidou.mybatisplus.annotation.TableName;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;


@TableName("sys_user")
public class User{
    int id ;
    String userName ;
    String password ;

    //加一个属性  用于记录token
    String token ;

    private String role;

    String grantedAuthority ;

    List<GrantedAuthority> grantedAuthorities  ;


    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }


    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public List<GrantedAuthority> getGrantedAuthorities() {
        return grantedAuthorities;
    }

    public void setGrantedAuthorities(List<GrantedAuthority> grantedAuthorities) {
        this.grantedAuthorities = grantedAuthorities;
    }

    public String getGrantedAuthority() {
        return grantedAuthority;
    }

    public void setGrantedAuthority(String grantedAuthority) {
        this.grantedAuthority = grantedAuthority;
    }
}
