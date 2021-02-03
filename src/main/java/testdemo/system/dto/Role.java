package testdemo.system.dto;

import com.baomidou.mybatisplus.annotation.TableName;

/**
 * @author yeyuting
 * @create 2021/1/20
 */
@TableName("sys_role")
public class Role {

    // 可以看出来这个角色类十分的简单，除了 id 只有角色和角色名
    // 在 Spring Security 中，默认使用以简单的字符串形式来表示角色，
    // 所以我们只需要提供一个 String 类型的字段用来表示角色即可
    // 需要注意的是在 Spring Security 中角色字符串表示需要以 “ROLE_” 前缀开头（例如：ROLE_ADMIN）

    int id ;

    // 角色的中文名
    String roleName ;
    // 角色的字符串表示
    String role ;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
