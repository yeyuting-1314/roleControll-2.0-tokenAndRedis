package testdemo.system.dto;

/**
 * @author yeyuting
 * @create 2021/1/28
 */
public class RolePrivilege {
    int roleId ;
    int privilegeId ;

    public int getRoleId() {
        return roleId;
    }

    public void setRoleId(int roleId) {
        this.roleId = roleId;
    }

    public int getPrivilegeId() {
        return privilegeId;
    }

    public void setPrivilegeId(int privilegeId) {
        this.privilegeId = privilegeId;
    }
}
