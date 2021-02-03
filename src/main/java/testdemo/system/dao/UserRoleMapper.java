package testdemo.system.dao;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;
import testdemo.system.dto.User;
import testdemo.system.dto.UserRole;

import java.util.List;

/**
 * @author yeyuting
 * @create 2021/1/21
 */
@Repository
@Mapper
public interface UserRoleMapper {
    public List<UserRole> selectList(int id);

}
