package testdemo.system.dao;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;
import testdemo.system.dto.Role;
import testdemo.system.dto.User;

/**
 * @author yeyuting
 * @create 2021/1/21
 */
@Repository
@Mapper
public interface RoleMapper{

    public Role selectOne1(int id);

}
