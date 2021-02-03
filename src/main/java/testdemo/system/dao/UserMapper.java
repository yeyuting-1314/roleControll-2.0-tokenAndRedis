package testdemo.system.dao;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;
import testdemo.system.dto.User;
import testdemo.util.PageBean;

import java.util.List;
import java.util.Map;

@Repository
@Mapper
/*
*  * 如果自定义xxMapper继承了mybatis-plus的BaseMapper时，xxMapper中不能有insert()方法，因为BaseMapper中就有这个方法。
 * 1.如果对应的xxMapper.xml中有<insert id="insert"/>方法，则会执行该方法，相当于对BaseMapper中的insert()方法重写了；
 * 2.如果对应的xxMapper.xml中没有<insert id="insert"/>方法，则默认使用mybatis-plus的insert()方法。
*
* */
public interface UserMapper {

    public List<User> select();

    public User selectOne1(int id);

    //public User selectByName(String userName) ;

    /*
     * 根据用户名查询某一条数据
     * */
    public User selectByName1(String name) ;

    public Integer insertOne(User user);

    public Integer insertMany(@Param("list") List<User> userList);

    public int updateById(User user) ;


    public Integer deleteOne(int id);

    //分页查询 通过开始页和数据条数进行查询
    public List<User> selectForPage1(int startIndex , int pageSize) ;

    //分页查询  通过map进行查询
    public List<User> selectForPage2(Map<String, Object> map);

    public Integer selectCount();

    public List<User> selectForPage3(PageBean pageBean);

    //模糊查询符合条件条数
    public Integer selectCount2(String keywords);

    //分页加模糊查询
    public List<User> selectForPage4(Map<String, Object> map);



}
