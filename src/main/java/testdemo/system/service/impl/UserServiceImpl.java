package testdemo.system.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import redis.clients.jedis.Jedis;
import testdemo.base.Result;
import testdemo.system.dao.RoleMapper;
import testdemo.system.dao.UserMapper;
import testdemo.system.dao.UserRoleMapper;
import testdemo.system.dto.Role;
import testdemo.system.dto.User;
import testdemo.system.dto.UserRole;
import testdemo.system.service.UserService;
import testdemo.util.JedisUtil;
import testdemo.util.PageBean;
import testdemo.util.Results;
import testdemo.util.TokenUtil;
import javax.servlet.http.Cookie;

import javax.servlet.http.HttpServletResponse;
import java.util.*;

@Service
public class UserServiceImpl implements UserService ,UserDetailsService {
    @Autowired
    UserMapper userMapper ;

    @Autowired
    TokenUtil tokenUtil ;

    @Autowired
    JedisUtil jedisUtil ;

    @Autowired
    RoleMapper roleMapper ;

    @Autowired
    UserRoleMapper userRoleMapper ;

    @Override
    public User selectOne1(int id){

        return userMapper.selectOne1(id) ;
    }

    /*
     * 根据用户名查询某一条数据
     * */
    public User selectByName(String name){

        return userMapper.selectByName1(name) ;
    }

    @Override
    public Integer insertOne(User user) {
        return null;
    }

    @Override
    public List<User> select(){
        return userMapper.select();
    }

    @Override
    public Integer insertOne1(User user){
        return userMapper.insertOne(user);
    }

    @Override
    public Integer insertMany(List<User> userList){
        return userMapper.insertMany(userList) ;
    }

    public Integer updateById(User user){
        return userMapper.updateById(user ) ;
    }
    @Override
    public Integer deleteOne(int id){
        return userMapper.deleteOne(id) ;
    }

    @Override
    public List<User> selectForPage1(int startIndex , int pageSize){
        return userMapper.selectForPage1(startIndex , pageSize) ;

    }

    public List<User> selectForPage2(Map<String, Object> map){

        return userMapper.selectForPage2(map);
    }

    public Integer selectCount(){
        return userMapper.selectCount() ;
    }

    public List<User> selectForPage3(PageBean pageBean){
        return userMapper.selectForPage3(pageBean) ;
    }

    public List<User> selectForPage4(Map<String, Object> map){
        return userMapper.selectForPage4(map) ;
    }

    public Integer selectCount2(String keywords){
        return userMapper.selectCount2(keywords) ;
    }

    public Result loginCheck(User user , HttpServletResponse response){
        User user1 = userMapper.selectByName1(user.getUserName()) ;
        if(user1 == null ){
            //response.sendRedirect("/login");
            return Results.failure("用户不存在,") ;
        }
        if(!user1.getPassword().equals(user.getPassword())){
            return Results.failure("密码输入错误") ;
        }
        String token = tokenUtil.generateToken(user1) ;
        System.out.println("token:" + token);
        user.setToken(token);

        // 设置cookie的值
        Cookie cookie = new Cookie("token" , token) ;

        cookie.setPath("/");
        response.addCookie(cookie);
        System.out.println("cookie:"+cookie);

        return Results.successWithData(user) ;
    }

    public Result loginWithRedis(User user ){
        User user1 = userMapper.selectByName1(user.getUserName()) ;

        if(user1 == null ){
            //response.sendRedirect("/login");
            return Results.failure("用户不存在,") ;
        }
        if(!user1.getPassword().equals(user.getPassword())){
            return Results.failure("密码输入错误") ;
        }
        //将原有的token值全部干掉，防止重复登陆
        Jedis jedis = jedisUtil.getResource();
         //存入键值对
        String jedisKey = jedis.get(user1.getUserName()) ;
        if(jedisKey != null){
            jedisUtil.delString(user1.getUserName());
        }
        //生成新的token
        String token = tokenUtil.generateToken(user1) ;
        user1.setToken(token);
        //将新生成的token放到redis中
        jedisUtil.tokenToJedis(user1);
        jedis.close();
        return Results.successWithData(user1) ;
    }


    /*
    * /*
     * 用户在登录时 Spring Security 会通过 UserDetailsService.loadUserByUsername() 方法获取登录的用户的详细信息，
     * 然后会将用户的数据封装进 UserDetails 对象中，因此这里需要实现UserDetailsService接口，并重写loadUserByUsername方法
    * */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //角色和权限共用GrantedAuthority接口，后面采集到的角色信息将存储到grantedAuthorities集合中
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        //将前端传过来的username信息传入数据库比对，将匹配的用户信息存入user对象
        User user = userMapper.selectByName1(username) ;

        if (user == null){
            throw new UsernameNotFoundException("用户不存在");
        }


        //根据用户id进入user_role表中查询对应的角色id，存储到userRoles列表中
        List<UserRole> userRoles = userRoleMapper.selectList(user.getId()) ;
        //遍历userRoles集合
        for (UserRole ur : userRoles){
            //再根据用户id查到对应的role，此时就拿到了用户对应的角色
            Role role = roleMapper.selectOne1(ur.getRoleId());
            //将对应的角色存储到权限grantedAuthorities集合中
            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(role.getRole());
            grantedAuthorities.add(grantedAuthority);
        }
        //生成token
        //将原有的token值全部干掉，防止重复登陆
        Jedis jedis = jedisUtil.getResource();
        //存入键值对
        String jedisKey = jedis.get(user.getUserName()) ;
        if(jedisKey != null){
            jedisUtil.delString(user.getUserName());
        }

        String token = tokenUtil.generateToken(user) ;
        user.setToken(token);
        user.setGrantedAuthority("authority");
        user.setGrantedAuthorities(grantedAuthorities);
        jedisUtil.tokenToJedis(user);
        jedis.close();
        //测试数据
        String name = user.getUserName() ;
        //创建一个用户，用于判断权限，请注意此用户名和方法参数中的username一致；BCryptPasswordEncoder是用来演示加密使用。
        //            //这里主要是实现用户名和密码的核对，如果信息都正确才给开这个权限，这是一种安全策略
        return new org.springframework.security.core.userdetails.User
                ("user",
                        new BCryptPasswordEncoder().encode(user.getPassword()), grantedAuthorities);


    }


}
