package testdemo.config.exception;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import testdemo.base.Result;
import testdemo.util.Results;

/**
 * @author yeyuting
 * @create 2021/1/29
 */
@RestControllerAdvice
public class GlobalExceptionHandler {


    // 会执行该方法
    @ExceptionHandler(AccessDeniedException.class)
    public Result handleAccessDeniedException(AccessDeniedException e){

        return Results.failure("403", "无权限访问该接口");
    }
}
