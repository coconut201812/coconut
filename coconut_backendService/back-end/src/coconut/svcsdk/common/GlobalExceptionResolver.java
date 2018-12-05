/* Notice: This part code is out of the coconut's core function. So it is supplied as a stub. 
 * If you want to use coconut in production environment, please implement this module. */
package coconut.svcsdk.common;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

@Component  
public class GlobalExceptionResolver implements HandlerExceptionResolver{  
	
    public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler,  
            							 Exception e) {
    	ModelAndView view = new ModelAndView();
        return view;  
     }
}