package com.project.inno.adminweb.web;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping
public class WebErrorController implements ErrorController {
    @GetMapping("/error")
    public String getErrorpage(HttpServletRequest request, Model model) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        if(status != null) {
            int statusCode = Integer.parseInt(status.toString());
            String text = "";
            if(statusCode == HttpStatus.NOT_FOUND.value()) {
                text = "the page you requested was not found";
            }
            else if(statusCode == HttpStatus.UNAUTHORIZED.value()){
                text = "you are not authorized to the page you are requesting";
            }
            else if (statusCode == HttpStatus.FORBIDDEN.value()) {
                text = "you do not have permission to view the page";
            }
            else {
                text = "something went wrong";
            }
            model.addAttribute("errorText", text);
            model.addAttribute("errorCode", statusCode);
        }
        else {
            model.addAttribute("errorText", "An unknow error has occured");
            model.addAttribute("errorCode", "Unknow");
        }
        return "error";
    }

}
