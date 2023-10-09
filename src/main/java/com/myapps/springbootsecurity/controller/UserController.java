package com.myapps.springbootsecurity.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {
	
	@RequestMapping("/hello")
	public String getUser()
	{
		return "Hello User";
	}
	
}
