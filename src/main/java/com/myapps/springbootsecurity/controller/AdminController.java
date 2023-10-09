package com.myapps.springbootsecurity.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

	@RequestMapping("/hello")
	public String getAdmin()
	{
		return "Hello Admin";
	}


}
