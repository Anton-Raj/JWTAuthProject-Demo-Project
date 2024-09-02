using JWTAuthProject.Models.DTO;
using JWTAuthProject.Models.Other_Objects;
using JWTAuthProject.Models.Repositories.Interfaces;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            this._authService = authService;
        }

        //Route for seeding my roles into DB
        [HttpPost]
        [Route("Seed-Roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seedRoles = await _authService.SeedRolesAsync();

            return Ok(seedRoles);
        }

        //Route for Register User
        [HttpPost]
        [Route("Register-User")]
        public async Task<IActionResult> Register([FromBody]RegisterDto register)
        {
            var registerUser = await _authService.RegisterAsync(register);

            if(!registerUser.IsSucceed)
            {
                return BadRequest(registerUser);
            }
            return Ok(registerUser);
        }


        //Login user
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> LoginUser([FromBody] LoginDto loginDto)
        {
            var loginUser = await _authService.LoginAsync(loginDto);

            if(!loginUser.IsSucceed)
            {
                return BadRequest(loginUser);
            }

            return Ok(loginUser);
        }

        [HttpPost]
        [Route("Make-Admin")]
        public async Task<IActionResult> MakeAdmin([FromBody]UpdatePermissionDto updatePermissionDto)
        {
            var makeAdmin = await _authService.MakeAdminAsync(updatePermissionDto);

            if(!makeAdmin.IsSucceed)
            { 
                return BadRequest(makeAdmin); 
            }

            return Ok(makeAdmin);
        }
    }
}