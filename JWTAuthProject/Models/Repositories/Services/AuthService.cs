using JWTAuthProject.Models.DTO;
using JWTAuthProject.Models.Other_Objects;
using JWTAuthProject.Models.Repositories.Interfaces;

using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthProject.Models.Repositories.Services
{
    public class AuthService : IAuthService
    {

        private readonly UserManager<IdentityUser> userManager;

        private readonly RoleManager<IdentityRole> roleManager;

        private readonly IConfiguration configuration;

        public AuthService(UserManager<IdentityUser> _userManager, RoleManager<IdentityRole> _roleManager, IConfiguration _configuration) 
        { 
            this.userManager = _userManager;
            this.roleManager = _roleManager;
            this.configuration = _configuration;
        }

        public async Task<AuthServiceResponseDto> SeedRolesAsync()
        {
            bool isOwnerRoleExists = await roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserRoleExists = await roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Roles already seeded"
                };
            }

            await roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            await roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "Roles seeded Successfully"
            };
        }

        public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDto register)
        {
            var isExistUser = await userManager.FindByNameAsync(register.UserName);

            if (isExistUser != null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "User Name Already registered"
                };
            }

            IdentityUser newUser = new IdentityUser()
            {
                UserName = register.UserName,
                Email = register.Email
            };

            var createUser = await userManager.CreateAsync(newUser, register.Password);

            if (!createUser.Succeeded)
            {
                var errorMessage = "User creation failed Because: ";

                foreach (var error in createUser.Errors)
                {
                    errorMessage += " # " + error.Description;

                }

                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = errorMessage
                };
                
            }

            //Add default user role to all user
            await userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "User Created Successfully"
            };
        }


        public async Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto)
        {
            var user = await userManager.FindByNameAsync(loginDto.UserName);

            if (user == null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials"
                };
            }

            var isPasswordValid = await userManager.CheckPasswordAsync(user, loginDto.Password);

            if (isPasswordValid == false)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials"
                };
            }

            var userRoles = await userManager.GetRolesAsync(user);

            //Create the claims
            var authClaim = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString())
            };

            foreach (var role in userRoles)
            {
                authClaim.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = GenerateNewJsonWebToken(authClaim);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = token
            };
        }

        public async Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user == null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "User not Found"
                };
            }

            await userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "User is now an Admin"
            };
        }


        //Method to create token
        private string GenerateNewJsonWebToken(List<Claim> authClaim)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration[ "JWT:Key" ]));

            var tokenObject = new JwtSecurityToken(

                issuer: configuration[ "JWT:Issuer" ],
                audience: configuration[ "JWT:Audience" ],
                claims: authClaim,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );

            var token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return (token);
        }
    }
}
