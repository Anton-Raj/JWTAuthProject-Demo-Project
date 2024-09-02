using JWTAuthProject.Models.DTO;

namespace JWTAuthProject.Models.Repositories.Interfaces
{
    public interface IAuthService
    {
        Task<AuthServiceResponseDto> SeedRolesAsync();

        Task<AuthServiceResponseDto> RegisterAsync(RegisterDto register);

        Task<AuthServiceResponseDto> LoginAsync(LoginDto login);

        Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto);
    }
}
