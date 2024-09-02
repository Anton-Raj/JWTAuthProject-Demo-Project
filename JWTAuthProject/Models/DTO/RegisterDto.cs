using System.ComponentModel.DataAnnotations;

namespace JWTAuthProject.Models.DTO
{
    public class RegisterDto
    {
        [Required(ErrorMessage ="User name is required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
    }
}
