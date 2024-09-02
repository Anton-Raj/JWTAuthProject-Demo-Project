using System.ComponentModel.DataAnnotations;

namespace JWTAuthProject.Models.DTO
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "User name is required")]
        public string UserName { get; set; }
    }
}
