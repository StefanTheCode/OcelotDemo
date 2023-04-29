using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace OcelotDemo.AuthProvider.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        [HttpPost("generateToken")]
        public IActionResult GenerateToken(User user)
        {
            if (user.Username == "stefan" && user.Password == "stefan123")
            {
                string secret = "thisIsSomeTestSecretKeyDontUseThisInProduction";
                var key = Encoding.ASCII.GetBytes(secret);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim("Id", Guid.NewGuid().ToString()),
                        new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                        new Claim(JwtRegisteredClaimNames.Email, user.Username),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    }),
                    Expires = DateTime.UtcNow.AddMinutes(5),
                    SigningCredentials = new SigningCredentials
                    (new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha512Signature)
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var jwtToken = tokenHandler.WriteToken(token);
                var stringToken = tokenHandler.WriteToken(token);

                return Ok(stringToken);
            }

            return Unauthorized();
        }
    }
}