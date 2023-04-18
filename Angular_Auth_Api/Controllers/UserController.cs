using Angular_Auth_Api.Context;
using Angular_Auth_Api.Helpers;
using Angular_Auth_Api.Models;
using Angular_Auth_Api.Models.Dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Angular_Auth_Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDBContext _authContext;
        public UserController(AppDBContext authContext)
        {
            _authContext = authContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj==null)
            {
                return BadRequest();
            }
            var user=await _authContext.Users.FirstOrDefaultAsync(x=>x.Username==userObj.Username);

            if (user==null)
            {
                return NotFound(new {Message="User is not found"});
            
            }
            if (!Passwordhasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new
                {
                    Message="Password is incorrect"
                });
            }
            user.Token = CreateJWT(user);
            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime=DateTime.Now.AddDays(5);
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApiDTO()
            {
                AccessToken=newAccessToken,
                RefreshToken=newRefreshToken
            });
        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userOBJ) {
            if (userOBJ==null)
            {
                return BadRequest();
            }
            //chack username
            if (await CheckUserNameExist(userOBJ.Username))
            {
                return BadRequest(new { Message = "Username already exist" });
            }

            //chack email
            if (await CheckEmailExist(userOBJ.Email))
            {
                return BadRequest(new { Message = "email already exist" });
            }

            //check password strength
            var pass = CheckPasswordStrength(userOBJ.Password);
            if (!string.IsNullOrEmpty(pass))
            {
                return BadRequest(new
                {
                    Message = pass.ToString()
                });
            }

            userOBJ.Password = Passwordhasher.HashPassword(userOBJ.Password);
            userOBJ.Role = "User";
            userOBJ.Token = "";
            await _authContext.Users.AddAsync(userOBJ);
           await _authContext.SaveChangesAsync();
            return Ok(new
            {
                Message="User register"
            });
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Getallusers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        } 

        private Task<Boolean> CheckUserNameExist(string username) =>
            _authContext.Users.AnyAsync(x => x.Username == username);

        private Task<Boolean> CheckEmailExist(string email) =>
        _authContext.Users.AnyAsync(x => x.Email == email);

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb=new StringBuilder();
            if (password.Length < 8)
            {
                sb.Append("Minimum password length should be 8" + Environment.NewLine);
            }
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]")
                &&Regex.IsMatch(password,"[0-9]")))
            {
                sb.Append("password should be alpha numeric"+Environment.NewLine);
            }
            if (!Regex.IsMatch(password, "[<,>,@,\\,/,$,^,&]"))
            {
                sb.Append("Password should contain special character" + Environment.NewLine);
            }
            return sb.ToString();
        }


        private string CreateJWT(User user)
        {
            var jwtTokenHandler =new JwtSecurityTokenHandler();
            var key = System.Text.Encoding.ASCII.GetBytes("veryverysecret.....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role,user.Role),
                new Claim(ClaimTypes.Name,$"{user.Username} "),
            });
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256);

            var tokenDescripter = new SecurityTokenDescriptor()
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(10),
                SigningCredentials = credentials,
            };
            var token=jwtTokenHandler.CreateToken(tokenDescripter);
            return jwtTokenHandler.WriteToken(token);
        }


        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken=Convert.ToBase64String(tokenBytes);
            var tokenInUser = _authContext.Users.Any(a=>a.RefreshToken==refreshToken);

            if (tokenInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }

        private ClaimsPrincipal GetPrincipalfromExpireToken(string token)
        {
            var key = System.Text.Encoding.ASCII.GetBytes("veryverysecret.....");

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime= false,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken=securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null||jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase)) {
                throw new SecurityTokenException("This is invalid token");
            }
            return principal;
        }


        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDTO tokenApiDTO)
        {
            if (tokenApiDTO==null)
            {
                return BadRequest("Invalid client request");
            }
            string accessToken=tokenApiDTO.AccessToken;
            string refreshToken = tokenApiDTO.RefreshToken;
            var principal=GetPrincipalfromExpireToken(accessToken);
            var userName=principal.Identity.Name;
            var user=await _authContext.Users.FirstOrDefaultAsync(u=>u.Username==userName);
            if (user==null||user.RefreshToken!=refreshToken||user.RefreshTokenExpiryTime<=DateTime.Now)
            {
                return BadRequest("Invalid Request");
            }
            var newAccessToken = CreateJWT(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken= newRefreshToken;
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApiDTO
            {
                AccessToken=newAccessToken,
                RefreshToken=newRefreshToken,
            });
        }
    }
}
