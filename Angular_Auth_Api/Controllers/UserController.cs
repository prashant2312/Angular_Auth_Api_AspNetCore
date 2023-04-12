using Angular_Auth_Api.Context;
using Angular_Auth_Api.Helpers;
using Angular_Auth_Api.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
            return Ok(new
            {
                Token = user.Token,
                Message="Login succesful"
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
                new Claim(ClaimTypes.Name,$"{user.FirstName} {user.LastName}"),
            });
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256);

            var tokenDescripter = new SecurityTokenDescriptor()
            {
                Subject= identity,
                Expires=DateTime.Now.AddDays(1),
                SigningCredentials=credentials,
            };
            var token=jwtTokenHandler.CreateToken(tokenDescripter);
            return jwtTokenHandler.WriteToken(token);
        }
    }
}
