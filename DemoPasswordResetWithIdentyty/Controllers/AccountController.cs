using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using MimeKit;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace DemoPasswordResetWithIdentity.Controllers
{
    [Route("api/[controller]")]
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;

        public AccountController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        private async Task<IdentityUser?> GetUser(string email)
        {
            return await _userManager.FindByIdAsync(email);
        }

        [HttpPost("register/{email}/{password}")]
        public async Task<IActionResult> Register(string email, string password)
        {
            var result = await _userManager.CreateAsync(new IdentityUser()
            {
                UserName = email,
                Email = email,
                PasswordHash = password
            },password);
            return Ok(result);
        }

        [HttpPost("login/{email}/{password}")]
        public async Task<IActionResult> Login(string email, string password)
        {
            bool checkPassword = await _userManager.CheckPasswordAsync(await GetUser(email!)!, password);
            if (checkPassword)
            {
                return Ok(new[] { "Successfully logged in", GenerateToken(await GetUser(email)) });
            }
            else
                return BadRequest("unable to log in");
        }

        private string GenerateToken(IdentityUser? identityUser)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Email,identityUser.Email!)
            };
            var cretential = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("dhdhdeGedyyv432994hfdeu48fF39hsjguewuwhu")), SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: claims,
                expires:null,
                signingCredentials: cretential
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [HttpGet("request-password-reset/{email}")]
        public async Task<IActionResult> RequestPasswordReset(string emali)
        {
            var user = await GetUser(emali);
            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user!);
            string validToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(resetToken));
            return Ok(SendEmail(user.Email, validToken));
        }

        private string SendEmail(string? email, string validToken)
        {
            string resetLink = $"https://localhost:7163/api/account/reset-password/{validToken}";
            StringBuilder sb = new();
            sb.AppendLine("<DOCTYPE html>");
            sb.AppendLine("<html >");
            sb.AppendLine("<body>");
            sb.AppendLine($"<h1>Hello {email}, reseltlink:{resetLink} </h1>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html >");
            sb.AppendLine("</DOCTYPE html>");
            string message = sb.ToString();
            var _email = new MimeMessage();
            _email.From.Add(MailboxAddress.Parse("mia.swift56@ethereal.email"));
            _email.To.Add(MailboxAddress.Parse("mia.swift56@ethereal.email"));
            _email.Subject = "Password reset";
            _email.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = message };
            using var smtp = new SmtpClient();
            smtp.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate("mia.swift56@ethereal.email", "3xE8nkWfBtdm4SQ99T");
            smtp.Send(_email);
            smtp.Disconnect(true);
            return "Kindly check your email for password reset link";
        }
        public static string Token { get; set; } = string.Empty;

        [HttpGet("reset-password/{token}")]
        public IActionResult ResetPassword(string token)
        {
            string Token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            return Ok("Reset password now!");
        }

        [HttpGet("reset-password/{email}/{newPassword}")]
        public async Task<IActionResult> ResetPassword(string email, string newPassword)
        {
            var result = await _userManager.ResetPasswordAsync(await GetUser(email)!, Token, newPassword);
            return Ok(result);
        }
    }
}

