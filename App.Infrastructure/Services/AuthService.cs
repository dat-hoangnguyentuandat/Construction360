using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using App.Application.DTOs;
using App.Application.Interfaces;
using App.Domain.Constants;
using App.Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace App.Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        public AuthService(UserManager<User> userManager, SignInManager<User> signInManager) 
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public async Task ForgotPasswordAsync(ForgotPasswordDto forgotPasswordDto)
        {
            var user = await _userManager.FindByEmailAsync(forgotPasswordDto.Email);
            if (user == null) return;
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        }

        public async Task<RegisterResponseDto> RegisterAsync(RegisterDto registerDto, RegisterPasswordDto registerPasswordDto)
        {
            var existingUser = await _userManager.FindByEmailAsync(registerDto.Email);
            if (existingUser != null)
                throw new Exception("Email đã được sử dụng");

            var user = new User
            {
                UserName = registerDto.Email,
                Email = registerDto.Email,
                PhoneNumber = registerDto.PhoneNumber,
                FullName = registerDto.Fullname,
                DateOfBirth = registerDto.DateOfBirth,
                Company = registerDto.Company,
                Position = registerDto.Position,
            };

            var result = await _userManager.CreateAsync(user, registerPasswordDto.Password);
            if (!result.Succeeded)
                throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, Roles.Viewer);
            }

            return new RegisterResponseDto
            {
                Message = "Đăng ký thành công",
                Email = user.Email!
            };
        }

        public async Task ResetPasswordAsync(string email, string token, ResetPasswordDto resetPasswordDto)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                throw new Exception("Không tìm thấy tài khoản");

            var result = await _userManager.ResetPasswordAsync(user, token, resetPasswordDto.Password);
            if (!result.Succeeded)
                throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
        }
    }
}
