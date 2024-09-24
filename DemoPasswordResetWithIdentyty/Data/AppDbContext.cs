﻿using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace DemoPasswordResetWithIdentity.Data
{
	public class AppDbContext : IdentityDbContext<IdentityUser>
	{
		public AppDbContext()
		{
		}

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }
    }
}
