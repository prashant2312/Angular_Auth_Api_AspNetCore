using Angular_Auth_Api.Models;
using Microsoft.EntityFrameworkCore;

namespace Angular_Auth_Api.Context
{
    public class AppDBContext:DbContext
    {
        public AppDBContext(DbContextOptions<AppDBContext> options):base(options)
        {
        }
       public DbSet<User> Users { get; set; } 
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("users");
        }
    }
}
