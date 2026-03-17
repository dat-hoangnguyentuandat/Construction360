using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Construction360.Data;

public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    public ApplicationDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
        optionsBuilder.UseNpgsql(
            "Host=localhost;Port=5432;Database=construction360;Username=postgres;Password=dat13032004",
            npgsql => npgsql.MigrationsAssembly("Construction360")
        );
        optionsBuilder.UseOpenIddict();
        return new ApplicationDbContext(optionsBuilder.Options);
    }
}
